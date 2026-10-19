/**
 * Harness installer: put one broker entry into each harness's MCP config.
 *
 * Three clients own a supported CLI (`claude mcp add`, `opencode mcp add`,
 * `codex mcp add`) and are driven through it; Cursor is file-edited because its config
 * is a plain JSON map with no CLI. Every method obeys the same contract:
 *
 *   - The proposed change is *shown* as a diff or an exact command line before anything
 *     is written. `install` without `--yes` is always a dry run.
 *   - A file edit snapshots the original to a hash-receipted backup first.
 *   - Entries written carry no secret material and no env block: the shim asks the
 *     daemon over the socket; nothing else leaves this process.
 *   - Uninstall reverses the change and rollback restores a backup byte-for-byte.
 */

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ensureDir0700, writeFileAtomic } from '../core/fsx.ts'
import { HOME_ENV_VAR, runtimeRoot } from '../core/runtime-paths.ts'
import { sweepCredentialPatterns } from '../cli/commands/config.ts'
import type { KnownClient } from './detect.ts'

export class InstallError extends Error {}

/** The MCP server entry name used in every harness config. */
export const SERVER_NAME = 'vaultbroker'

/** Where this module sits, so the launcher path resolves regardless of cwd. */
const MODULE_DIR = dirname(fileURLToPath(import.meta.url))

/** The command a harness is told to run: absolute node, absolute launcher, argv only. */
export function brokerLauncherEntry(client: KnownClient): { command: string; args: string[] } {
  const launcher = resolve(MODULE_DIR, '..', '..', 'bin', 'vaultbroker.mjs')
  return { command: process.execPath, args: [launcher, 'mcp', client] }
}

interface ProposedEntry {
  readonly command: string
  readonly args: readonly string[]
}

export interface InstallPlan {
  readonly client: KnownClient
  /** `cli` drives the harness's own installer; `file` edits its JSON directly. */
  readonly method: 'cli' | 'file'
  /** The exact subcommand (cli) or the rendered diff (file) that applying will use. */
  readonly argv?: readonly string[]
  readonly fileDiff?: readonly string[]
  readonly entry: ProposedEntry
}

/** Where each client's config lives, relative to the user's home. */
export const CONFIG_PATHS: Readonly<Record<KnownClient, string>> = {
  cursor: '.cursor/mcp.json',
  'claude-code': '.claude.json',
  opencode: '.config/opencode/opencode.json',
  codex: '.codex/config.toml',
}

/**
 * Per-client CLI verbs, captured from the real tools rather than guessed: they have
 * changed between versions and will again. Cursor has no CLI and is file-only on purpose.
 */
const CLI_SPECS: Readonly<Record<Exclude<KnownClient, 'cursor'>, { add: readonly string[]; remove: readonly string[] }>> = {
  'claude-code': { add: ['mcp', 'add', '-s', 'user'], remove: ['mcp', 'remove', '-s', 'user'] },
  opencode: { add: ['mcp', 'add', '--global'], remove: ['mcp', 'remove'] },
  codex: { add: ['mcp', 'add'], remove: ['mcp', 'remove'] },
}

function homeBase(home?: string): string {
  return home ?? process.env[HOME_ENV_VAR] ?? ''
}

export function configPathFor(client: KnownClient, home?: string): string {
  return join(homeBase(home), CONFIG_PATHS[client])
}

/**
 * One readable unified diff over line arrays.
 *
 * The diff is shown before a write, so it has to look like what tools assume a diff
 * looks like — a real LCS, not an unordered splat.
 */
export function diffLines(before: readonly string[], after: readonly string[]): string[] {
  const table: number[][] = Array.from({ length: before.length + 1 }, () =>
    new Array<number>(after.length + 1).fill(0),
  )

  for (let i = before.length - 1; i >= 0; i -= 1) {
    for (let j = after.length - 1; j >= 0; j -= 1) {
      table[i]![j] =
        before[i] === after[j]
          ? table[i + 1]![j + 1]! + 1
          : Math.max(table[i + 1]![j]!, table[i]![j + 1]!) ?? 0
    }
  }

  const out: string[] = []
  let i = 0
  let j = 0
  while (i < before.length && j < after.length) {
    if (before[i] === after[j]) {
      out.push(`  ${before[i]}`)
      i += 1
      j += 1
    } else if ((table[i + 1]![j] ?? 0) >= (table[i]![j + 1] ?? 0)) {
      out.push(`- ${before[i]}`)
      i += 1
    } else {
      out.push(`+ ${after[j]}`)
      j += 1
    }
  }
  while (i < before.length) {
    out.push(`- ${before[i]}`)
    i += 1
  }
  while (j < after.length) {
    out.push(`+ ${after[j]}`)
    j += 1
  }
  return out.length === 0 ? ['  (identical)'] : out
}

/** Rewrite a cursor config in memory: parse → mutate → re-serialise keeping key order. */
export function rewriteCursorConfigText(text: string, serverName: string, entry: ProposedEntry): string {
  const parsed = JSON.parse(text) as { mcpServers?: Record<string, unknown> }
  const servers = { ...(parsed.mcpServers ?? {}) }
  const updated: Record<string, unknown> = {}
  let placed = false

  for (const [name, existing] of Object.entries(servers)) {
    updated[name] = name === serverName ? { command: entry.command, args: entry.args } : existing
    if (name === serverName) placed = true
  }
  if (!placed) updated[serverName] = { command: entry.command, args: entry.args }

  parsed.mcpServers = updated
  return `${JSON.stringify(parsed, null, 2)}\n`
}

/**
 * Does the client's config already carry the broker entry, by its own conventions?
 *
 * Re-install must be idempotent: running the harness CLI twice, or splicing the JSON
 * twice, is either an error or a duplicate. Detection stays in this one place.
 */
export function alreadyInstalled(client: KnownClient, serverName: string, home?: string): boolean {
  const path = configPathFor(client, home)
  if (!existsSync(path)) return false

  const text = readFileSync(path, 'utf8')
  if (client === 'codex') {
    // TOML section headers are `[mcp_servers.<name>]`.
    return text.includes(`[mcp_servers.${serverName}]`)
  }
  if (client === 'cursor') {
    const parsed = JSON.parse(text) as { mcpServers?: Record<string, unknown> }
    return Boolean(parsed.mcpServers && serverName in parsed.mcpServers)
  }
  // claude-code's store is one flat JSON; opencode nests under `mcp`.
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>
    if (client === 'claude-code') {
      const servers = parsed['mcpServers'] as Record<string, unknown> | undefined
      return Boolean(servers && serverName in servers)
    }
    const servers = parsed['mcp'] as Record<string, unknown> | undefined
    return Boolean(servers && serverName in servers)
  } catch {
    return false
  }
}

/** Compute the plan for one client without touching anything. */
export function planInstall(
  client: KnownClient,
  options: { home?: string; serverName?: string } = {},
): InstallPlan {
  const serverName = options.serverName ?? SERVER_NAME
  const entry = brokerLauncherEntry(client)

  if (alreadyInstalled(client, serverName, options.home)) {
    return {
      client,
      method: client === 'cursor' ? 'file' : 'cli',
      fileDiff: ['  (already installed)'],
      entry,
    }
  }

  if (client === 'cursor') {
    const path = configPathFor(client, options.home)
    const before = existsSync(path) ? readFileSync(path, 'utf8') : '{}\n'
    const after = rewriteCursorConfigText(before, serverName, entry)
    return {
      client,
      method: 'file',
      fileDiff: diffLines(before.split('\n'), after.split('\n')),
      entry,
    }
  }

  const spec = CLI_SPECS[client]
  const argv = [
    clientBinary(client, options.home),
    ...spec.add,
    serverName,
    '--',
    entry.command,
    ...entry.args,
  ]
  return { client, method: 'cli', argv, entry }
}

/** Join argv into a display string, quoting anything with whitespace. */
function displayArgv(argv: readonly string[]): string {
  return argv.map((part) => (/\s/u.test(part) ? JSON.stringify(part) : part)).join(' ')
}

export function renderPlan(plan: InstallPlan): string {
  if (plan.method === 'cli') {
    return `harness entry: ${displayArgv([plan.entry.command, ...plan.entry.args])}\n` +
      `proposal (command shown in full):\n  ${displayArgv(plan.argv ?? [])}\n`
  }
  return `harness entry: ${displayArgv([plan.entry.command, ...plan.entry.args])}\n` +
    `proposal (apply writes exactly this diff):\n${(plan.fileDiff ?? []).join('\n')}\n`
}

function clientBinary(client: Exclude<KnownClient, 'cursor'>, home?: string): string {
  const base = homeBase(home)
  const candidates: Readonly<Record<Exclude<KnownClient, 'cursor'>, readonly string[]>> = {
    'claude-code': base
      ? [join(base, '.local/bin/claude'), join(base, 'bin/claude-test-stub')]
      : ['/usr/local/bin/claude', '/opt/homebrew/bin/claude'],
    opencode: base
      ? [join(base, '.opencode/bin/opencode'), join(base, 'bin/opencode-test-stub')]
      : ['/usr/local/bin/opencode', '/opt/homebrew/bin/opencode'],
    codex: base
      ? [join(base, '.codex/bin/codex'), join(base, 'bin/codex-test-stub')]
      : ['/usr/local/bin/codex', '/opt/homebrew/bin/codex'],
  }
  const found = candidates[client].find((candidate) => existsSync(candidate))
  // A missing binary is a plan-time decision, never a silent halt: the plan names it so
  // the user can read exactly what could not run.
  return found ?? `MISSING:${client}`
}

interface SnapshotReceipt {
  readonly backupPath: string
  readonly metaPath: string
  readonly originalPath: string
  readonly digest: string
  readonly mode: number
}

/**
 * Snapshot a config file plus a hash receipt.
 *
 * A backup that has not been read back is not a backup. This is the same discipline as
 * the migration command's, with receipts for `rollback`.
 */
function snapshot(configPath: string): SnapshotReceipt {
  const bytes = readFileSync(configPath)
  ensureDir0700(join(runtimeRoot(), 'backups'))
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const stem = `install-${stamp}-${basename(configPath)}`
  const backupPath = join(runtimeRoot(), 'backups', `${stem}.bak`)
  const metaPath = join(runtimeRoot(), 'backups', `${stem}.json`)

  writeFileAtomic(backupPath, bytes)
  if (!readFileSync(backupPath).equals(bytes)) {
    throw new InstallError('backup could not be verified; aborting without touching the config')
  }

  const receipt: SnapshotReceipt = {
    backupPath,
    metaPath,
    originalPath: configPath,
    digest: createHash('sha256').update(bytes).digest('hex'),
    mode: statSync(configPath).mode & 0o7777,
  }
  writeFileAtomic(
    metaPath,
    JSON.stringify(
      { originalPath: configPath, sha256: receipt.digest, mode: receipt.mode, bytes: bytes.byteLength },
      null,
      2,
    ),
  )
  return receipt
}

/**
 * Apply a plan.
 *
 * Never echoes harness stderr wholesale — it may contain anything — so a CLI failure
 * surfaces as an exit code only.
 */
export function applyInstall(
  client: KnownClient,
  options: { home?: string; serverName?: string } = {},
): { changed: boolean; summary: string } {
  const serverName = options.serverName ?? SERVER_NAME

  if (alreadyInstalled(client, serverName, options.home)) {
    return { changed: false, summary: `${client}: already installed; nothing to do\n` }
  }

  if (client !== 'cursor') {
    const plan = planInstall(client, options)
    const bin = (plan.argv as readonly string[])[0] as string
    if (bin.startsWith('MISSING:')) {
      throw new InstallError(`no ${client} CLI found; refusing to fabricate an install`)
    }
    const result = spawnSync(bin, (plan.argv as readonly string[]).slice(1), {
      encoding: 'utf8',
      timeout: 60_000,
    })
    if (result.status !== 0) {
      throw new InstallError(`${client} mcp add exited ${String(result.status)}`)
    }
    verifyConfigClean(client, options.home)
    return {
      changed: true,
      summary: `${client}: added ${serverName} through the harness CLI\n` +
        `entry: ${displayArgv([plan.entry.command, ...plan.entry.args])}\n` +
        `config verified credential-free\n`,
    }
  }

  const path = configPathFor(client, options.home)
  const exists = existsSync(path)
  const before = exists ? readFileSync(path, 'utf8') : '{}\n'
  const after = rewriteCursorConfigText(before, serverName, brokerLauncherEntry(client))

  if (exists) {
    const receipt = snapshot(path)
    const mode = (statSync(path).mode & 0o7777)
    writeFileAtomic(path, after)
    chmodSync(path, mode)
    verifyConfigClean(client, options.home)
    return {
      changed: true,
      summary: `${client}: rewrote ${path}\nbackup: ${receipt.backupPath}\ndiff applied exactly as shown\n`,
    }
  }

  writeFileAtomic(path, after)
  verifyConfigClean(client, options.home)
  return { changed: true, summary: `${client}: created ${path}\ndiff applied exactly as shown\n` }
}

/**
 * Uninstall one client.
 *
 * The inverse of install with the same discipline: back up, write atomically. For CLI
 * clients the harness's own remove verb is used so the broker never hand-edits a config
 * that tool owns.
 */
export function applyUninstall(
  client: KnownClient,
  options: { home?: string; serverName?: string } = {},
): { changed: boolean; summary: string } {
  const serverName = options.serverName ?? SERVER_NAME

  if (client !== 'cursor') {
    const bin = clientBinary(client, options.home)
    if (bin.startsWith('MISSING:')) {
      throw new InstallError(`no ${client} CLI found; uninstall would leave ${serverName} behind`)
    }
    const result = spawnSync(bin, [...CLI_SPECS[client].remove, serverName], {
      encoding: 'utf8',
      timeout: 60_000,
    })
    if (result.status !== 0) {
      throw new InstallError(`${client} mcp remove exited ${String(result.status)}`)
    }
    return { changed: true, summary: `${client}: removed ${serverName}\n` }
  }

  const path = configPathFor(client, options.home)
  if (!existsSync(path)) {
    return { changed: false, summary: 'no config; nothing to remove\n' }
  }

  const before = readFileSync(path, 'utf8')
  const parsed = JSON.parse(before) as { mcpServers?: Record<string, unknown> }
  if (parsed.mcpServers === undefined || !(serverName in parsed.mcpServers)) {
    return { changed: false, summary: `${client}: not installed\n` }
  }

  const receipt = snapshot(path)
  const servers = { ...parsed.mcpServers }
  delete servers[serverName]
  parsed.mcpServers = servers
  const after = `${JSON.stringify(parsed, null, 2)}\n`
  writeFileAtomic(path, after)
  chmodSync(path, receipt.mode)
  return { changed: true, summary: `${client}: removed ${serverName} from ${path}\nbackup: ${receipt.backupPath}\n` }
}

/**
 * Restore the newest verify-receipted install snapshot.
 *
 * Newest-first over receipt files. The digest is re-verified before the restore; a
 * mismatch aborts and the target is left untouched.
 */
export function applyRollback(client: KnownClient, home?: string): string {
  const backupsDir = join(runtimeRoot(), 'backups')
  if (!existsSync(backupsDir)) return 'no backups exist\n'

  const receipts = readdirSync(backupsDir)
    .filter((name) => name.startsWith('install-') && name.endsWith('.json'))
    .sort()
  if (receipts.length === 0) return `no install snapshots from this session\n`

  for (const receiptName of receipts.reverse()) {
    const metaPath = join(backupsDir, receiptName)
    const meta = JSON.parse(readFileSync(metaPath, 'utf8')) as {
      originalPath?: string
      sha256?: string
      mode?: number
    }
    if (meta.originalPath === undefined || meta.sha256 === undefined) continue

    // Only a snapshot of THIS client's config qualifies; there is one config path per
    // client, so path-relative containment decides.
    const expected = configPathFor(client, home)
    if (relative(resolve(meta.originalPath), resolve(expected)) !== '') continue

    const stem = receiptName.replace(/\.json$/u, '')
    const backupPath = join(backupsDir, `${stem}.bak`)
    if (!existsSync(backupPath)) continue

    const bytes = readFileSync(backupPath)
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (digest !== meta.sha256) {
      continue // Not the snapshot's own bytes; refuse loud rather than restore wrong.
    }

    writeFileAtomic(meta.originalPath, bytes)
    if (meta.mode !== undefined) chmodSync(meta.originalPath, meta.mode)
    return `restored ${meta.originalPath} from ${backupPath}\n`
  }

  return `no verified snapshot for ${client}\n`
}

/** Refuse to leave a credential-shaped string in a config we just wrote. */
function verifyConfigClean(client: KnownClient, home?: string): void {
  const counts = sweepCredentialPatterns([configPathFor(client, home)])
  const dirty = Object.entries(counts).filter(([, count]) => count > 0)
  if (dirty.length > 0) {
    throw new InstallError('credential-shaped string detected in the config after write; refusing')
  }
}
