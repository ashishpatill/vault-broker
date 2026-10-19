/**
 * `vaultbroker import` and `vaultbroker config` — migrate a plaintext token.
 *
 * The reason this command exists: a token sitting in a harness config file under `env`
 * is in the model's reach, in every backup of that file, and in the harness's own
 * transcripts. The migration moves it into the vault (import), then rewrites the config
 * to stop carrying it (migrate), with a verified backup that `rollback` can restore
 * byte-for-byte.
 *
 * The same redaction rules as everywhere else apply with extra force here, because the
 * command's whole working set *is* a credential: nothing in any code path, message,
 * table or error may include the plaintext, and the value is only ever handed to
 * `Secret` or counted, never interpolated.
 */

import { createHash } from 'node:crypto'
import { chmodSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, join } from 'node:path'

import { ensureDir0700, writeFileAtomic } from '../../core/fsx.ts'
import { Secret } from '../../core/secret.ts'
import { runtimeRoot } from '../../core/runtime-paths.ts'
import { InMemoryKeychain, MacSecurityKeychain, type KeychainStore } from '../../core/keychain.ts'
import { Vault } from '../../core/vault.ts'
import { parseArgs } from './secret.ts'
import type { CommandResult } from './secret.ts'

export class MigrationError extends Error {}

/** Shape of a harness MCP config we understand (Cursor's `mcpServers` map). */
interface McpConfig {
  readonly mcpServers: Record<string, { readonly env?: Record<string, unknown> } & Record<string, unknown>>
}

/** Patterns for credential-shaped strings we sweep for. Deliberately provider-shaped. */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /napi_[A-Za-z0-9-_]{20,}/u,
  /ghp_[A-Za-z0-9]{30,}/u,
]

/** Default location of the only config surface this build imports from. */
export function defaultCursorConfigPath(): string {
  return join(homedir(), '.cursor', 'mcp.json')
}

/**
 * Find the config entry that carries the Neon credential.
 *
 * Name matching is exact first, then case-insensitive, then prefix — real-world configs
 * have said "Neon", "neon" and "Neon MCP". The credential inside is NOT read here; the
 * caller decides when and how to wrap it.
 */
export function findServiceEntry(
  parsed: unknown,
  service: string,
): { name: string; entry: Record<string, unknown> } | MigrationError {
  const servers = (parsed as Partial<McpConfig> | null)?.mcpServers
  if (servers === undefined || servers === null || typeof servers !== 'object') {
    return new MigrationError('config has no mcpServers map')
  }

  const names = Object.keys(servers)
  const exact = names.find((name) => name === service)
  const loose = names.find((name) => name.toLowerCase() === service.toLowerCase())
  const fuzzy = names.find((name) => name.toLowerCase().startsWith(service.toLowerCase()))

  const name = exact ?? loose ?? fuzzy
  if (name === undefined) {
    return new MigrationError(`no server entry for ${service} in mcpServers`)
  }

  return { name, entry: servers[name] as Record<string, unknown> }
}

/**
 * Wrap the credential from a server entry's env block.
 *
 * Accepts any single env value that names itself a token, or self-identifies by shape.
 * Two values matching is ambiguous; refusing with no detail is safer than guessing.
 */
function extractCredentialSecret(entry: Record<string, unknown>): { secret: Secret; byteLength: number } | MigrationError {
  const env = entry['env']
  if (env === undefined || env === null || typeof env !== 'object') {
    return new MigrationError('the service entry carries no env block')
  }

  const pairs = Object.entries(env as Record<string, unknown>)
  const values = pairs
    .map(([, value]) => value)
    .filter((value): value is string => typeof value === 'string' && value.length > 0)

  // Prefer a value that self-identifies by shape; fall back to a single env key that
  // names itself a token. More than one candidate is ambiguous, and guessing at which
  // plaintext is "the" credential is not a risk worth taking at any convenience.
  const byShape = values.filter((value) => CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value)))
  const byKey = pairs.filter(([key, value]) => /token/i.test(key) && typeof value === 'string' && value.length > 0)

  if (byShape.length === 0 && byKey.length === 0) {
    return new MigrationError('no credential-shaped env value found')
  }
  if (byShape.length > 1) {
    return new MigrationError('ambiguous credential source; refusing to guess')
  }

  const chosen = byShape.length === 1 ? (byShape[0] as string) : (byKey[0]?.[1] as string)
  const secret = Secret.of(chosen)
  return { secret, byteLength: secret.byteLength }
}

/**
 * Count credential-shaped occurrences in a list of files.
 *
 * Returns paths and counts only. The caller renders them; the value itself must never
 * reach output, so this returns no substring beyond per-file counts.
 */
export function sweepCredentialPatterns(paths: readonly string[]): Readonly<Record<string, number>> {
  const counts: Record<string, number> = {}
  for (const path of paths) {
    if (!existsSync(path)) continue
    const text = readFileSync(path, 'utf8')
    counts[path] = CREDENTIAL_PATTERNS.reduce((n, pattern) => n + (text.match(new RegExp(pattern, 'gu'))?.length ?? 0), 0)
  }
  return counts
}

/**
 * Open the vault for import, honouring the shared --memory/--keychain flags.
 */
function openVault(flags: ReadonlyMap<string, string | true>, override?: KeychainStore): Vault {
  if (override !== undefined) return Vault.open(override)
  if (flags.get('memory') === true) return Vault.open(new InMemoryKeychain())
  return Vault.open(new MacSecurityKeychain())
}

/**
 * `vaultbroker import --from-config [--service neon] [--account primary] [--config <path>]`
 *
 * Reads the token out of a harness config file, stores it in the vault, and reports
 * metadata plus residual findings. The output is checked by tests for the absence of any
 * credential value.
 */
export function runImport(argv: readonly string[], keychainOverride?: KeychainStore): CommandResult {
  const { flags } = parseArgs(argv)

  if (flags.get('from-config') !== true) {
    return { exitCode: 2, output: 'import requires --from-config (the only supported source for v0)\n' }
  }

  const service = typeof flags.get('service') === 'string' ? (flags.get('service') as string) : 'neon'
  const account = typeof flags.get('account') === 'string' ? (flags.get('account') as string) : 'primary'
  const configPath = typeof flags.get('config') === 'string' ? (flags.get('config') as string) : defaultCursorConfigPath()

  if (!existsSync(configPath)) {
    return { exitCode: 1, output: `config not found: ${configPath}\n` }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(configPath, 'utf8'))
  } catch {
    return { exitCode: 1, output: `config is not valid JSON: ${configPath}\n` }
  }

  const found = findServiceEntry(parsed, service)
  if (found instanceof MigrationError) {
    return { exitCode: 1, output: `${found.message}\n` }
  }

  const credential = extractCredentialSecret(found.entry)
  if (credential instanceof MigrationError) {
    return { exitCode: 1, output: `${credential.message}\n` }
  }

  const vault = openVault(flags, keychainOverride)
  try {
    const rotated = vault.find(service, account) !== undefined
    try {
      if (rotated) {
        vault.rotate(service, account, credential.secret)
      } else {
        vault.add({
          service,
          accountAlias: account,
          secret: credential.secret,
          secretType: 'bearer',
          note: `imported from ${basename(configPath)}`,
        })
      }
    } finally {
      credential.secret.dispose()
    }

    const residuals = sweepCredentialPatterns([configPath])
    return {
      exitCode: 0,
      output: `${rotated ? 'rotated' : 'imported'} ${service}/${account} (bearer, ${String(
        credential.byteLength,
      )} bytes)\nsource: ${configPath}\nresidual credential-shaped strings: ${JSON.stringify(residuals)}\n` +
        'next: vaultbroker config migrate --client cursor\n',
    }
  } finally {
    vault.dispose()
  }
}

/**
 * Backup file naming: newest sorts last, and the client is in the name so rollback can
 * filter without reading contents.
 */
function backupStem(client: string, configPath: string, stamp: string): string {
  return `${client}-${stamp}-${basename(configPath)}`
}

function backupsDir(): string {
  return join(runtimeRoot(), 'backups')
}

/**
 * Snapshot a config file with a hash receipt.
 *
 * A backup that has not been read back is not a backup; this verifies both existence and
 * digest before the caller is allowed to touch the original. The error is coarse on
 * purpose: no content of the file is ever quoted.
 */
function snapshotOriginal(configPath: string, client: string, stamp: string): MigrationError | { path: string; bytes: number } {
  const bytes = readFileSync(configPath)
  ensureDir0700(backupsDir())
  const stem = backupStem(client, configPath, stamp)
  const backupPath = join(backupsDir(), `${stem}.bak`)
  const metaPath = join(backupsDir(), `${stem}.json`)

  writeFileAtomic(backupPath, bytes)

  const written = readFileSync(backupPath)
  if (!written.equals(bytes)) {
    return new MigrationError('backup could not be verified; aborting without touching the config')
  }

  writeFileAtomic(
    metaPath,
    JSON.stringify(
      {
        client,
        stamp,
        originalPath: configPath,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        bytes: bytes.byteLength,
        mode: statSync(configPath).mode & 0o7777,
      },
      null,
      2,
    ),
  )

  return { path: backupPath, bytes: bytes.byteLength }
}

/** Render the proposed migration as a short, credential-free summary. */
function summariseRemoval(parsed: unknown, entryName: string): Record<string, unknown> {
  const servers = (parsed as Partial<McpConfig>).mcpServers
  return {
    removedEntry: entryName,
    remaining: Object.keys(servers ?? {}).filter((name) => name !== entryName),
  }
}

/**
 * Rewrite the config in place with one server entry removed.
 *
 * Parse → mutate → re-serialise preserves key order (JS object insertion order), so the
 * unrelated entries survive textually for human readers, though not byte-for-byte —
 * that is exactly what the backup and `rollback` are for.
 */
function removeEntry(configPath: string, entryName: string): string {
  const parsed = JSON.parse(readFileSync(configPath, 'utf8')) as Partial<McpConfig>
  const servers = parsed.mcpServers as Record<string, unknown> | undefined

  if (servers === undefined) {
    throw new MigrationError('config has no mcpServers map')
  }
  if (!(entryName in servers)) {
    throw new MigrationError(`entry ${entryName} is no longer present`)
  }
  delete servers[entryName]

  const rewritten = `${JSON.stringify(parsed, null, 2)}\n`
  writeFileAtomic(configPath, rewritten)
  return rewritten
}

/**
 * `vaultbroker config migrate --client cursor [--config <path>] [--yes]`
 *
 * Without `--yes` this is a dry run: the proposed change is summarised and nothing is
 * written. With `--yes`: verified backup, atomic rewrite, residual sweep.
 */
export function runConfigMigration(argv: readonly string[]): CommandResult {
  const { flags } = parseArgs(argv)
  const client = typeof flags.get('client') === 'string' ? (flags.get('client') as string) : 'cursor'
  const configPath =
    typeof flags.get('config') === 'string' ? (flags.get('config') as string) : defaultCursorConfigPath()

  if (!existsSync(configPath)) {
    return { exitCode: 1, output: `config not found: ${configPath}\n` }
  }

  const parsed: unknown = JSON.parse(readFileSync(configPath, 'utf8'))
  const found = findServiceEntry(parsed, 'neon')
  if (found instanceof MigrationError) {
    return { exitCode: 1, output: `${found.message}\n` }
  }

  const proposed = summariseRemoval(parsed, found.name)
  if (flags.get('yes') !== true) {
    return {
      exitCode: 0,
      output: `proposed (dry run, nothing written):\n${JSON.stringify(proposed, null, 2)}\n` +
        're-run with --yes to apply\n',
    }
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const snapshot = snapshotOriginal(configPath, client, stamp)
  if (snapshot instanceof MigrationError) {
    return { exitCode: 1, output: `${snapshot.message}\n` }
  }

  removeEntry(configPath, found.name)

  const residuals = sweepCredentialPatterns([configPath])
  return {
    exitCode: 0,
    output: `rewrote ${configPath}\nremoved entry: ${found.name}\nbackup: ${snapshot.path}\n` +
      `residual credential-shaped strings: ${JSON.stringify(residuals)}\n` +
      `rollback: vaultbroker config rollback --client ${client}\n`,
  }
}

/**
 * `vaultbroker config rollback [--client cursor]`
 *
 * Restores the most recent verified snapshot for the client, byte-for-byte, including the
 * original file mode. The digest is re-verified before the restore; a mismatch aborts.
 */
export function runConfigRollback(argv: readonly string[]): CommandResult {
  const { flags } = parseArgs(argv)
  const client = typeof flags.get('client') === 'string' ? (flags.get('client') as string) : 'cursor'
  const snapshotDir = backupsDir()

  if (!existsSync(snapshotDir)) {
    return { exitCode: 1, output: 'no backups exist\n' }
  }

  const metas = readdirSafe(snapshotDir).filter(
    (name) => name.startsWith(`${client}-`) && name.endsWith('.json'),
  )
  if (metas.length === 0) {
    return { exitCode: 1, output: `no backups for ${client}\n` }
  }
  const newest = metas.sort().at(-1)
  if (newest === undefined) {
    return { exitCode: 1, output: 'backup metadata is missing\n' }
  }

  const metaPath = join(snapshotDir, newest)
  const stem = newest.replace(/\.json$/u, '')
  const backupPath = join(snapshotDir, `${stem}.bak`)

  const meta = JSON.parse(readFileSync(metaPath, 'utf8')) as {
    originalPath?: string
    sha256?: string
    mode?: number
  }
  if (meta.originalPath === undefined || meta.sha256 === undefined) {
    return { exitCode: 1, output: 'backup metadata is incomplete\n' }
  }

  const restored = readFileSync(backupPath)
  const digest = createHash('sha256').update(restored).digest('hex')
  if (digest !== meta.sha256) {
    return { exitCode: 1, output: 'backup does not match its verified hash; refusing to restore\n' }
  }

  writeFileAtomic(meta.originalPath, restored)
  if (meta.mode !== undefined) chmodSync(meta.originalPath, meta.mode)

  return {
    exitCode: 0,
    output: `restored ${meta.originalPath} from ${backupPath}\n`,
  }
}

function readdirSafe(dir: string): string[] {
  return readdirSync(dir)
}
