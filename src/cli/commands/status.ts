/**
 * `vaultbroker status` — one honest control panel.
 *
 * The command's job is to answer, in one screen, everything an operator needs before
 * trusting the broker: what holds credentials, what may ask for them, what the policy
 * state is, whether the audit chain still verifies, and whether any plaintext token is
 * still sitting in a harness config. Counts and verdicts only — the only credential-
 * adjacent data here is a per-file occurrence *count*, never a value, and the suite
 * asserts that a canary planted in a config never reaches this output.
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { verifyChainFile } from '../../core/audit.ts'
import { InMemoryKeychain, MacSecurityKeychain, type KeychainStore } from '../../core/keychain.ts'
import { auditLogPath, runtimeRoot } from '../../core/runtime-paths.ts'
import { Vault } from '../../core/vault.ts'
import { sweepCredentialPatterns } from './config.ts'
import { configPathFor } from '../../install/install.ts'
import { ClientRegistry } from '../../install/registry.ts'
import { PolicyEngine } from '../../core/policy.ts'
import { createGitHubAdapter } from '../../adapters/github.ts'
import { createNeonAdapter } from '../../adapters/neon.ts'
import { parseArgs, type CommandResult } from './secret.ts'

/** Grants live beside the audit log — the same convention `policy grant` uses. */
const GRANTS_FILE = 'grants.json'

interface StoredGrant {
  readonly id?: string
  readonly clientId?: string
  readonly expiresAt?: string
}

/** Config surfaces the residual sweep covers. The extra Cursor map has no client id. */
function residualPaths(): string[] {
  const cursor = configPathFor('cursor')
  return [
    configPathFor('cursor'),
    configPathFor('claude-code'),
    configPathFor('opencode'),
    configPathFor('codex'),
    join(dirname(cursor), 'mcp-servers.json'),
  ]
}

export function runStatus(argv: readonly string[], keychainOverride?: KeychainStore): CommandResult {
  const { flags } = parseArgs(argv)
  const keychain = keychainOverride ?? (flags.get('memory') === true ? new InMemoryKeychain() : new MacSecurityKeychain())

  const lines: string[] = []

  // Runtime directory mode. A runtime root that grew looser than 0700 is a finding, not
  // a footnote — anything with read access to the socket directory can talk to the daemon.
  const root = runtimeRoot()
  if (existsSync(root)) {
    const mode = statSync(root).mode & 0o7777
    lines.push(`runtime    ${root}`)
    lines.push(`           mode ${mode.toString(8).padStart(4, '0')} ${mode === 0o700 ? 'ok' : 'TOO PERMISSIVE'}`)
  } else {
    lines.push(`runtime    ${root} (not initialised — run vaultbroker init)`)
  }

  // Vault: metadata only. Never list values, and byte-lengths only on request.
  try {
    const vault = Vault.open(keychain)
    try {
      lines.push(`vault      ${String(vault.list().length)} credential(s)`)
    } finally {
      vault.dispose()
    }
  } catch {
    lines.push('vault      unreadable in this shell (unlock required, or --memory)')
  }

  // Grants: live versus expired, from the persisted store.
  const grantsPath = join(dirname(auditLogPath()), GRANTS_FILE)
  if (existsSync(grantsPath)) {
    try {
      const grants = JSON.parse(readFileSync(grantsPath, 'utf8')) as StoredGrant[]
      const now = Date.now()
      const live = grants.filter((g) => typeof g.expiresAt === 'string' && new Date(g.expiresAt).getTime() > now)
      lines.push(`grants     ${String(live.length)} live, ${String(grants.length - live.length)} expired`)
    } catch {
      lines.push('grants     unreadable (grants.json is corrupt; revoke all and re-grant)')
    }
  } else {
    lines.push('grants     none')
  }

  // Audit: the chain verdict is the headline; a broken chain invalidates every decision
  // in it, so colour that only when broken.
  const auditPath = auditLogPath()
  if (existsSync(auditPath)) {
    const verdict = verifyChainFile(auditPath)
    const count = readFileSync(auditPath, 'utf8').split('\n').filter((line) => line.trim() !== '').length
    lines.push(`audit      ${verdict.ok ? 'chain verified' : `BROKEN at seq ${String(verdict.brokenAtSeq)}`} — ${String(count)} event(s)`)
    if (!verdict.ok) lines.push(`           ${verdict.message}`)
  } else {
    lines.push('audit      empty')
  }

  // Registered harnesses: who may ask, and when their identity was last verified.
  const policy = new PolicyEngine()
  const registry = ClientRegistry.load({ policy })
  const clients = registry.list()
  lines.push(
    clients.length === 0
      ? 'clients    none registered'
      : `clients    ${String(clients.length)} registered: ${clients.map((c) => c.clientId).join(', ')}`,
  )

  // Adapters: what this build can broker, operation counts only.
  const adapters = [createGitHubAdapter(), createNeonAdapter()]
  lines.push(`adapters   ${adapters.map((a) => `${a.service}: ${String(a.operations.length)} op(s)`).join(', ')}`)

  // Residual plaintext findings across every config surface. Counts only.
  const counts = sweepCredentialPatterns(residualPaths())
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0)
  lines.push('residual   credential-shaped strings in harness configs:')
  for (const [path, count] of Object.entries(counts)) {
    lines.push(`           ${count === 0 ? 'clean      ' : `FOUND ${String(count)}  `}${path}`)
  }
  if (total === 0) {
    lines.push('           (no files carried findings; missing files are skipped)')
  }

  return { exitCode: 0, output: `${lines.join('\n')}\n` }
}
