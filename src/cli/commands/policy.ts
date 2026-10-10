/**
 * `vaultbroker policy` — grant, approve, revoke and inspect policy state.
 *
 * This command exists as the **out-of-band** path for permissions. It is deliberately a
 * CLI rather than an MCP tool: an approval that a model could request would not be an
 * approval. Every mutation here requires a human at a terminal.
 *
 * It talks to a running daemon when one is listening, and otherwise operates on a local
 * policy engine so that grants and audit history can be inspected before the daemon is
 * ever started.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { AuditLog, verifyChainFile } from '../../core/audit.ts'
import type { Capability } from '../../core/capability.ts'
import { describeCapability } from '../../core/capability.ts'
import { createLogger } from '../../core/logging.ts'
import type { Operation } from '../../core/operations.ts'
import { PolicyEngine } from '../../core/policy.ts'
import { auditLogPath } from '../../core/runtime-paths.ts'
import { CliError, parseArgs, type CommandResult } from './secret.ts'

const log = createLogger('policy-cli')

/**
 * Grant persistence.
 *
 * Grants live in a JSON file beside the audit log rather than inside the vault: they are
 * policy state, not secret material, and keeping them separate means revoking every grant
 * on a machine does not require touching the vault or its keychain.
 *
 * Capability *nonces* are stored here too. That is deliberate — a nonce must survive a
 * daemon restart, or a restart would become a replay window.
 */
const GRANTS_FILE = 'grants.json'

function grantsPath(): string {
  return join(dirname(auditLogPath()), GRANTS_FILE)
}

export function runPolicy(argv: readonly string[]): CommandResult {
  const [subcommand, ...rest] = argv
  const { flags } = parseArgs(rest)

  switch (subcommand) {
    case 'grant':
      return runGrant(flags)
    case 'list':
      return runList()
    case 'describe':
      return runDescribe(flags)
    case 'revoke':
      return runRevoke(flags)
    case 'approve':
      return runApprove(flags)
    case 'audit':
      return runAudit(flags)
    case 'verify':
      return runVerify()
    default:
      throw new CliError(
        `unknown subcommand: ${subcommand ?? '(none)'}. Expected grant, list, describe, revoke, approve, audit or verify.`,
      )
  }
}

/** Load grants from disk, tolerating a missing file. */
function loadGrants(): Capability[] {
  const path = grantsPath()
  if (!existsSync(path)) return []
  return JSON.parse(readFileSync(path, 'utf8')) as Capability[]
}

function saveGrants(grants: readonly Capability[]): void {
  writeFileSync(grantsPath(), `${JSON.stringify(grants, null, 2)}\n`, { mode: 0o600 })
}

/**
 * A policy engine backed by the persisted audit log.
 *
 * Deliberately does NOT re-mint persisted grants. An earlier version did, which meant
 * every read-only command (`policy list`) appended fresh `grant.requested` /
 * `grant.minted` events to the audit chain — a history that recorded the act of looking
 * at it rather than the decisions that mattered. Read commands now read `grants.json`
 * directly; only `grant` and `approve` construct an engine.
 */
function engineForAudit(): PolicyEngine {
  return new PolicyEngine({ audit: AuditLog.open(auditLogPath()) })
}

function requiredFlag(flags: ReadonlyMap<string, string | true>, name: string): string {
  const value = flags.get(name)
  if (value === undefined || value === true) throw new CliError(`--${name} is required`)
  return value
}

function runGrant(flags: ReadonlyMap<string, string | true>): CommandResult {
  const operations = requiredFlag(flags, 'operations').split(',').map((s) => s.trim())

  const engine = engineForAudit()
  const capability = engine.grant({
    clientId: requiredFlag(flags, 'client'),
    service: requiredFlag(flags, 'service'),
    accountAlias: requiredFlag(flags, 'account'),
    operations: operations as Operation[],
    projectPath: requiredFlag(flags, 'project'),
    ttlMinutes: Number(flags.get('ttl') ?? '15'),
  })

  const existing = loadGrants().filter((g) => g.id !== capability.id)
  saveGrants([...existing, capability])

  return { exitCode: 0, output: `${describeCapability(capability)}\n` }
}

function runList(): CommandResult {
  const grants = loadGrants()
  if (grants.length === 0) return { exitCode: 0, output: 'no grants\n' }

  const lines = grants.map((grant) => {
    const prefix = `${grant.id.slice(0, 12)}  ${grant.clientId.padEnd(12)} ${grant.service}/${grant.accountAlias}`
    return `${prefix}  [${grant.tier}]  expires ${grant.expiresAt}  ${String(grant.operations.length)} op(s)`
  })
  return { exitCode: 0, output: `${lines.join('\n')}\n` }
}

function runDescribe(flags: ReadonlyMap<string, string | true>): CommandResult {
  const id = requiredFlag(flags, 'id')
  const grant = loadGrants().find((g) => g.id === id)
  if (grant === undefined) return { exitCode: 1, output: 'not found\n' }
  return { exitCode: 0, output: `${describeCapability(grant)}\n` }
}

function runRevoke(flags: ReadonlyMap<string, string | true>): CommandResult {
  const grants = loadGrants()

  const client = flags.get('client')
  if (typeof client === 'string') {
    const remaining = grants.filter((g) => g.clientId !== client)
    const revoked = grants.length - remaining.length
    saveGrants(remaining)
    return { exitCode: 0, output: `revoked ${String(revoked)} grant(s) for ${client}\n` }
  }

  const id = requiredFlag(flags, 'id')
  const remaining = grants.filter((g) => g.id !== id)
  if (remaining.length === grants.length) return { exitCode: 1, output: 'not found\n' }
  saveGrants(remaining)
  return { exitCode: 0, output: `revoked ${id}\n` }
}

function runApprove(flags: ReadonlyMap<string, string | true>): CommandResult {
  const engine = engineForAudit()
  const operation = requiredFlag(flags, 'operation')

  const approval = engine.approve({
    clientId: requiredFlag(flags, 'client'),
    service: requiredFlag(flags, 'service'),
    accountAlias: requiredFlag(flags, 'account'),
    operation: operation as Operation,
    projectPath: requiredFlag(flags, 'project'),
  })

  return {
    exitCode: 0,
    output:
      `approved ${approval.operation} for ${approval.clientId}\n` +
      `  id:       ${approval.id}\n` +
      `  expires:  ${approval.expiresAt}\n` +
      `  single use: yes\n`,
  }
}

function runAudit(flags: ReadonlyMap<string, string | true>): CommandResult {
  const log_ = AuditLog.open(auditLogPath())
  const count = Number(flags.get('count') ?? '20')
  const events = log_.recent(count)

  if (events.length === 0) return { exitCode: 0, output: 'no audit events\n' }

  const lines = events.map(
    (event) =>
      `${event.at}  ${event.severity.padEnd(8)} ${event.kind.padEnd(18)} ${event.decision ?? '-'}` +
      `${event.reason === null ? '' : ` (${event.reason})`}  ${event.detail ?? ''}`,
  )
  return { exitCode: 0, output: `${lines.join('\n')}\n` }
}

function runVerify(): CommandResult {
  const path = auditLogPath()
  const verdict = verifyChainFile(path)
  return {
    exitCode: verdict.ok ? 0 : 1,
    output: `${verdict.ok ? 'verified' : 'BROKEN'}: ${verdict.message}\n`,
  }
}