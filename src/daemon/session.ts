/**
 * Daemon session: the single owner of vault state.
 *
 * One daemon serves every harness. That is the whole reason this exists rather than a
 * per-harness process: four independent broker processes would mean four unlocked vaults,
 * four approval authorities and four audit logs, and "authenticate once" would be
 * impossible.
 *
 * Concurrency is serialised through a promise chain rather than a mutex, because Node is
 * single-threaded and the only real hazard is interleaved async work (a `await` between
 * reading the vault file and writing it back). Chaining guarantees no interleaving without
 * pulling in a dependency.
 */

import { statSync } from 'node:fs'

import { AuditLog } from '../core/audit.ts'
import type { KeychainStore } from '../core/keychain.ts'
import { createLogger } from '../core/logging.ts'
import type { Operation } from '../core/operations.ts'
import { PolicyEngine } from '../core/policy.ts'
import type { VaultEntry } from '../core/vault.ts'
import { Vault } from '../core/vault.ts'
import type { ClientId, DaemonCommand, RequestFrame, ResponseFrame } from './protocol.ts'

const log = createLogger('daemon')

/** Error codes the shim may act on. Deliberately coarse — a shim must not learn internals. */
export type DaemonErrorCode =
  | 'BAD_REQUEST'
  | 'UNKNOWN_COMMAND'
  | 'UNSUPPORTED_VERSION'
  | 'VAULT_ERROR'
  | 'INTERNAL'

export class DaemonError extends Error {
  readonly code: DaemonErrorCode
  constructor(code: DaemonErrorCode, message: string) {
    super(message)
    this.code = code
  }
}

/**
 * Result of `list_accounts` — the first tool that crosses the trust boundary.
 *
 * Contains service names and account aliases and nothing else. There is deliberately no
 * field here that could hold credential material, so a bug in the shim cannot turn this
 * into a disclosure.
 */
export interface AccountSummary {
  readonly service: string
  readonly accountAlias: string
  readonly secretType: string
  readonly createdAt: string
  readonly rotatedAt: string | null
}

export interface DaemonStatus {
  readonly pid: number
  readonly socketPath: string
  readonly startedAt: string
  readonly credentialCount: number
  readonly connectedClients: readonly ClientId[]
  readonly protocolVersion: number
}

/**
 * Strip a `VaultEntry` down to the fields safe to expose.
 *
 * Written as an explicit field list rather than a spread. A spread would forward any
 * field added to `VaultEntry` later — which is precisely how a secret leaks into a
 * response by accident, months after the field was introduced.
 */
function toAccountSummary(entry: VaultEntry): AccountSummary {
  return {
    service: entry.service,
    accountAlias: entry.accountAlias,
    secretType: entry.secretType,
    createdAt: entry.createdAt,
    rotatedAt: entry.rotatedAt,
  }
}

/**
 * Optional reload source.
 *
 * The vault *file* is the durable source of truth, but the daemon keeps an open `Vault`
 * in memory. `vaultbroker secret add` writes that file directly, so without a reload check
 * the daemon would answer `list_accounts` from a stale snapshot — a real bug, observed
 * only once a long-lived daemon was tested against a CLI write.
 *
 * Rather than forcing every mutation through the daemon (which would mean refusing to add
 * a credential whenever the daemon happened to be running), the daemon re-reads the file
 * when it changes on disk.
 */
export interface ReloadSource {
  readonly keychain: KeychainStore
  readonly path: string
}

export class Session {
  readonly startedAt: Date
  readonly #reload: ReloadSource | undefined
  readonly #clients = new Set<ClientId>()
  /** Serialises async work so two concurrent requests cannot interleave file writes. */
  #chain: Promise<unknown> = Promise.resolve()
  #vault: Vault
  #signature: string
  readonly #policy: PolicyEngine

  constructor(
    vault: Vault,
    options: { reload?: ReloadSource; now?: Date; audit?: AuditLog; policy?: PolicyEngine } = {},
  ) {
    this.#vault = vault
    this.#reload = options.reload
    this.startedAt = options.now ?? new Date()
    this.#signature = this.#currentSignature()
    this.#policy = options.policy ?? new PolicyEngine({ audit: options.audit ?? new AuditLog() })
  }

  /** The policy engine. Exposed for the CLI and tests; requests still go through here. */
  get policy(): PolicyEngine {
    return this.#policy
  }

  /** Cheap change detector: size plus mtime. Good enough for a local file we own. */
  #currentSignature(): string {
    if (this.#reload === undefined) return 'fixed'
    try {
      const stats = statSync(this.#reload.path)
      return `${String(stats.size)}:${String(stats.mtimeMs)}`
    } catch {
      return 'absent'
    }
  }

  /**
   * Re-read the vault if the file changed underneath us.
   *
   * Runs inside the serialised section so a reload cannot race a concurrent read. If the
   * reload fails — most likely because the keychain KEK no longer matches — the previous
   * in-memory vault is kept and the error surfaces, rather than leaving the daemon
   * serving an empty list as though nothing had been stored.
   */
  #reloadIfChanged(): void {
    if (this.#reload === undefined) return

    const signature = this.#currentSignature()
    if (signature === this.#signature) return

    try {
      const fresh = Vault.open(this.#reload.keychain, this.#reload.path)
      this.#vault.dispose()
      this.#vault = fresh
      this.#signature = signature
      log.info('vault reloaded after out-of-band change')
    } catch (error) {
      log.warn('vault reload failed; keeping previous state', { error })
    }
  }

  /**
   * Run a task with exclusive access.
   *
   * Errors are swallowed here and returned as values; a rejected chain would otherwise
   * poison every subsequent request.
   */
  #serialise<T>(task: () => Promise<T>): Promise<T> {
    const result = this.#chain.then(task, task)
    this.#chain = result.catch(() => undefined)
    return result
  }

  /** Handle one request frame and produce a response frame. Never throws. */
  async handle(frame: RequestFrame, socketPath: string): Promise<ResponseFrame> {
    const respond = (result: unknown): ResponseFrame => ({
      kind: 'response',
      id: frame.id,
      ok: true,
      result,
    })

    const fail = (code: DaemonErrorCode, message: string): ResponseFrame => ({
      kind: 'response',
      id: frame.id,
      ok: false,
      error: { code, message },
    })

    if (frame.version !== 1) {
      return fail('UNSUPPORTED_VERSION', `unsupported protocol version ${frame.version}`)
    }

    this.#clients.add(frame.clientId)

    try {
      switch (frame.command) {
        case 'ping':
          return respond({ pong: true, pid: process.pid })

        case 'status':
          return respond(this.#status(socketPath))

        case 'list_accounts':
          return respond(
            await this.#serialise(async () => {
              this.#reloadIfChanged()
              return this.#vault.list().map(toAccountSummary)
            }),
          )

        // I3: authorisation is reachable only through the policy engine. There is
        // deliberately no daemon command that performs an operation directly.
        case 'grant': {
          const capability = this.#policy.grant({
            clientId: frame.clientId,
            service: readString(frame, 'service'),
            accountAlias: readString(frame, 'accountAlias'),
            operations: readOperations(frame),
            projectPath: readString(frame, 'projectPath'),
            ttlMinutes: readNumber(frame, 'ttlMinutes', 15),
            auditHead: this.#policy.audit.head,
          })
          return respond({ capabilityId: capability.id, expiresAt: capability.expiresAt })
        }

        case 'authorise': {
          const verdict = this.#policy.authorise({
            clientId: frame.clientId,
            capabilityId: readString(frame, 'capabilityId'),
            service: readString(frame, 'service'),
            accountAlias: readString(frame, 'accountAlias'),
            operation: readString(frame, 'operation') as Operation,
            projectPath: readString(frame, 'projectPath'),
          })
          return respond({
            allowed: verdict.allowed,
            reason: verdict.allowed ? null : verdict.reason,
            auditEventId: verdict.auditEventId,
          })
        }

        case 'audit_recent':
          return respond(this.#policy.audit.recent(readNumber(frame, 'count', 20)))

        case 'shutdown':
          return respond({ stopping: true })

        default:
          return fail('UNKNOWN_COMMAND', `unknown command: ${String(frame.command)}`)
      }
    } catch (error) {
      // The shim must not learn vault internals, so the message is coarse. The detail
      // goes to stderr, where it is redacted.
      log.warn('request failed', { command: frame.command, error })
      return fail('VAULT_ERROR', 'the vault could not complete this request')
    }
  }

    #status(socketPath: string): DaemonStatus {
    return {
      pid: process.pid,
      socketPath,
      startedAt: this.startedAt.toISOString(),
      credentialCount: this.#vault.size,
      connectedClients: [...this.#clients].sort(),
      protocolVersion: 1,
    }
  }

  /** Release the vault's key material. */
  dispose(): void {
    this.#vault.dispose()
    this.#signature = 'disposed'
  }
}

/** Read a required string parameter, or refuse with a coarse error. */
function readString(frame: RequestFrame, name: string): string {
  const value = frame.params[name]
  if (typeof value !== 'string' || value === '') {
    throw new DaemonError('BAD_REQUEST', `${name} is required`)
  }
  return value
}

function readNumber(frame: RequestFrame, name: string, fallback: number): number {
  const value = frame.params[name]
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function readOperations(frame: RequestFrame): Operation[] {
  const value = frame.params['operations']
  if (!Array.isArray(value) || value.length === 0) {
    throw new DaemonError('BAD_REQUEST', 'operations must be a non-empty array')
  }
  // Elements are validated by the policy engine, which rejects unknown operations.
  return value as Operation[]
}

/** Open the daemon's vault. Exposed so the server and tests share one construction path. */
export function openDaemonVault(keychain: KeychainStore, path?: string): Vault {
  return Vault.open(keychain, path)
}

export type { DaemonCommand }