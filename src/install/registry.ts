/**
 * Client registry: binds a client id to a verified code signature.
 *
 * The rule this file exists to enforce: **identity is re-verified on every connection,
 * not just at registration.** A one-time check is worthless against a binary that is
 * swapped afterwards, which is the entire attack this defends against.
 *
 * On mismatch the response is refuse + lock, not refuse-and-carry-on:
 *
 *   1. the request is refused;
 *   2. every grant for that client is revoked immediately, regardless of TTL;
 *   3. a critical audit event is written with the specific reason;
 *   4. the vault is locked, releasing key material from memory;
 *   5. the user is notified — a silent refusal would leave a compromised client free to
 *      keep probing with no indication anything happened.
 *
 * Steps 2–5 are what turn "we noticed" into "we contained it".
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { createLogger } from '../core/logging.ts'
import type { PolicyEngine } from '../core/policy.ts'
import { ensureDir0700 } from '../core/fsx.ts'
import { clientsDir } from '../core/runtime-paths.ts'
import {
  inspectSignature,
  verifyIdentity,
  type ClientRegistration,
  type CodeSignatureIdentity,
  type IdentityVerdict,
} from './identity.ts'

const log = createLogger('registry')

const REGISTRY_FILE = 'registry.json'

function registryPath(): string {
  return join(clientsDir(), REGISTRY_FILE)
}

/** What a caller is told after a failed verification. Coarse on purpose. */
export interface RegistrationOutcome {
  readonly allowed: boolean
  readonly reason: string | null
  readonly message: string | null
  /** True when the vault was locked as a result. */
  readonly vaultLocked: boolean
}

export type LockVault = () => void

export type NotifyUser = (message: string) => void

export class ClientRegistry {
  readonly #registrations = new Map<string, ClientRegistration>()
  readonly #policy: PolicyEngine
  readonly #lockVault: LockVault
  readonly #notify: NotifyUser

  constructor(options: {
    policy: PolicyEngine
    lockVault?: LockVault
    notify?: NotifyUser
    registrations?: readonly ClientRegistration[]
  }) {
    this.#policy = options.policy
    this.#lockVault = options.lockVault ?? ((): void => {})
    this.#notify = options.notify ?? ((): void => {})

    for (const registration of options.registrations ?? []) {
      this.#registrations.set(registration.clientId, registration)
    }
  }

  list(): ClientRegistration[] {
    return [...this.#registrations.values()]
  }

  get(clientId: string): ClientRegistration | undefined {
    return this.#registrations.get(clientId)
  }

  /**
   * Register a client by inspecting its binary.
   *
   * Refuses to register an unsigned or invalid binary: registering an unverified identity
   * would create the appearance of verification while providing none.
   */
  register(clientId: string, label: string, target: string): ClientRegistration {
    const identity = inspectSignature(target)

    if (!identity.signatureValid) {
      throw new Error(
        `${label} at ${target} is not correctly code-signed. Refusing to register it: a ` +
          `registration that cannot be verified would provide no protection.`,
      )
    }

    const registration: ClientRegistration = Object.freeze({
      clientId,
      label,
      identity,
      registeredAt: new Date().toISOString(),
    })

    this.#registrations.set(clientId, registration)

    this.#policy.record({
      kind: 'client.registered',
      severity: 'notice',
      clientId,
      detail: {
        label,
        teamId: identity.teamId,
        identifier: identity.identifier,
        notarized: identity.notarized,
        path: identity.path,
      },
    })

    return registration
  }

  /** Remove a client and every grant it held. */
  unregister(clientId: string): boolean {
    const removed = this.#registrations.delete(clientId)
    this.#policy.revokeClient(clientId, 'client-unregistered')
    if (removed) {
      this.#policy.record({ kind: 'client.unregistered', severity: 'notice', clientId })
    }
    return removed
  }

  /**
   * Verify a client before serving it, and contain the damage on mismatch.
   *
   * `target` is the path the shim claims. It is re-inspected here — the daemon does not
   * trust the caller's word about which binary it is.
   */
  verify(clientId: string, target: string): RegistrationOutcome {
    const registration = this.#registrations.get(clientId)

    if (registration === undefined) {
      this.#policy.record({
        kind: 'client.unknown',
        severity: 'warning',
        clientId,
        decision: 'denied',
        reason: 'unregistered-client',
      })
      return {
        allowed: false,
        reason: 'unregistered-client',
        message: `${clientId} is not registered with this broker`,
        vaultLocked: false,
      }
    }

    let live: CodeSignatureIdentity
    try {
      live = inspectSignature(target)
    } catch (error) {
      // The path the shim named does not resolve. Treated as a verification failure
      // rather than a transient error: a client that cannot produce its own binary is
      // not the client it claims to be.
      return this.#contain(registration, {
        ok: false,
        reason: 'content-changed',
        message:
          error instanceof Error
            ? `could not inspect ${registration.label}: ${error.message}`
            : `could not inspect ${registration.label}`,
      })
    }

    const verdict = verifyIdentity(registration, live)

    if (verdict.ok) {
      this.#policy.record({
        kind: 'client.verified',
        severity: 'info',
        clientId,
        detail: { teamId: live.teamId, path: live.path },
      })
      return { allowed: true, reason: null, message: null, vaultLocked: false }
    }

    return this.#contain(registration, verdict)
  }

  /**
   * Containment path for a failed verification.
   *
   * Ordered so the most important effects happen even if a later step throws: revoke
   * grants, write the audit record, lock the vault, then notify. A failure to notify must
   * not leave grants live.
   */
  #contain(
    registration: ClientRegistration,
    verdict: Extract<IdentityVerdict, { ok: false }>,
  ): RegistrationOutcome {
    const clientId = registration.clientId

    const revoked = this.#policy.revokeClient(clientId, `identity-${verdict.reason}`)

    this.#policy.record({
      kind: 'client.identity-mismatch',
      severity: 'critical',
      clientId,
      decision: 'denied',
      reason: verdict.reason,
      detail: {
        label: registration.label,
        message: verdict.message,
        grantsRevoked: revoked,
        expectedTeam: registration.identity.teamId,
        expectedHash: registration.identity.contentHash,
        response: 'refused, grants revoked, vault locked',
      },
    })

    let vaultLocked = false
    try {
      this.#lockVault()
      vaultLocked = true
    } catch (error) {
      log.error('vault lock failed after identity mismatch', { error })
    }

    const message = `${verdict.message}. Access refused, ${String(revoked)} grant(s) revoked` +
      (vaultLocked ? ', vault locked.' : ', but the vault could NOT be locked — restart the broker.')

    try {
      this.#notify(message)
    } catch (error) {
      log.error('notification failed', { error })
    }

    return { allowed: false, reason: verdict.reason, message, vaultLocked }
  }

  /** Persist registrations so they survive a daemon restart. */
  save(): void {
    ensureDir0700(clientsDir())
    writeFileSync(registryPath(), `${JSON.stringify(this.list(), null, 2)}\n`, { mode: 0o600 })
  }

  /** Load persisted registrations. A missing file is not an error. */
  static load(options: { policy: PolicyEngine; lockVault?: LockVault; notify?: NotifyUser }): ClientRegistry {
    const path = registryPath()
    if (!existsSync(path)) {
      return new ClientRegistry(options)
    }

    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as ClientRegistration[]
      return new ClientRegistry({ ...options, registrations: parsed })
    } catch (error) {
      // Refuse to start with an unreadable registry rather than silently treating every
      // client as unregistered — or worse, as trusted.
      throw new Error(
        `client registry at ${path} could not be read: ${
          error instanceof Error ? error.message : 'unknown'
        }. Fix or remove it; the broker will not start with an unreadable registry.`,
      )
    }
  }
}