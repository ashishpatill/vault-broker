/**
 * Policy engine: the single place a permission decision is made.
 *
 * Every request goes through {@link PolicyEngine.authorise}. There is no second path — no
 * tool handler that checks a scope itself, no adapter that trusts its caller. That matters
 * because a policy engine with an escape hatch is not a policy engine.
 *
 * Defaults are deny. A request is refused when any attribute is missing, unknown, expired,
 * mismatched, or when the evidence required to allow it is absent. Absence of information
 * is treated as a reason to refuse, never as permission.
 *
 * ## What this cannot do in v0.3
 *
 * The engine authorises on a `clientId` string the shim supplies. In I4 that becomes a
 * code-signature check; in v0.2, kernel peer credentials. Until then, a process running as
 * this user could claim to be any registered client. This is stated in the module comment
 * rather than buried, because a least-privilege engine whose identity check is a claim is
 * worth much less than its type signature suggests.
 */

import {
  advance,
  check,
  describeCapability,
  mintCapability,
  nonceMatches,
  type Capability,
  type DenyReason,
  type GrantRequest,
  type RequestContext,
} from './capability.ts'
import { assertKnownOperation, type Operation } from './operations.ts'
import { AuditLog, type AuditEventInput, type AuditLog as AuditLogType } from './audit.ts'

/** Per-request decision, with the audit event that records it. */
export type Authorisation =
  | {
      readonly allowed: true
      readonly capability: Capability
      readonly auditEventId: string
    }
  | {
      readonly allowed: false
      readonly reason: DenyReason
      readonly message: string
      readonly auditEventId: string
    }

/**
 * One-time approval for a sensitive operation.
 *
 * Separate from capabilities on purpose: a grant is a statement made ahead of time, while
 * an approval is a decision made at the moment of use. Keeping them apart is what stops
 * "approve deploy once" from becoming "approve deploy forever".
 */
export interface FreshApproval {
  readonly id: string
  readonly clientId: string
  readonly service: string
  readonly accountAlias: string
  readonly operation: Operation
  readonly projectPath: string
  readonly approvedAt: string
  /** Short window. An approval is not a licence. */
  readonly expiresAt: string
  readonly consumed: boolean
}

export const APPROVAL_WINDOW_MS = 2 * 60 * 1000

export interface PolicyEngineOptions {
  readonly audit?: AuditLogType
  /** Injected in tests; defaults to wall-clock time. */
  readonly now?: () => Date
}

export class PolicyEngine {
  readonly #capabilities = new Map<string, Capability>()
  readonly #usedNonces = new Set<string>()
  readonly #approvals = new Map<string, FreshApproval>()
  readonly #audit: AuditLogType
  readonly #now: () => Date

  constructor(options: PolicyEngineOptions = {}) {
    this.#audit = options.audit ?? new AuditLog()
    this.#now = options.now ?? ((): Date => new Date())
  }

  get audit(): AuditLogType {
    return this.#audit
  }

  /** Live capabilities, excluding expired and revoked ones. */
  active(): Capability[] {
    const now = this.#now().getTime()
    return [...this.#capabilities.values()].filter(
      (c) => !c.revoked && new Date(c.expiresAt).getTime() > now,
    )
  }

  /**
   * Record an arbitrary event.
   *
   * Exposed so the daemon can log lifecycle things (vault reloaded, daemon started) that
   * are not authorisation decisions but must still land in the chain.
   */
  record(input: AuditEventInput): string {
    return this.#audit.append(input, this.#now()).id
  }

  /**
   * Create a grant.
   *
   * Validates first: a malformed request must not reach the audit log as a granted
   * permission, and must not leave a partial capability behind.
   */
  grant(request: GrantRequest): Capability {
    const eventId = this.#audit.append(
      {
        kind: 'grant.requested',
        severity: 'notice',
        clientId: request.clientId,
        service: request.service,
        capabilityId: null,
        detail: {
          operations: request.operations,
          projectPath: request.projectPath,
          ttlMinutes: request.ttlMinutes,
        },
      },
      this.#now(),
    ).id

    let capability: Capability
    try {
      capability = mintCapability({ ...request, auditHead: this.#audit.head }, this.#now())
    } catch (error) {
      this.#audit.append(
        {
          kind: 'grant.rejected',
          severity: 'warning',
          clientId: request.clientId,
          service: request.service,
          decision: 'denied',
          reason: error instanceof Error ? error.constructor.name : 'invalid',
          detail: { requested: request.operations, message: error instanceof Error ? error.message : '' },
        },
        this.#now(),
      )
      throw error
    }

    this.#capabilities.set(capability.id, capability)

    this.#audit.append(
      {
        kind: 'grant.minted',
        severity: 'notice',
        clientId: capability.clientId,
        service: capability.service,
        capabilityId: capability.id,
        decision: 'allowed',
        detail: {
          account: capability.accountAlias,
          operations: capability.operations,
          tier: capability.tier,
          projectPath: capability.projectPath,
          expiresAt: capability.expiresAt,
          request: eventId,
        },
      },
      this.#now(),
    )

    return capability
  }

  /**
   * Revoke a grant immediately.
   *
   * Takes effect for the next request regardless of TTL, which is the point: revocation
   * must not wait for a capability to lapse on its own.
   */
  revoke(capabilityId: string, reason = 'user-requested'): boolean {
    const existing = this.#capabilities.get(capabilityId)
    if (existing === undefined) return false

    const revoked: Capability = Object.freeze({ ...existing, revoked: true })
    this.#capabilities.set(capabilityId, revoked)

    this.#audit.append(
      {
        kind: 'grant.revoked',
        severity: 'warning',
        clientId: existing.clientId,
        service: existing.service,
        capabilityId,
        decision: 'allowed',
        detail: { reason },
      },
      this.#now(),
    )
    return true
  }

  /** Revoke every grant for one client. The blunt instrument. */
  revokeClient(clientId: string, reason = 'client-revoked'): number {
    let count = 0
    for (const [id, capability] of this.#capabilities) {
      if (capability.clientId !== clientId || capability.revoked) continue
      this.revoke(id, reason)
      count += 1
    }
    return count
  }

  /**
   * Record an interactive approval for a sensitive operation.
   *
   * In v0 the approval arrives from the broker's own channel — a CLI prompt, or a macOS
   * notification acknowledgement. It is never taken from model-generated text, which is
   * why this is not exposed as an MCP tool.
   */
  approve(input: {
    clientId: string
    service: string
    accountAlias: string
    operation: Operation
    projectPath: string
  }): FreshApproval {
    assertKnownOperation(input.operation)
    const now = this.#now()

    const approval: FreshApproval = Object.freeze({
      id: `apr_${now.getTime().toString(36)}_${input.operation.replaceAll('.', '-')}`,
      clientId: input.clientId,
      service: input.service,
      accountAlias: input.accountAlias,
      operation: input.operation,
      projectPath: input.projectPath,
      approvedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + APPROVAL_WINDOW_MS).toISOString(),
      consumed: false,
    })

    this.#approvals.set(approval.id, approval)

    this.#audit.append(
      {
        kind: 'approval.granted',
        severity: 'notice',
        clientId: approval.clientId,
        service: approval.service,
        operation: approval.operation,
        decision: 'allowed',
        detail: {
          approvalId: approval.id,
          projectPath: approval.projectPath,
          expiresAt: approval.expiresAt,
        },
      },
      this.#now(),
    )

    return approval
  }

  /**
   * Consume a fresh approval.
   *
   * Single-use: consumed immediately on redemption, whether or not the subsequent request
   * succeeds. An approval that could be reused after a failure would be a retry loop with
   * extra steps.
   */
  #consumeApproval(request: RequestContext, service: string, accountAlias: string): boolean {
    const now = this.#now()

    for (const [id, approval] of this.#approvals) {
      if (approval.consumed) continue
      if (approval.clientId !== request.clientId) continue
      if (approval.service !== service) continue
      if (approval.accountAlias !== accountAlias) continue
      if (approval.operation !== request.operation) continue
      if (approval.projectPath !== request.projectPath) continue
      if (new Date(approval.expiresAt).getTime() <= now.getTime()) {
        this.#approvals.delete(id)
        continue
      }

      this.#approvals.set(id, Object.freeze({ ...approval, consumed: true }))
      return true
    }
    return false
  }

  /**
   * Authorise one request, and record the decision.
   *
   * Order matters: identity, then grant, then freshness. Checking the cheapest, most
   * selective conditions first means a request from the wrong client never reaches the
   * more expensive paths.
   */
  authorise(
    request: RequestContext & { readonly capabilityId: string; readonly service: string; readonly accountAlias: string },
  ): Authorisation {
    const now = request.now ?? this.#now()

    const deny = (reason: DenyReason, message: string): Authorisation => {
      const event = this.#audit.append(
        {
          kind: 'request.denied',
          severity: 'warning',
          clientId: request.clientId,
          service: request.service,
          operation: request.operation,
          decision: 'denied',
          reason,
          capabilityId: request.capabilityId,
          detail: { message, projectPath: request.projectPath },
        },
        now,
      )
      return { allowed: false, reason, message, auditEventId: event.id }
    }

    const capability = this.#capabilities.get(request.capabilityId)
    if (capability === undefined) {
      return deny('revoked', 'no such grant')
    }

    // Replay guard before anything else consumes state.
    if (this.#usedNonces.has(capability.nonce)) {
      return deny('nonce-replayed', 'this grant has already been used')
    }

    // Credentials may be optional: read-only broker surfaces need no account.
    if (
      request.service !== capability.service ||
      request.accountAlias !== capability.accountAlias
    ) {
      return deny('operation-not-granted', 'this grant is for a different account')
    }

    const verdict = check(capability, { ...request, now })

    // A fresh approval can rescue a request that the cached grant cannot authorise.
    if (!verdict.ok && verdict.reason === 'requires-fresh-approval') {
      const approved = this.#consumeApproval(request, request.service, request.accountAlias)
      if (!approved) return deny(verdict.reason, verdict.message)

      this.#usedNonces.add(capability.nonce)
      const spent = advance(capability, now)
      this.#capabilities.set(spent.id, spent)

      const event = this.#audit.append(
        {
          kind: 'request.allowed',
          severity: 'notice',
          clientId: request.clientId,
          service: request.service,
          operation: request.operation,
          decision: 'allowed',
          capabilityId: capability.id,
          detail: { projectPath: request.projectPath, viaFreshApproval: true },
        },
        now,
      )
      return { allowed: true, capability: spent, auditEventId: event.id }
    }

    if (!verdict.ok) return deny(verdict.reason, verdict.message)

    this.#usedNonces.add(capability.nonce)
    const spent = advance(capability, now)
    this.#capabilities.set(spent.id, spent)

    const event = this.#audit.append(
      {
        kind: 'request.allowed',
        severity: 'info',
        clientId: request.clientId,
        service: request.service,
        operation: request.operation,
        decision: 'allowed',
        capabilityId: capability.id,
        detail: { projectPath: request.projectPath, requestCount: spent.requestCount },
      },
      now,
    )

    return { allowed: true, capability: spent, auditEventId: event.id }
  }

  /** Nonce check exposed for callers verifying a frame before authorising it. */
  verifyNonce(capabilityId: string, nonce: string): boolean {
    const capability = this.#capabilities.get(capabilityId)
    if (capability === undefined) return false
    return nonceMatches(capability, nonce)
  }

  /** Render a grant for a human. Never includes credential material. */
  describe(capabilityId: string): string | undefined {
    const capability = this.#capabilities.get(capabilityId)
    return capability === undefined ? undefined : describeCapability(capability)
  }

  /**
   * Anomaly signals for I8's containment response.
   *
   * Returns the clients whose recent denial rate looks like probing rather than a typo.
   */
  suspectClients(threshold = 5): string[] {
    return [...this.#audit.denialCounts().entries()]
      .filter(([, count]) => count >= threshold)
      .map(([client]) => client)
      .sort()
  }
}