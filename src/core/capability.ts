/**
 * Capabilities: the unit of authorisation.
 *
 * A capability is a short-lived, narrowly scoped permission to perform a named set of
 * operations against one account, from one client, in one project, until a stated time.
 * Everything in the type exists to make a grant hard to widen by accident:
 *
 *   - `service` + `accountAlias` — one credential, not "any credential".
 *   - `operations`               — an explicit list. There is no wildcard; a capability
 *                                  carrying `'*'` is rejected at construction, because a
 *                                  wildcard is the shape every privilege-escalation bug
 *                                  eventually takes.
 *   - `projectPath`              — bound to a directory, so a grant for ~/src/acme does
 *                                  not apply in ~/src/other.
 *   - `expiresAt`                — minutes to hours, never days. Staleness is the main
 *                                  way a permission outlives its justification.
 *   - `maxRequests` / `requestCount` / `minIntervalMs` — bounds on volume and rate.
 *   - `nonce`                    — one-time redemption token, so a replayed frame does not
 *                                  spend the same permission twice.
 *
 * The invariant that matters: **a capability is only ever obtained through the policy
 * engine, and only ever spent through `redeem`.** There is no method that widens one, and
 * no field a caller can mutate after minting.
 */

import { randomUUID, timingSafeEqual } from 'node:crypto'

import {
  assertKnownOperation,
  requiresFreshApproval,
  type Operation,
  type Tier,
  tierOf,
} from './operations.ts'

/** Deny reasons, deliberately specific: the approval UI needs to explain refusals. */
export type DenyReason =
  | 'unknown-operation'
  | 'operation-not-granted'
  | 'requires-fresh-approval'
  | 'expired'
  | 'exhausted'
  | 'rate-limited'
  | 'project-mismatch'
  | 'client-mismatch'
  | 'nonce-replayed'
  | 'revoked'

export class CapabilityError extends Error {
  readonly reason: DenyReason

  constructor(reason: DenyReason, message: string) {
    super(message)
    this.reason = reason
  }
}

/**
 * What a request looks like when checked against a capability.
 *
 * `clientId` is a claim, not proof. In v0 the shim states who it is; I4 verifies it
 * against the client's code signature. Recorded honestly rather than assumed.
 */
export interface RequestContext {
  readonly clientId: string
  readonly projectPath: string
  readonly operation: Operation
  readonly now?: Date
}

export interface GrantRequest {
  readonly clientId: string
  readonly service: string
  readonly accountAlias: string
  readonly operations: readonly Operation[]
  /** Directory the grant is bound to. Compared by realpath in production. */
  readonly projectPath: string
  /** Lifetime in minutes. Clamped to MAX_TTL_MINUTES. */
  readonly ttlMinutes: number
  readonly maxRequests?: number
  readonly minIntervalMs?: number
  /** Chain-hash of the audit log at mint time, so a grant is anchored to history. */
  readonly auditHead?: string
}

export interface Capability {
  readonly id: string
  readonly clientId: string
  readonly service: string
  readonly accountAlias: string
  readonly operations: readonly Operation[]
  readonly projectPath: string
  readonly issuedAt: string
  readonly expiresAt: string
  readonly maxRequests: number
  readonly requestCount: number
  readonly minIntervalMs: number
  readonly lastUsedAt: string | null
  readonly nonce: string
  readonly revoked: boolean
  readonly auditHead: string | null
  readonly tier: Tier
  /** True when any operation in the grant needs fresh interactive approval. */
  readonly needsFreshApproval: boolean
}

/** Ceiling on grant lifetime. A user asking for a week is asking for a bug. */
export const MAX_TTL_MINUTES = 8 * 60

/** Floor, so a zero or negative TTL cannot create a capability that is born expired. */
export const MIN_TTL_MINUTES = 1

/** Defaults when a grant does not specify. */
export const DEFAULT_MAX_REQUESTS = 50
export const DEFAULT_MIN_INTERVAL_MS = 0

export function clampTtl(minutes: number): number {
  if (!Number.isFinite(minutes)) return MIN_TTL_MINUTES
  return Math.min(Math.max(Math.round(minutes), MIN_TTL_MINUTES), MAX_TTL_MINUTES)
}

/**
 * Validate and normalise a grant request.
 *
 * Rejects rather than sanitises. A grant naming an unknown operation, an empty operation
 * list, or a wildcard is a caller bug, and quietly dropping the offending entry would
 * produce a capability that looks like what was asked for but is not.
 */
export function validateGrant(request: GrantRequest): Readonly<Required<Omit<GrantRequest, 'auditHead'>>> & {
  readonly auditHead: string | null
} {
  if (request.service.trim() === '') throw new CapabilityError('unknown-operation', 'service is required')
  if (request.accountAlias.trim() === '') {
    throw new CapabilityError('unknown-operation', 'accountAlias is required')
  }
  if (request.projectPath.trim() === '') {
    throw new CapabilityError('project-mismatch', 'projectPath is required')
  }
  if (request.operations.length === 0) {
    throw new CapabilityError('unknown-operation', 'a grant must name at least one operation')
  }

  // Widened to string for the wildcard check: `Operation` is a literal union, so comparing
  // it to '*' is a type error that would also mean a wildcard could never be caught if a
  // caller widened the type later.
  for (const raw of request.operations as readonly string[]) {
    if (raw === '*' || raw.includes('*')) {
      throw new CapabilityError(
        'unknown-operation',
        'wildcard operations are not permitted; name the operations explicitly',
      )
    }
    assertKnownOperation(raw)
  }

  // De-duplicate so request accounting is not inflated by a repeated entry.
  const operations = [...new Set(request.operations)].sort()

  return {
    clientId: request.clientId,
    service: request.service,
    accountAlias: request.accountAlias,
    operations,
    projectPath: request.projectPath,
    ttlMinutes: clampTtl(request.ttlMinutes),
    maxRequests: request.maxRequests ?? DEFAULT_MAX_REQUESTS,
    minIntervalMs: request.minIntervalMs ?? DEFAULT_MIN_INTERVAL_MS,
    auditHead: request.auditHead ?? null,
  }
}

/**
 * Mint a capability.
 *
 * The returned object is frozen and every field is `readonly`, so a caller cannot widen a
 * grant after the fact by assignment.
 */
export function mintCapability(request: GrantRequest, now: Date = new Date()): Capability {
  const grant = validateGrant(request)

  const issuedAt = now.toISOString()
  const expiresAt = new Date(now.getTime() + grant.ttlMinutes * 60_000).toISOString()

  const operations = grant.operations as readonly Operation[]
  const tiers = operations.map((op) => tierOf(op))

  const capability: Capability = Object.freeze({
    id: `cap_${randomUUID().replaceAll('-', '')}`,
    clientId: grant.clientId,
    service: grant.service,
    accountAlias: grant.accountAlias,
    operations,
    projectPath: grant.projectPath,
    issuedAt,
    expiresAt,
    maxRequests: grant.maxRequests,
    requestCount: 0,
    minIntervalMs: grant.minIntervalMs,
    lastUsedAt: null,
    nonce: randomUUID(),
    revoked: false,
    auditHead: grant.auditHead,
    // The grant's tier is its most sensitive member. Reporting the weakest would
    // understate the permission in the approval UI.
    tier: (['read', 'write', 'deploy', 'delete', 'billing', 'admin'] as const).reduce(
      (worst, tier) => (tiers.includes(tier) ? tier : worst),
      'read' as Tier,
    ),
    needsFreshApproval: operations.some((op) => requiresFreshApproval(op)),
  })

  return capability
}

export type RedeemResult =
  | { readonly ok: true; readonly spent: Capability }
  | { readonly ok: false; readonly reason: DenyReason; readonly message: string }

/**
 * Check a request against a capability.
 *
 * Pure: it never mutates. `PolicyEngine.spend` is what actually consumes a capability, so
 * that a denied attempt cannot have side effects and a successful one is accounted for in
 * exactly one place.
 *
 * Checks run cheapest-and-most-likely first, so a revoked grant costs nothing to reject.
 */
export function check(capability: Capability, request: RequestContext): RedeemResult {
  const now = request.now ?? new Date()

  if (capability.revoked) {
    return { ok: false, reason: 'revoked', message: 'this grant has been revoked' }
  }

  if (new Date(capability.expiresAt).getTime() <= now.getTime()) {
    return {
      ok: false,
      reason: 'expired',
      message: `this grant expired at ${capability.expiresAt}`,
    }
  }

  if (capability.clientId !== request.clientId) {
    return {
      ok: false,
      reason: 'client-mismatch',
      message: `this grant belongs to ${capability.clientId}`,
    }
  }

  // Compare normalised paths. A trailing slash or a `..` segment must not be a way to
  // satisfy a project binding.
  if (!samePath(capability.projectPath, request.projectPath)) {
    return {
      ok: false,
      reason: 'project-mismatch',
      message: `this grant is bound to ${capability.projectPath}`,
    }
  }

  if (!capability.operations.includes(request.operation)) {
    return {
      ok: false,
      reason: 'operation-not-granted',
      message: `${request.operation} is not in this grant`,
    }
  }

  if (capability.requestCount >= capability.maxRequests) {
    return {
      ok: false,
      reason: 'exhausted',
      message: `this grant has no requests left (${String(capability.maxRequests)} used)`,
    }
  }

  if (
    capability.minIntervalMs > 0 &&
    capability.lastUsedAt !== null &&
    now.getTime() - new Date(capability.lastUsedAt).getTime() < capability.minIntervalMs
  ) {
    return {
      ok: false,
      reason: 'rate-limited',
      message: `this grant allows one request every ${String(capability.minIntervalMs)}ms`,
    }
  }

  // Fresh-approval operations are refused here. The policy engine handles them with a
  // separate one-shot approval path, so a long-lived grant can never authorise them.
  if (requiresFreshApproval(request.operation)) {
    return {
      ok: false,
      reason: 'requires-fresh-approval',
      message: `${request.operation} requires approval at the moment of use`,
    }
  }

  return { ok: true, spent: capability }
}

/**
 * Produce the next state of a capability after a successful check.
 *
 * Returns a new frozen object rather than mutating, so a capability in use by several
 * in-flight requests cannot have its counters corrupted by interleaving.
 */
export function advance(capability: Capability, now: Date = new Date()): Capability {
  return Object.freeze({
    ...capability,
    requestCount: capability.requestCount + 1,
    lastUsedAt: now.toISOString(),
  })
}

/** Compare two nonces in constant time. */
export function nonceMatches(capability: Capability, candidate: string): boolean {
  const a = Buffer.from(capability.nonce, 'utf8')
  const b = Buffer.from(candidate, 'utf8')
  if (a.byteLength !== b.byteLength) return false
  return timingSafeEqual(a, b)
}

/**
 * Normalise a path for comparison.
 *
 * Collapses duplicate separators, strips a trailing slash, and resolves `.`/`..` segments
 * lexically. This is not a security boundary on its own — a symlink can still point
 * elsewhere — which is why the daemon resolves the realpath before comparing. It does
 * close the cheap trick of appending `/..` to defeat a string prefix check.
 */
export function normalisePath(input: string): string {
  const absolute = input.startsWith('/')
  const segments: string[] = []

  for (const segment of input.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      const last = segments.at(-1)
      if (last !== undefined && last !== '..') segments.pop()
      else if (!absolute) segments.push('..')
      continue
    }
    segments.push(segment)
  }

  return (absolute ? '/' : '') + segments.join('/')
}

export function samePath(a: string, b: string): boolean {
  const na = normalisePath(a)
  const nb = normalisePath(b)
  if (na === nb) return true
  const ba = Buffer.from(na, 'utf8')
  const bb = Buffer.from(nb, 'utf8')
  return ba.byteLength === bb.byteLength && timingSafeEqual(ba, bb)
}

/** Render a capability for a human approval prompt. Contains no secret material. */
export function describeCapability(capability: Capability): string {
  const lines = [
    `Client:    ${capability.clientId}`,
    `Account:   ${capability.service}/${capability.accountAlias}`,
    `Project:   ${capability.projectPath}`,
    `Tier:      ${capability.tier}${capability.needsFreshApproval ? ' (some operations need approval each time)' : ''}`,
    `Expires:   ${capability.expiresAt}`,
    `Requests:  ${String(capability.requestCount)}/${String(capability.maxRequests)}`,
    'Operations:',
    ...capability.operations.map((operation) => `  - ${operation} [${tierOf(operation)}]`),
  ]
  return lines.join('\n')
}