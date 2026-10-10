/**
 * Operation identifiers and the tiers they belong to.
 *
 * The tier is the important part. A single flat list of operations would make "read" and
 * "delete" the same kind of thing to grant, and the whole point of a least-privilege
 * broker is that they are not.
 *
 * Tiers, and what each costs to grant:
 *
 *   read     cheap, reversible, grantable for hours
 *   write    changes remote state; hours
 *   deploy   changes production; always requires fresh interactive approval
 *   delete   destroys remote state; always requires fresh interactive approval
 *   billing  touches money; always requires fresh interactive approval
 *   admin    changes permissions or policy; always requires fresh interactive approval
 *
 * The bottom four tiers are never satisfied by a cached grant. There is deliberately no
 * way to pre-approve them, because a grant that survives a week cannot be one the user
 * looked at.
 */

/** Severity ordering, used for sorting and for "is this at least as sensitive as X". */
export const TIER_ORDER = ['read', 'write', 'deploy', 'delete', 'billing', 'admin'] as const

export type Tier = (typeof TIER_ORDER)[number]

/** Tiers that always require a fresh, interactive approval at the moment of use. */
export const ALWAYS_APPROVED_TIERS: ReadonlySet<Tier> = new Set<Tier>([
  'deploy',
  'delete',
  'billing',
  'admin',
])

export function isTier(value: string): value is Tier {
  return (TIER_ORDER as readonly string[]).includes(value)
}

/** Rank of a tier; higher is more sensitive. */
export function tierRank(tier: Tier): number {
  return TIER_ORDER.indexOf(tier)
}

/**
 * Operations the broker understands.
 *
 * Namespaced by service so an adapter can only ever claim operations in its own space,
 * and `assertKnownOperation` rejects anything unrecognised rather than defaulting to
 * allow. An unknown operation is the most dangerous possible input to a policy engine:
 * defaulting it to "allowed" would let a typo widen access.
 */
export const OPERATIONS = {
  // GitHub
  'github.repo.read': 'read',
  'github.repo.list': 'read',
  'github.pr.read': 'read',
  'github.pr.create': 'write',
  'github.issue.read': 'read',
  'github.issue.create': 'write',
  'github.branch.create': 'write',
  'github.release.create': 'deploy',
  'github.repo.delete': 'delete',
  'github.billing.read': 'billing',
  'github.member.admin': 'admin',

  // Neon
  'neon.project.read': 'read',
  'neon.project.list': 'read',
  'neon.branch.list': 'read',
  'neon.query.execute': 'write',
  'neon.branch.delete': 'delete',
  'neon.project.create': 'write',
  'neon.billing.read': 'billing',

  // Meta: the broker's own read-only surfaces.
  'vault.account.list': 'read',
  'broker.status.read': 'read',
} as const satisfies Readonly<Record<string, Tier>>

export type Operation = keyof typeof OPERATIONS

export class UnknownOperationError extends Error {
  /** The unrecognised value, kept for the audit detail. */
  readonly requested: string

  constructor(requested: string) {
    super(`unknown operation: ${requested}`)
    this.requested = requested
  }
}

/**
 * Look up an operation's tier.
 *
 * Throws for anything unrecognised. There is deliberately no "default to read" or
 * "default to allow" branch — see the note on `OPERATIONS`.
 */
export function assertKnownOperation(operation: string): Operation {
  if (!Object.hasOwn(OPERATIONS, operation)) {
    throw new UnknownOperationError(operation)
  }
  return operation as Operation
}

export function tierOf(operation: string): Tier {
  return OPERATIONS[assertKnownOperation(operation)]
}

/** True when this operation can never be satisfied by a cached grant. */
export function requiresFreshApproval(operation: string): boolean {
  return ALWAYS_APPROVED_TIERS.has(tierOf(operation))
}

/** Group operations by tier, for rendering a permission request readably. */
export function operationsByTier(operations: readonly Operation[]): Map<Tier, Operation[]> {
  const grouped = new Map<Tier, Operation[]>()
  for (const operation of operations) {
    const tier = OPERATIONS[operation]
    const bucket = grouped.get(tier)
    if (bucket === undefined) grouped.set(tier, [operation])
    else bucket.push(operation)
  }
  return grouped
}