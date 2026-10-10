/**
 * Tamper-evident audit log.
 *
 * A hash-linked chain: each record commits to the previous record's hash, so altering or
 * removing any historical entry invalidates every hash after it. A tamperer who can write
 * the file can also recompute the whole chain, so this is **not** a signature and does not
 * claim to be — it detects accidental corruption, partial writes and naive edits, and it
 * gives I8's checkpoint signing something to anchor to.
 *
 * ## What is never recorded
 *
 * The log deliberately has no field for a secret, and no API that accepts one. Concretely
 * this means:
 *
 *   - no credential values, in any encoding;
 *   - no Authorization headers or cookies;
 *   - no full request or response bodies;
 *   - no model prompts or tool results.
 *
 * `AuditEvent` is a closed set of fields, and `sanitiseDetail` runs every free-form value
 * through the credential redactor before it is stored. Adding a field to an event is a
 * code review event, not a runtime possibility.
 */

import { createHash, randomUUID } from 'node:crypto'
import { appendFileSync, existsSync, readFileSync } from 'node:fs'

import { redact } from './logging.ts'

/** Genesis link. Using the empty string makes "previous hash" uniformly a string. */
export const GENESIS_HASH = ''

/** Severity of an audit event. */
export type AuditSeverity = 'info' | 'notice' | 'warning' | 'critical'

/**
 * Closed set of event fields.
 *
 * Every field is non-secret by construction. There is intentionally no `detail: unknown`
 * catch-all on the type itself — free-form detail goes through {@link AuditEventInput}'s
 * `detail` field, which is sanitised and stringified.
 */
export interface AuditEvent {
  /** Monotonic sequence number, starting at 1. */
  readonly seq: number
  /** Event id. Unique, but the chain does not depend on it. */
  readonly id: string
  /** ISO-8601 timestamp. */
  readonly at: string
  /** What happened, e.g. `grant.minted`, `request.denied`, `vault.reloaded`. */
  readonly kind: string
  readonly severity: AuditSeverity
  readonly clientId: string | null
  readonly service: string | null
  readonly operation: string | null
  /** Coarse outcome: `allowed`, `denied`, `error`. Never a free-form verdict. */
  readonly decision: string | null
  /** Deny reason, when the event is a denial. */
  readonly reason: string | null
  readonly capabilityId: string | null
  /** Sanitised, redacted free-form detail. Never a credential. */
  readonly detail: string | null
  /** Hash of the previous record. Empty for the first. */
  readonly prevHash: string
  /** Hash of this record, chaining to the next. */
  readonly hash: string
}

export interface AuditEventInput {
  readonly kind: string
  readonly severity?: AuditSeverity
  readonly clientId?: string | null
  readonly service?: string | null
  readonly operation?: string | null
  readonly decision?: string | null
  readonly reason?: string | null
  readonly capabilityId?: string | null
  /** Free-form detail. Redacted and length-capped before storage. */
  readonly detail?: unknown
}

export class AuditChainError extends Error {}

/** Cap on stored detail, so a log entry cannot be used to smuggle a large payload. */
export const MAX_DETAIL_LENGTH = 512

/**
 * Sanitise a free-form detail value.
 *
 * Redacts credential-shaped substrings and truncates. Anything that is not a string is
 * rendered via its own `toString`, which for a `Secret` yields the redacted description —
 * so even an accidental `detail: someSecret` cannot store the value.
 */
/**
 * Sanitise a single identifier field.
 *
 * Applies the same credential redaction as `sanitiseDetail` but keeps the value intact
 * otherwise, so legitimate identifiers stay greppable. Length-capped for the same reason.
 */
export function sanitiseField(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null

  const redacted = redact(value)
  return redacted.length > MAX_DETAIL_LENGTH
    ? `${redacted.slice(0, MAX_DETAIL_LENGTH)}…[truncated]`
    : redacted
}

export function sanitiseDetail(detail: unknown): string | null {
  if (detail === undefined || detail === null) return null

  let text: string
  if (typeof detail === 'string') {
    text = detail
  } else if (typeof detail === 'object') {
    // JSON, not String(): `String({})` is "[object Object]", which makes the log useless
    // for the one job it has. A `Secret` nested in here still serialises to its redacted
    // description via its own `toJSON`.
    try {
      text = JSON.stringify(detail) ?? String(detail)
    } catch {
      return '[unserialisable]'
    }
  } else {
    text = String(detail)
  }

  const redacted = redact(text)
  return redacted.length > MAX_DETAIL_LENGTH
    ? `${redacted.slice(0, MAX_DETAIL_LENGTH)}…[truncated]`
    : redacted
}

/**
 * Canonical serialisation for hashing.
 *
 * Field order is fixed and separators are explicit, so the same logical event always
 * hashes identically. The separator is the ASCII unit separator (0x1F), which cannot
 * appear in any of these fields: dates are ISO-8601, kinds and reasons are identifiers, and
 * `detail` is redacted text.
 *
 * An empty separator would be ambiguous -- `["ab", "c"]` and `["a", "bc"]` would produce
 * the same string and therefore the same hash, which is precisely the kind of collision
 * that lets a tampered field slip past verification.
 *
 * `JSON.stringify` is not used here because key order in an object literal is an
 * implementation detail rather than a contract.
 */
const FIELD_SEPARATOR = '\u001f'

function canonicalise(event: Omit<AuditEvent, 'hash'>): string {
  return [
    event.seq,
    event.id,
    event.at,
    event.kind,
    event.severity,
    event.clientId ?? '',
    event.service ?? '',
    event.operation ?? '',
    event.decision ?? '',
    event.reason ?? '',
    event.capabilityId ?? '',
    event.detail ?? '',
    event.prevHash,
  ].join(FIELD_SEPARATOR)
}

export function hashEvent(event: Omit<AuditEvent, 'hash'>): string {
  return createHash('sha256').update(canonicalise(event), 'utf8').digest('hex')
}

/**
 * Append-only audit log over a hash chain.
 *
 * In-memory with append-through to a newline-delimited JSON file. Append-only is enforced
 * by the API — there is no update or delete — but the file itself is not made immutable
 * at the filesystem level, so a process with write access *can* rewrite history. Detecting
 * that requires {@link verifyChain} to fail, or (v0.2) a signed checkpoint.
 */
export class AuditLog {
  readonly #path: string | undefined
  readonly #events: AuditEvent[] = []
  #head: string = GENESIS_HASH

  constructor(path?: string) {
    this.#path = path
  }

  /** Load an existing chain, verifying its integrity as it goes. */
  static open(path?: string): AuditLog {
    const log = new AuditLog(path)
    if (path !== undefined && existsSync(path)) {
      log.#load(path)
    }
    return log
  }

  #load(path: string): void {
    const lines = readFileSync(path, 'utf8').split('\n').filter((line) => line.trim() !== '')
    const parsed = lines.map((line) => JSON.parse(line) as AuditEvent)

    const verdict = verifyChain(parsed)
    if (!verdict.ok) {
      throw new AuditChainError(
        `audit log at ${path} failed verification: ${verdict.message}. ` +
          `Treat this as tampering until proven otherwise; do not silently truncate.`,
      )
    }

    this.#events.push(...parsed)
    this.#head = parsed.at(-1)?.hash ?? GENESIS_HASH
  }

  get length(): number {
    return this.#events.length
  }

  /** Hash of the newest record, or the genesis value when empty. */
  get head(): string {
    return this.#head
  }

  /**
   * Append an event and advance the chain.
   *
   * Returns the stored event so a caller can reference its hash — a grant minted here is
   * anchored to this exact point in history.
   */
  append(input: AuditEventInput, now: Date = new Date()): AuditEvent {
    // Every string field is redacted, not just `detail`. A caller who passes a token as
    // `service` or `clientId` would otherwise write it straight into a file that is meant
    // to be safe to read. Redaction is cheap and the failure mode it prevents is silent.
    const base: Omit<AuditEvent, 'hash'> = {
      seq: this.#events.length + 1,
      id: randomUUID(),
      at: now.toISOString(),
      kind: redact(input.kind),
      severity: input.severity ?? 'info',
      clientId: sanitiseField(input.clientId),
      service: sanitiseField(input.service),
      operation: sanitiseField(input.operation),
      decision: sanitiseField(input.decision),
      reason: sanitiseField(input.reason),
      capabilityId: sanitiseField(input.capabilityId),
      detail: sanitiseDetail(input.detail),
      prevHash: this.#head,
    }

    const event: AuditEvent = { ...base, hash: hashEvent(base) }

    this.#events.push(event)
    this.#head = event.hash

    if (this.#path !== undefined) {
      // One line per record so a partial write can only ever truncate the tail, and so the
      // chain can be verified without parsing a JSON array.
      appendFileSync(this.#path, `${JSON.stringify(event)}\n`, { mode: 0o600 })
    }

    return event
  }

  /** Read the chain. Returns the internal array; treat callers as read-only. */
  all(): readonly AuditEvent[] {
    return [...this.#events]
  }

  /** Most recent `count` events, newest first. */
  recent(count: number): AuditEvent[] {
    return this.#events.slice(-Math.max(0, count)).reverse()
  }

  /** Events of one kind. Useful for "what did this client ask for". */
  byKind(kind: string): AuditEvent[] {
    return this.#events.filter((event) => event.kind === kind)
  }

  /**
   * Events attributable to one client.
   *
   * This backs the per-client audit view, which is what a harness may read. It is scoped
   * to the client by construction so one harness cannot read another's history.
   */
  byClient(clientId: string): AuditEvent[] {
    return this.#events.filter((event) => event.clientId === clientId)
  }

  /**
   * Count denials per client.
   *
   * Feeds the anomaly response in I8: a burst of denials is what a probing client looks
   * like.
   */
  denialCounts(): Map<string, number> {
    const counts = new Map<string, number>()
    for (const event of this.#events) {
      if (event.decision !== 'denied' || event.clientId === null) continue
      counts.set(event.clientId, (counts.get(event.clientId) ?? 0) + 1)
    }
    return counts
  }
}

export interface VerificationVerdict {
  readonly ok: boolean
  readonly message: string
  /** Sequence number of the first record that failed, when ok is false. */
  readonly brokenAtSeq: number | null
}

/**
 * Verify a chain end to end.
 *
 * Checks, in order: monotonic sequence from 1, each `prevHash` equal to the previous
 * record's `hash`, and each record's own hash recomputed from its fields. Recomputing is
 * what catches an edit that leaves the hashes alone — changing `detail` or `decision`
 * without updating `hash`.
 */
export function verifyChain(events: readonly AuditEvent[]): VerificationVerdict {
  let previous = GENESIS_HASH

  for (const [index, event] of events.entries()) {
    const expectedSeq = index + 1

    if (event.seq !== expectedSeq) {
      return {
        ok: false,
        message: `sequence gap: expected ${String(expectedSeq)}, found ${String(event.seq)}`,
        brokenAtSeq: event.seq,
      }
    }

    if (event.prevHash !== previous) {
      return {
        ok: false,
        message: `broken link at seq ${String(event.seq)}: prevHash does not match the previous record`,
        brokenAtSeq: event.seq,
      }
    }

    const { hash, ...rest } = event
    if (hashEvent(rest) !== hash) {
      return {
        ok: false,
        message: `record ${String(event.seq)} was modified: its contents do not match its hash`,
        brokenAtSeq: event.seq,
      }
    }

    previous = hash
  }

  return { ok: true, message: `chain verified across ${String(events.length)} record(s)`, brokenAtSeq: null }
}

/** Verify a persisted newline-delimited log file. */
export function verifyChainFile(path: string): VerificationVerdict {
  const lines = readFileSync(path, 'utf8').split('\n').filter((line) => line.trim() !== '')
  const events = lines.map((line) => JSON.parse(line) as AuditEvent)
  return verifyChain(events)
}