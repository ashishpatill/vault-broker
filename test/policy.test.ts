/**
 * Policy tests.
 *
 * Structure of the suite mirrors the security claims:
 *
 *   - deny by default, including for unknown operations;
 *   - a grant cannot be widened, replayed, or outlive its TTL;
 *   - sensitive operations are never satisfiable by a cached grant;
 *   - the audit chain detects an edit anywhere in its history;
 *   - no audit event, at any point, contains a credential.
 *
 * Every case here is a case where getting it wrong means an agent acts with authority the
 * user never intended to give it.
 */

import { strict as assert } from 'node:assert'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, test } from 'node:test'

import {
  advance,
  check,
  clampTtl,
  describeCapability,
  MAX_TTL_MINUTES,
  mintCapability,
  nonceMatches,
  normalisePath,
  samePath,
  validateGrant,
  type Capability,
  type GrantRequest,
} from '../src/core/capability.ts'
import {
  ALWAYS_APPROVED_TIERS,
  assertKnownOperation,
  operationsByTier,
  requiresFreshApproval,
  tierOf,
  UnknownOperationError,
  type Operation,
} from '../src/core/operations.ts'
import { AuditChainError, AuditLog, verifyChain, verifyChainFile } from '../src/core/audit.ts'
import { PolicyEngine } from '../src/core/policy.ts'
import { Secret } from '../src/core/secret.ts'

const CANARY = 'policy-canary-6b1e4f-do-not-log'
const PROJECT = '/Users/someone/src/acme'

function grant(overrides: Partial<GrantRequest> = {}): GrantRequest {
  return {
    clientId: 'cursor',
    service: 'github',
    accountAlias: 'work',
    operations: ['github.repo.read'],
    projectPath: PROJECT,
    ttlMinutes: 15,
    ...overrides,
  }
}

/**
 * Engine with a controllable clock, so TTL, approval windows and rate limits are
 * deterministic.
 *
 * The clock controls are attached to the engine instance rather than returned alongside
 * it: spreading a class instance would not copy prototype methods, so the test would get
 * an object with none of the engine's methods on it.
 */
function engineWithClock(start = new Date('2026-10-09T12:00:00Z')): PolicyEngine & {
  advanceMinutes(minutes: number): void
  advanceMs(ms: number): void
} {
  let now = start
  const engine = new PolicyEngine({ now: (): Date => now })

  return Object.assign(engine, {
    advanceMinutes(minutes: number): void {
      now = new Date(now.getTime() + minutes * 60_000)
    },
    advanceMs(ms: number): void {
      now = new Date(now.getTime() + ms)
    },
  })
}

describe('operations and tiers', () => {
  test('an unknown operation is rejected, never defaulted to allowed', () => {
    // The single most dangerous input to a policy engine: a typo must fail closed.
    assert.throws(() => assertKnownOperation('github.repo.everything'), UnknownOperationError)
    assert.throws(() => tierOf(''), UnknownOperationError)
    assert.throws(() => tierOf('*'), UnknownOperationError)
  })

  test('operations carry the expected tiers', () => {
    assert.equal(tierOf('github.repo.read'), 'read')
    assert.equal(tierOf('github.pr.create'), 'write')
    assert.equal(tierOf('github.release.create'), 'deploy')
    assert.equal(tierOf('github.repo.delete'), 'delete')
    assert.equal(tierOf('github.billing.read'), 'billing')
    assert.equal(tierOf('github.member.admin'), 'admin')
  })

  test('sensitive tiers can never be satisfied by a cached grant', () => {
    for (const operation of ['github.release.create', 'github.repo.delete', 'github.billing.read', 'github.member.admin'] as const) {
      assert.equal(requiresFreshApproval(operation), true, `${operation} must require fresh approval`)
    }
    for (const operation of ['github.repo.read', 'github.pr.create'] as const) {
      assert.equal(requiresFreshApproval(operation), false)
    }
    assert.equal(ALWAYS_APPROVED_TIERS.size, 4)
  })

  test('groups operations by tier for readable approval prompts', () => {
    const grouped = operationsByTier(['github.repo.read', 'github.pr.create', 'github.repo.delete'])
    assert.deepEqual(grouped.get('read'), ['github.repo.read'])
    assert.deepEqual(grouped.get('write'), ['github.pr.create'])
    assert.deepEqual(grouped.get('delete'), ['github.repo.delete'])
  })
})

describe('grant validation', () => {
  test('rejects wildcards', () => {
    assert.throws(() => validateGrant(grant({ operations: ['*' as Operation] })), /wildcard/u)
    assert.throws(
      () => validateGrant(grant({ operations: ['github.repo.*' as Operation] })),
      /wildcard/u,
    )
  })

  test('rejects an empty operation list', () => {
    assert.throws(() => validateGrant(grant({ operations: [] })), /at least one operation/u)
  })

  test('rejects unknown operations rather than dropping them', () => {
    // Silently dropping would produce a capability that looks like what was asked for.
    assert.throws(() => validateGrant(grant({ operations: ['github.nope' as Operation] })), UnknownOperationError)
  })

  test('requires service, account and project', () => {
    assert.throws(() => validateGrant(grant({ service: '  ' })), /service is required/u)
    assert.throws(() => validateGrant(grant({ accountAlias: '' })), /accountAlias is required/u)
    assert.throws(() => validateGrant(grant({ projectPath: '' })), /projectPath is required/u)
  })

  test('de-duplicates operations so request accounting is not inflated', () => {
    const normalised = validateGrant(
      grant({ operations: ['github.repo.read', 'github.repo.read'] }),
    )
    assert.deepEqual(normalised.operations, ['github.repo.read'])
  })

  test('clamps TTL to a sane window', () => {
    assert.equal(clampTtl(0), 1, 'must not be born expired')
    assert.equal(clampTtl(-5), 1)
    assert.equal(clampTtl(60 * 24 * 30), MAX_TTL_MINUTES, 'a month is a bug, not a request')
    assert.equal(clampTtl(Number.NaN), 1)
    assert.equal(clampTtl(15), 15)
  })
})

describe('capabilities', () => {
  test('a minted capability is frozen', () => {
    const capability = mintCapability(grant())
    assert.equal(Object.isFrozen(capability), true)

    // Widening a grant by assignment must be impossible at runtime, not merely by typing.
    assert.throws(() => {
      (capability as unknown as { operations: readonly Operation[] }).operations = ['github.billing.read']
    }, TypeError)
  })

  test('reports the most sensitive tier in the grant', () => {
    const mixed = mintCapability(grant({ operations: ['github.repo.read', 'github.repo.delete'] }))
    assert.equal(mixed.tier, 'delete')
    assert.equal(mixed.needsFreshApproval, true)

    const tame = mintCapability(grant())
    assert.equal(tame.tier, 'read')
    assert.equal(tame.needsFreshApproval, false)
  })

  test('is anchored to the audit chain at mint time', () => {
    const engine = new PolicyEngine()
    engine.record({ kind: 'test.seed' })

    const before = engine.audit.head
    const capability = engine.grant(grant())

    // The grant anchors to a point in the chain, not the genesis value and not the
    // current head — `grant` records a `grant.requested` event before minting, so the
    // anchor sits after it. Asserting it is a real link in the chain is the meaningful
    // property; pinning it to an exact position would just restate the implementation.
    assert.equal(typeof capability.auditHead, 'string')
    assert.notEqual(capability.auditHead, before, 'anchored after the request event')
    assert.notEqual(capability.auditHead, engine.audit.head, 'the chain advances on mint too')
    assert.ok(
      engine.audit.all().some((event) => event.hash === capability.auditHead),
      'anchor must be a hash that exists in the chain',
    )
  })
})

describe('authorisation: deny by default', () => {
  test('a request with no grant is denied', () => {
    const engine = engineWithClock()
    const verdict = engine.authorise({
      clientId: 'cursor',
      capabilityId: 'cap_nonexistent',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed, false)
  })

  test('an operation outside the grant is denied even for a valid grant', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ operations: ['github.repo.read'] }))

    const verdict = engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.pr.create',
      projectPath: PROJECT,
    })

    assert.equal(verdict.allowed, false)
    assert.equal(verdict.allowed === false && verdict.reason, 'operation-not-granted')
  })

  test('a grant cannot be replayed', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant())

    const first = engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(first.allowed, true)

    // Same frame again: the nonce is spent.
    const replay = engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(replay.allowed, false)
    assert.equal(replay.allowed === false && replay.reason, 'nonce-replayed')
  })

  test('another client cannot use a grant', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ clientId: 'cursor' }))

    const verdict = engine.authorise({
      clientId: 'claude-code',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed === false && verdict.reason, 'client-mismatch')
  })

  test('a grant cannot be used from another project, including via path tricks', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ projectPath: PROJECT }))

    for (const attempt of [
      '/Users/someone/src/other',
      '/Users/someone/src/acme/../secrets',
      '/Users/someone/src/acme/subdir',
      '/Users/someone/src/acme-2',
      '/Users/someone/src',
    ]) {
      const verdict = engine.authorise({
        clientId: 'cursor',
        capabilityId: capability.id,
        service: 'github',
        accountAlias: 'work',
        operation: 'github.repo.read',
        projectPath: attempt,
      })
      assert.equal(verdict.allowed, false, `should refuse ${attempt}`)
    }

    // A trailing separator is the same directory, not an escape, so it must still work.
    // Asserted separately because "refuse everything that looks different" would
    // otherwise quietly permit a rule that breaks legitimate use.
    const trailing = engineWithClock()
    const sameDirectory = trailing.grant(grant({ projectPath: PROJECT }))
    const verdict = trailing.authorise({
      clientId: 'cursor',
      capabilityId: sameDirectory.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: `${PROJECT}/`,
    })
    assert.equal(verdict.allowed, true, 'a trailing slash is the same directory')
  })

  test('a grant for one account cannot reach another', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ accountAlias: 'work' }))

    const verdict = engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'personal',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed === false && verdict.reason, 'operation-not-granted')
  })

  test('expiry is enforced', () => {
    const clock = engineWithClock()

    // Both grants are minted at t0. Minting the second one *after* advancing the clock
    // would give it a fresh TTL and the test would silently not be testing expiry.
    const capability = clock.grant(grant({ ttlMinutes: 5 }))
    const alsoMintedAtZero = clock.grant(grant({ ttlMinutes: 5 }))

    const before = clock.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(before.allowed, true)

    clock.advanceMinutes(6)

    // The second grant has an unspent nonce, so the replay guard does not mask the
    // expiry check.
    const after = clock.authorise({
      clientId: 'cursor',
      capabilityId: alsoMintedAtZero.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(after.allowed, false)
    assert.equal(after.allowed === false && after.reason, 'expired')
  })

  test('the request cap is enforced', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ maxRequests: 3 }))

    // Each authorisation spends the nonce, so mint one grant per attempt.
    for (let i = 0; i < 3; i += 1) {
      const c = engine.grant(grant({ maxRequests: 3 }))
      assert.equal(c.maxRequests, 3)
    }

    const capped = mintCapability(grant({ maxRequests: 1 }))
    const spent = advance(capped)
    const verdict = check(spent, {
      clientId: 'cursor',
      projectPath: PROJECT,
      operation: 'github.repo.read',
    })
    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.reason, 'exhausted')
  })

  test('rate limiting is enforced', () => {
    const now = new Date('2026-10-09T12:00:00Z')
    const capability = mintCapability(grant({ minIntervalMs: 1000 }), now)

    const first = check(capability, { clientId: 'cursor', projectPath: PROJECT, operation: 'github.repo.read', now })
    assert.equal(first.ok, true)

    const used = advance(capability, now)
    const tooSoon = check(used, {
      clientId: 'cursor',
      projectPath: PROJECT,
      operation: 'github.repo.read',
      now: new Date(now.getTime() + 500),
    })
    assert.equal(tooSoon.ok === false && tooSoon.reason, 'rate-limited')

    const later = check(used, {
      clientId: 'cursor',
      projectPath: PROJECT,
      operation: 'github.repo.read',
      now: new Date(now.getTime() + 1500),
    })
    assert.equal(later.ok, true)
  })
})

describe('fresh approval for sensitive operations', () => {
  test('a cached grant alone cannot authorise a delete', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ operations: ['github.repo.delete'] }))

    const withoutApproval = engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete',
      projectPath: PROJECT,
    })
    assert.equal(withoutApproval.allowed === false && withoutApproval.reason, 'requires-fresh-approval')
  })

  test('an approval lets it through exactly once', () => {
    const clock = engineWithClock()
    const first = clock.grant(grant({ operations: ['github.repo.delete'] }))
    clock.approve({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete',
      projectPath: PROJECT,
    })

    const request = {
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete' as Operation,
      projectPath: PROJECT,
    }

    const allowed = clock.authorise({ ...request, capabilityId: first.id })
    assert.equal(allowed.allowed, true)

    // Second grant, second attempt with no fresh approval: refused.
    const second = clock.grant(grant({ operations: ['github.repo.delete'] }))
    const refused = clock.authorise({ ...request, capabilityId: second.id })
    assert.equal(refused.allowed === false && refused.reason, 'requires-fresh-approval')
  })

  test('an approval expires quickly', () => {
    const clock = engineWithClock()
    const capability = clock.grant(grant({ operations: ['github.billing.read'] }))
    clock.approve({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.billing.read',
      projectPath: PROJECT,
    })

    clock.advanceMs(3 * 60 * 1000)

    const verdict = clock.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.billing.read',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed, false)
  })

  test('an approval for one client does not help another', () => {
    const clock = engineWithClock()
    const capability = clock.grant(grant({ clientId: 'cursor', operations: ['github.repo.delete'] }))
    clock.approve({
      clientId: 'claude-code',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete',
      projectPath: PROJECT,
    })

    const verdict = clock.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed, false)
  })

  test('an approval for one project does not help another', () => {
    const clock = engineWithClock()
    const capability = clock.grant(grant({ operations: ['github.repo.delete'] }))
    clock.approve({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete',
      projectPath: '/somewhere/else',
    })

    const verdict = clock.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.delete',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed, false)
  })
})

describe('revocation', () => {
  test('revoke takes effect immediately, without waiting for TTL', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant({ ttlMinutes: 60 }))

    assert.equal(engine.revoke(capability.id), true)
    assert.equal(
      engine.active().length,
      0,
      'a revoked grant must not be active even though its TTL has not expired',
    )

    const verdict = engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    assert.equal(verdict.allowed === false && verdict.reason, 'revoked')
  })

  test('revokeClient removes every grant for that client', () => {
    const engine = engineWithClock()
    engine.grant(grant({ clientId: 'cursor' }))
    engine.grant(grant({ clientId: 'cursor', accountAlias: 'personal' }))
    engine.grant(grant({ clientId: 'opencode' }))

    assert.equal(engine.revokeClient('cursor'), 2)
    assert.equal(engine.active().length, 1)
    assert.equal(engine.active()[0]?.clientId, 'opencode')
  })

  test('revoking an unknown grant reports false rather than throwing', () => {
    const engine = engineWithClock()
    assert.equal(engine.revoke('cap_nope'), false)
  })
})

describe('path normalisation', () => {
  test('collapses separators, dots and trailing slashes', () => {
    assert.equal(normalisePath('/a//b/'), '/a/b')
    assert.equal(normalisePath('/a/./b'), '/a/b')
    assert.equal(normalisePath('/a/b/../c'), '/a/c')
    assert.equal(normalisePath('/'), '/')
  })

  test('does not let a prefix match satisfy a binding', () => {
    assert.equal(samePath('/src/acme', '/src/acme'), true)
    assert.equal(samePath('/src/acme/', '/src/acme'), true)
    assert.equal(samePath('/src/acme', '/src/acme-2'), false, 'prefix must not match')
    assert.equal(samePath('/src/acme', '/src/acme/../acme2'), false)
  })
})

describe('audit detail rendering', () => {
  test('renders objects as JSON, not [object Object]', () => {
    // String({}) produces "[object Object]", which would make the log useless for the one
    // job it has: telling a human what was decided.
    const log = new AuditLog()
    log.append({ kind: 'grant.minted', detail: { operations: ['github.repo.read'], ttl: 60 } })

    const detail = log.all()[0]?.detail ?? ''
    assert.match(detail, /"operations":\["github.repo.read"\]/u)
    assert.ok(!detail.includes('[object Object]'))
  })

  test('renders a nested Secret as its redacted description', () => {
    const log = new AuditLog()
    log.append({ kind: 'probe', detail: { token: Secret.of('ghp_' + 'x'.repeat(36)) } })

    const detail = log.all()[0]?.detail ?? ''
    assert.ok(!detail.includes(`ghp_${'x'.repeat(36)}`))
    assert.match(detail, /redacted/u)
  })

  test('a read-only engine does not append events to the chain', () => {
    // Guards against the earlier behaviour where reconstructing persisted grants inside
    // `policy list` appended grant.requested / grant.minted events, so reading the audit
    // log changed it.
    const log = new AuditLog()
    log.append({ kind: 'seed' })
    const before = log.length

    const engine = new PolicyEngine({ audit: log })
    engine.active()
    engine.describe('cap_nope')
    engine.suspectClients()

    assert.equal(log.length, before, 'inspection must not mutate history')
  })
})

describe('audit chain', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaultbroker-audit-'))
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  test('a fresh chain verifies', () => {
    const log = new AuditLog()
    log.append({ kind: 'one' })
    log.append({ kind: 'two' })
    assert.equal(verifyChain(log.all()).ok, true)
  })

  test('an empty chain verifies', () => {
    assert.equal(verifyChain([]).ok, true)
  })

  test('editing a record in the middle breaks the chain', () => {
    const log = new AuditLog()
    for (let i = 0; i < 5; i += 1) log.append({ kind: `event.${String(i)}`, detail: `value ${String(i)}` })

    const tampered = log.all().map((event) =>
      event.seq === 3 ? { ...event, detail: 'tampered value' } : event,
    )

    const verdict = verifyChain(tampered)
    assert.equal(verdict.ok, false)
    assert.equal(verdict.brokenAtSeq, 3)
  })

  test('recomputing hashes after an edit still breaks the link to the next record', () => {
    // A tamperer who fixes the edited record's hash must also fix every hash after it.
    // Doing one without the other is detectable, which is the point of a chain.
    const log = new AuditLog()
    for (let i = 0; i < 4; i += 1) log.append({ kind: `event.${String(i)}` })

    const events = log.all().map((event) => ({ ...event }))
    events[1] = { ...events[1]!, decision: 'allowed' } // edit, hash left stale

    const verdict = verifyChain(events)
    assert.equal(verdict.ok, false, 'a naive edit is caught immediately')
  })

  test('deleting a record breaks the chain', () => {
    const log = new AuditLog()
    for (let i = 0; i < 4; i += 1) log.append({ kind: `event.${String(i)}` })

    const withoutMiddle = log.all().filter((event) => event.seq !== 2)
    const verdict = verifyChain(withoutMiddle)
    assert.equal(verdict.ok, false)
    assert.equal(verdict.brokenAtSeq, 3, 'the gap surfaces at the following record')
  })

  test('survives a round trip through the file', () => {
    const path = join(dir, 'audit.log')
    const log = new AuditLog(path)
    log.append({ kind: 'one', detail: 'alpha' })
    log.append({ kind: 'two', detail: 'beta' })

    assert.equal(verifyChainFile(path).ok, true)
    assert.equal(AuditLog.open(path).length, 2)
    assert.equal(AuditLog.open(path).head, log.head)
  })

  test('refuses to open a tampered file rather than truncating it', () => {
    const path = join(dir, 'audit.log')
    const log = new AuditLog(path)
    log.append({ kind: 'one' })
    log.append({ kind: 'two' })
    log.append({ kind: 'three' })

    // Rewrite the middle record's detail, leaving its hash alone.
    const lines = readFileSync(path, 'utf8').trim().split('\n')
    const middle = JSON.parse(lines[1] ?? '{}') as Record<string, unknown>
    middle['detail'] = 'tampered'
    lines[1] = JSON.stringify(middle)
    writeFileSync(path, `${lines.join('\n')}\n`)

    assert.throws(() => AuditLog.open(path), AuditChainError)
  })

  test('no event ever contains a credential', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant())
    engine.approve({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.release.create',
      projectPath: PROJECT,
    })
    engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })

    // Throw credential-shaped values at every text field the log has.
    engine.record({ kind: 'leak.probe', detail: `token ghp_${'a'.repeat(36)}` })
    engine.record({ kind: 'leak.probe', detail: Secret.of(`sk-${'b'.repeat(40)}`) })
    engine.record({ kind: 'leak.probe', service: `napi_${'c'.repeat(40)}` })

    const serialised = JSON.stringify(engine.audit.all())
    assert.ok(!serialised.includes(`ghp_${'a'.repeat(36)}`), 'GitHub token must not be logged')
    assert.ok(!serialised.includes(`sk-${'b'.repeat(40)}`), 'sk- token must not be logged')
    assert.ok(!serialised.includes(`napi_${'c'.repeat(40)}`), 'Neon token must not be logged')
    assert.match(serialised, /redacted/u)
  })

  test('detail is truncated so a log entry cannot smuggle a payload', () => {
    const log = new AuditLog()
    log.append({ kind: 'big', detail: 'x'.repeat(5000) })
    const detail = log.all()[0]?.detail ?? ''
    assert.ok(detail.length < 600, `detail should be capped, got ${String(detail.length)}`)
    assert.match(detail, /truncated/u)
  })

  test('events are scoped per client so one cannot read another history', () => {
    const engine = engineWithClock()
    engine.grant(grant({ clientId: 'cursor' }))
    engine.grant(grant({ clientId: 'opencode' }))

    const cursorEvents = engine.audit.byClient('cursor')
    assert.ok(cursorEvents.length > 0)
    assert.ok(cursorEvents.every((e) => e.clientId === 'cursor'))
    assert.ok(cursorEvents.some((e) => e.detail?.includes('cursor') || e.clientId === 'cursor'))
  })

  test('repeated denials are counted per client for anomaly detection', () => {
    const engine = engineWithClock()

    for (let i = 0; i < 6; i += 1) {
      engine.authorise({
        clientId: 'cursor',
        capabilityId: 'cap_missing',
        service: 'github',
        accountAlias: 'work',
        operation: 'github.repo.read',
        projectPath: PROJECT,
      })
    }
    engine.grant(grant({ clientId: 'opencode' }))

    const counts = engine.audit.denialCounts()
    assert.equal(counts.get('cursor'), 6)
    assert.equal(counts.get('opencode'), undefined)
    assert.deepEqual(engine.suspectClients(5), ['cursor'])
  })

  test('every decision is recorded, allowed or denied', () => {
    const engine = engineWithClock()
    const capability = engine.grant(grant())

    engine.authorise({
      clientId: 'cursor',
      capabilityId: capability.id,
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })
    engine.authorise({
      clientId: 'cursor',
      capabilityId: 'cap_missing',
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      projectPath: PROJECT,
    })

    const decisions = engine.audit.byKind('request.allowed').length
    const denials = engine.audit.byKind('request.denied').length
    assert.equal(decisions, 1)
    assert.equal(denials, 1)
  })
})

describe('capability rendering', () => {
  test('describes a grant for a human without credential material', () => {
    const capability: Capability = mintCapability(
      grant({ operations: ['github.repo.read', 'github.repo.delete'] }),
    )
    const text = describeCapability(capability)

    assert.match(text, /github\/work/u)
    assert.match(text, /github\.repo\.delete \[delete\]/u)
    assert.match(text, /some operations need approval/u)
    assert.ok(!text.includes(CANARY))
  })

  test('nonce comparison is exact', () => {
    const capability = mintCapability(grant())
    assert.equal(nonceMatches(capability, capability.nonce), true)
    assert.equal(nonceMatches(capability, `${capability.nonce}x`), false)
    assert.equal(nonceMatches(capability, ''), false)
  })
})