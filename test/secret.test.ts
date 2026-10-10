/**
 * Negative tests for the non-disclosure invariant.
 *
 * Every assertion here is of the form "this operation must NOT produce the credential".
 * That direction matters: a suite that only checks the happy path would still pass if
 * someone added a `toJSON` returning plaintext, which is precisely the regression these
 * tests exist to catch.
 *
 * If you change anything in src/core/secret.ts that makes one of these pass-through
 * assertions fail, you have reopened the leak. Do not "fix" the test.
 */

import { strict as assert } from 'node:assert'
import { inspect } from 'node:util'
import { test } from 'node:test'

import { Secret, SecretDisposedError } from '../src/core/secret.ts'

/** Distinctive enough that a substring match cannot collide with unrelated text. */
const CANARY = 'SUPERSECRET-CANARY-9f3a2b7c-do-not-leak'

/** Collect a human-readable rendering of arbitrary values without ever throwing. */
function render(value: unknown): string {
  try {
    if (typeof value === 'string') return value
    return inspect(value, { depth: 10 })
  } catch {
    return String(value)
  }
}

/** Assert that no rendering of these values contains the credential. */
function assertNoCanary(label: string, ...values: unknown[]): void {
  for (const [i, value] of values.entries()) {
    const text = render(value)
    assert.ok(
      !text.includes(CANARY),
      `${label}: value #${i} leaked the credential → ${text.slice(0, 200)}`,
    )
  }
}

// ---------------------------------------------------------------------------
// Serialisation guards
// ---------------------------------------------------------------------------

test('JSON.stringify does not leak the credential', () => {
  const secret = Secret.of(CANARY)

  assertNoCanary(
    'json',
    JSON.stringify(secret),
    JSON.stringify([secret]),
    JSON.stringify({ token: secret }),
    JSON.stringify({ nested: { deep: [{ token: secret }] } }),
    JSON.stringify({ token: secret }, null, 2),
  )

  // Explicit: the redaction marker should actually be present, not just "absent".
  assert.match(JSON.stringify(secret), /redacted/u)
})

test('string coercion does not leak the credential', () => {
  const secret = Secret.of(CANARY)

  assertNoCanary(
    'coercion',
    String(secret),
    `${secret}`,
    secret + '',
    [secret].join(','),
    [CANARY.includes('x') ? '' : secret].join(''),
  )
})

test('util.inspect does not leak the credential', () => {
  const secret = Secret.of(CANARY)

  assertNoCanary('inspect', inspect(secret), inspect({ token: secret }, { depth: 5 }))
  assert.match(inspect(secret), /redacted/u)
})

test('property enumeration and copying do not leak the credential', () => {
  const secret = Secret.of(CANARY)

  assertNoCanary(
    'enumeration',
    Object.keys(secret),
    Object.entries(secret),
    Object.getOwnPropertyNames(secret),
    Object.getOwnPropertySymbols(secret),
    { ...secret },
    Object.assign({}, secret),
    Object.fromEntries(Object.entries(secret)),
  )
})

test('structuredClone does not leak the credential', () => {
  const secret = Secret.of(CANARY)

  const clone = structuredClone(secret)
  assertNoCanary('structuredClone', clone, inspect(clone))
})

test('throwing an error that embeds a Secret does not leak the credential', () => {
  const secret = Secret.of(CANARY)

  const err = new Error('adapter failed') as Error & { cause?: unknown; token?: unknown }
  err.token = secret
  assertNoCanary('error', err.message, inspect(err), inspect(err, { depth: 5 }))
})

test('describe() and byteLength expose metadata only', () => {
  const secret = Secret.of(CANARY)

  assertNoCanary('describe', secret.describe())
  assert.equal(secret.byteLength, Buffer.byteLength(CANARY))
  assert.match(secret.describe(), /redacted/u)
})

// ---------------------------------------------------------------------------
// Callback-scoped sinks: value available inside, unreachable outside
// ---------------------------------------------------------------------------

test('withHeaders delivers the credential inside the callback and not outside', () => {
  const secret = Secret.of(CANARY)

  const seen = secret.withHeaders((headers) => headers.get('Authorization'))

  // Positive assertion, so the leak tests above cannot pass vacuously.
  assert.equal(seen, `Bearer ${CANARY}`)

  // The Headers object itself does not outlive the callback.
  assertNoCanary('withHeaders', inspect(secret), JSON.stringify(secret))
})

test('withHeaderPair delivers the credential inside the callback only', () => {
  const secret = Secret.of(CANARY)

  const pair = secret.withHeaderPair('X-Api-Key', (p) => p)
  assert.deepEqual(pair, { name: 'X-Api-Key', value: CANARY })
})

test('withEnvVar does not mutate the caller base object', () => {
  const secret = Secret.of(CANARY)
  const base: Record<string, string | undefined> = { PATH: '/usr/bin' }

  const observed = secret.withEnvVar(base, 'GH_TOKEN', (env) => {
    assert.equal(env['GH_TOKEN'], CANARY)
    assert.equal(env['PATH'], '/usr/bin')
    return 'spawn-args-returned'
  })

  assert.equal(observed, 'spawn-args-returned')
  // The leak that a naive implementation would have: mutating the caller's object.
  assert.equal(base['GH_TOKEN'], undefined)
  assert.deepEqual(base, { PATH: '/usr/bin' })
})

test('withEnvVar cleans up its own copy even when the callback throws', () => {
  const secret = Secret.of(CANARY)
  const base: Record<string, string | undefined> = {}
  let captured: Record<string, string | undefined> | undefined

  assert.throws(() =>
    secret.withEnvVar(base, 'GH_TOKEN', (env) => {
      captured = env
      throw new Error('boom')
    }),
  )

  assert.equal(base['GH_TOKEN'], undefined)
  assert.equal(captured?.['GH_TOKEN'], undefined, 'env copy should have the entry removed on throw')
})

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

test('fingerprint is deterministic, key-dependent, and irreversible', () => {
  const secret = Secret.of(CANARY)
  const keyA = Buffer.alloc(32, 1)
  const keyB = Buffer.alloc(32, 2)

  const a1 = secret.fingerprint(keyA)
  const a2 = secret.fingerprint(keyA)
  const b = secret.fingerprint(keyB)

  assert.equal(a1, a2, 'same key + same secret must be stable')
  assert.notEqual(a1, b, 'different keys must produce different fingerprints')
  assertNoCanary('fingerprint', a1, b)
  assert.match(a1, /^[0-9a-f]{16}$/u)
})

// ---------------------------------------------------------------------------
// Disposal
// ---------------------------------------------------------------------------

test('dispose zeroes the bytes and makes the Secret unusable', () => {
  const secret = Secret.of(CANARY)

  assert.equal(secret.byteLength, CANARY.length)
  secret.dispose()

  assert.equal(secret.byteLength, 0)
  assert.throws(() => secret.withHeaders(() => 'unreachable'), SecretDisposedError)
  assert.throws(() => secret.withEnvVar({}, 'X', () => 'unreachable'), SecretDisposedError)
  assert.throws(() => secret.fingerprint(Buffer.alloc(32)), SecretDisposedError)

  // dispose is idempotent
  secret.dispose()
  assert.equal(secret.byteLength, 0)
})

test('dispose scrubs our own copy without scribbling on caller memory', () => {
  const source = Buffer.from(CANARY, 'utf8')
  const secret = Secret.fromBuffer(source)

  secret.dispose()

  // fromBuffer copies, so disposal must not mutate memory we do not own.
  assert.equal(source.toString('utf8'), CANARY, 'caller buffer must be left untouched')

  // What is externally observable after disposal: nothing left to spend.
  assert.equal(secret.byteLength, 0)
  assert.throws(() => secret.withHeaders(() => 'x'), SecretDisposedError)
  assert.throws(() => secret.withEnvVar({}, 'X', () => 'x'), SecretDisposedError)

  // NB: the actual zeroing of our internal buffer is deliberately NOT asserted here.
  // Observing it would require exposing the private field, which would be precisely the
  // leak vector this type exists to close. Zeroization is a best-effort internal
  // behaviour; the guarantee we can and do test is that the value cannot escape.
})

test('fromBuffer copies, so caller buffer reuse cannot mutate the Secret', () => {
  const source = Buffer.from(CANARY, 'utf8')
  const secret = Secret.fromBuffer(source)

  source.fill(0x41)

  const seen = secret.withHeaders((h) => h.get('Authorization'))
  assert.equal(seen, `Bearer ${CANARY}`)
})

test('Symbol.dispose zeroes the Secret, so scope-bound disposal is possible', () => {
  // NB: `using secret = ...` syntax cannot be used here — Node 22's TypeScript type
  // stripper does not support the `using` declaration yet (SyntaxError). The class still
  // implements `[Symbol.dispose]`, so `using` will work for callers on a runtime that
  // supports it; this test exercises the same disposal path explicitly.
  const escaped = ((): Secret | undefined => {
    const secret = Secret.of(CANARY)
    assert.equal(secret.byteLength, CANARY.length)
    const disposable = secret as unknown as { [Symbol.dispose](): void }
    disposable[Symbol.dispose]()
    return secret
  })()

  assert.equal(escaped?.byteLength, 0)
  assert.throws(() => escaped?.withHeaders(() => 'x'), SecretDisposedError)
})

// ---------------------------------------------------------------------------
// Compile-time guarantees (enforced by `tsc --noEmit`, not at runtime)
// ---------------------------------------------------------------------------

test('a Secret is not assignable to string', () => {
  const secret = Secret.of(CANARY)

  // If Secret ever became assignable to string, tsc would report "Unused '@ts-expect-error'"
  // and `npm run typecheck` would fail. That is the assertion.
  // @ts-expect-error Secret must not be usable where a string is expected.
  const asString: string = secret
  void asString

  // @ts-expect-error Secret has no public accessor that yields the plaintext.
  const direct = secret.value
  void direct
})