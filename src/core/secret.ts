/**
 * Secret<T> — the non-disclosure primitive for VaultBroker.
 *
 * The product's central invariant is:
 *
 *   > The model may request an authorized action, but it never receives the
 *   > credential that authorizes that action.
 *
 * This type is where that invariant is made structural rather than aspirational.
 * A `Secret` holds credential material in an ES private field, which means:
 *
 *   - it is not an own enumerable property, so `JSON.stringify`, spread, `Object.keys`,
 *     `Object.assign` and `structuredClone` cannot reach the value;
 *   - it cannot be coerced to a string, number or primitive by any implicit coercion;
 *   - its only public surface is a set of *callback-scoped* escape hatches that hand the
 *     plaintext to a specific sink (an HTTP header set, a child environment) for the
 *     duration of one call and never return it to the caller.
 *
 * Callback scoping is the load-bearing design choice. A method like `reveal(): string`
 * would make every one of those guarantees optional, because a single careless caller
 * re-opens the leak. With `withHeaders(fn)` the plaintext is unreachable outside `fn`
 * by construction: `fn`'s return value is the only thing that escapes.
 *
 * ## Honest limits of this design
 *
 * This type prevents a credential from being *returned*. It cannot prevent one from being
 * *read from memory* by malware running as the same user, and it cannot undo the copies
 * that `Headers` / child-process environments create internally (JavaScript strings are
 * immutable and cannot be zeroized; they are released to the garbage collector eventually).
 * What it does guarantee is that no value ever crosses the MCP boundary, and that
 * `JSON.stringify` / logging / error paths cannot leak it accidentally.
 * See README.md → "What this does not protect against". Do not widen these claims.
 */

import * as crypto from 'node:crypto'
import { inspect } from 'node:util'

/** `util.inspect.custom`, re-exported under a name that is erasable-syntax safe. */
const inspectCustom = inspect.custom

const SECRET_TAG = Symbol('vaultbroker.Secret')

/** Nominal brand so unrelated string-shaped values cannot be passed where a Secret is required. */
export type SecretBrand = typeof SECRET_TAG

/** Thrown when a disposed Secret is used. Disposal is final and irreversible. */
export class SecretDisposedError extends Error {
  override readonly name = 'SecretDisposedError'
  constructor() {
    super('Secret has been disposed and can no longer be used')
  }
}

const REDACTED = '[redacted]'

/**
 * A holder for credential material that can only be spent on a specific sink.
 *
 * Construction goes exclusively through {@link Secret.of}; the constructor is private so
 * that a `Secret` cannot be fabricated from untrusted structural input.
 */
export class Secret<T extends string = string> {
  /**
   * Credential bytes. Stored as a Buffer rather than a string specifically so that
   * {@link dispose} can zero it — strings are immutable and cannot be scrubbed.
   *
   * `#` makes this a true private field: invisible to enumeration, to serialization, to
   * subclassing, and unreachable at runtime even via bracket access.
   */
  #buf: Buffer | null = null

  #disposed = false

  private constructor(buf: Buffer) {
    this.#buf = buf
  }

  /** Nominal brand field. Erases to a plain own property holding `true`. */
  readonly [SECRET_TAG] = true

  /**
   * Wrap a plaintext value. The caller's own string is not zeroizable by us.
   *
   * Declares its own type parameter because static members cannot reference `T`.
   */
  static of<V extends string>(value: string): Secret<V> {
    return new Secret<V>(Buffer.from(value, 'utf8'))
  }

  /**
   * Wrap a value without ever materialising it as a JS string.
   *
   * Use this for values read from files, pipes or keychains so the plaintext exists only
   * as bytes we control and can scrub in {@link dispose}.
   */
  static fromBuffer<V extends string>(value: Buffer): Secret<V> {
    // Copy: the caller may reuse or zero its own buffer.
    return new Secret<V>(Buffer.from(value))
  }

  get #live(): Buffer {
    if (this.#disposed || this.#buf === null) throw new SecretDisposedError()
    return this.#buf
  }

  /** Number of bytes held. Metadata only — safe to log, and not the secret. */
  get byteLength(): number {
    if (this.#disposed || this.#buf === null) return 0
    return this.#buf.byteLength
  }

  /** Safe description for logs, errors and audit records. Contains no credential material. */
  describe(): string {
    return `Secret(${REDACTED}, ${this.byteLength} bytes)`
  }

  /**
   * Spend this secret on an HTTP header set.
   *
   * `fn` receives a `Headers` object carrying the credential. Only `fn`'s return value
   * escapes; the `Headers` instance is discarded when `fn` returns.
   *
   * ```ts
   * const body = await token.withHeaders((headers) =>
   *   fetch(url, { headers }).then((r) => r.json()),
   * )
   * ```
   */
  withHeaders<R>(fn: (headers: Headers) => R): R {
    const headers = new Headers()
    headers.set('Authorization', `Bearer ${this.#live.toString('utf8')}`)
    try {
      return fn(headers)
    } finally {
      headers.delete('Authorization')
    }
  }

  /**
   * Spend this secret on a `name: value` pair without building a `Headers` object.
   * Same escape rules as {@link withHeaders}.
   */
  withHeaderPair<R>(name: string, fn: (pair: { name: string; value: string }) => R): R {
    return fn({ name, value: this.#live.toString('utf8') })
  }

  /**
   * Spend this secret inside a child-process environment.
   *
   * `base` is copied, never mutated, so a caller's environment object is not modified as a
   * side effect and cannot end up holding the value afterwards. Only `fn`'s return value
   * escapes.
   *
   * Note: the child process *will* hold the value in its own environment, where `ps -E`
   * can read it. Prefer broker-side adapters, which keep the credential inside the daemon.
   * See README.md → "Where this design is still weak".
   */
  withEnvVar<R>(
    base: Readonly<Record<string, string | undefined>>,
    name: string,
    fn: (env: Record<string, string | undefined>) => R,
  ): R {
    const env: Record<string, string | undefined> = { ...base, [name]: this.#live.toString('utf8') }
    try {
      return fn(env)
    } finally {
      // Best-effort: drop the copy we own. The string inside `env` is GC-bound, not scrubbed.
      delete env[name]
    }
  }

  /**
   * Spend this secret on raw bytes.
   *
   * Used by the vault's encryption path, which operates on bytes and has no business
   * converting credential material to a string first. The callback receives the live
   * internal buffer: it must not retain it, mutate it, or hand it to anything that
   * outlives the call. Those are contract obligations, not enforced ones — the reason
   * this method is narrower than it looks is that keeping the plaintext inside a short
   * synchronous callback is the only thing that makes it safe.
   */
  withBytes<R>(fn: (bytes: Buffer) => R): R {
    return fn(this.#live)
  }

  /**
   * Derive a non-reversible, key-dependent fingerprint.
   *
   * Lets the audit log record "the credential for github/work was rotated to a new value"
   * without ever storing or displaying either value. Requires a key so an attacker holding
   * the audit log alone cannot brute-force short tokens offline.
   */
  fingerprint(key: Buffer): string {
    return crypto.createHmac('sha256', key).update(this.#live).digest('hex').slice(0, 16)
  }

  /** Scrub the underlying bytes. Idempotent; the Secret is unusable afterwards. */
  dispose(): void {
    if (this.#buf !== null) {
      this.#buf.fill(0)
      this.#buf = null
    }
    this.#disposed = true
  }

  // ---------------------------------------------------------------------------
  // Serialisation guards.
  //
  // These redact rather than disappear, so an accidental `JSON.stringify` or `console.log`
  // leaves an obvious `[redacted]` marker instead of a silent `{}` that a reader could
  // mistake for empty data.
  //
  // test/secret.test.ts asserts that none of these ever emit the plaintext. If anyone
  // changes one to return the real value, those tests fail — that is the point.
  // ---------------------------------------------------------------------------

  toJSON(): string {
    return this.describe()
  }

  toString(): string {
    return this.describe()
  }

  [Symbol.toPrimitive](): string {
    return this.describe()
  }

  [inspectCustom](): string {
    return this.describe()
  }

  /** Support explicit disposal in `using` blocks. */
  [Symbol.dispose](): void {
    this.dispose()
  }
}