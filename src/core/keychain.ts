/**
 * Keychain integration.
 *
 * The KEK lives in the macOS login Keychain, reached through `/usr/bin/security`. Two
 * rules govern this file, both of them `ps`-leak rules rather than cryptography rules:
 *
 *   1. **Never put the key in argv.** `security add-generic-password -w <value>` would
 *      put the key in the process table, readable by every process on the machine via
 *      `ps`. We always pass `-w` as the *last* option with no value, which makes
 *      `security` prompt on stdin instead.
 *   2. **Never put the key in a shell string.** We spawn the binary directly with an
 *      argv array — no shell — so there is no interpolation to get wrong.
 *
 * The interface exists so tests never touch the real login Keychain. `InMemoryKeychain`
 * is used in-tree; a stub `security` binary (selected via `VAULTBROKER_SECURITY_BIN`) is
 * used to assert rule 1 directly.
 */

import { spawnSync } from 'node:child_process'

/** Handle to a keychain item. */
export interface KeychainRef {
  readonly service: string
  readonly account: string
}

export interface KeychainStore {
  /** Read the item's bytes, or `undefined` when it does not exist. */
  read(ref: KeychainRef): Buffer | undefined
  /** Create or replace the item. */
  write(ref: KeychainRef, secret: Buffer): void
  /** Remove the item. Returns true when something was removed. */
  delete(ref: KeychainRef): boolean
  /** True when the item exists. */
  has(ref: KeychainRef): boolean
}

/** Absolute path to the real binary, overridable so tests can substitute a stub. */
export function securityBinary(): string {
  return process.env['VAULTBROKER_SECURITY_BIN'] ?? '/usr/bin/security'
}

/**
 * Transport encoding for key material crossing the keychain boundary.
 *
 * The `security` CLI reads and writes passwords as *text*, so raw 32-byte key material
 * has to become a string to pass through it. Random bytes are not valid UTF-8: decoding
 * them replaces invalid sequences with U+FFFD and silently expands the value (32 bytes
 * becomes 49-60 bytes), and encoding back does not restore the original. A KEK stored
 * that way is unrecoverable — every read yields a different key and every record fails
 * authentication.
 *
 * Hex is used rather than base64 for one reason: it is invariant under any character
 * encoding, so a round trip through the CLI cannot corrupt it regardless of locale or
 * terminal settings. Base64 would work too, but hex makes the failure mode of a bug
 * ("wrong key") independent of encoding concerns.
 */
function encodeForTransport(key: Buffer): string {
  return key.toString('hex')
}

function decodeFromTransport(text: string, ref: KeychainRef): Buffer {
  const trimmed = text.trim()

  if (!/^[0-9a-fA-F]*$/u.test(trimmed) || trimmed.length % 2 !== 0) {
    throw new KeychainError(
      `keychain item for ${ref.service}/${ref.account} is not valid hex. It may have been ` +
        `written by another tool, or corrupted. Restoring from a backup requires removing ` +
        `this item first — do not attempt to re-encrypt over it.`,
    )
  }

  return Buffer.from(trimmed, 'hex')
}

function run(args: readonly string[], input?: Buffer): { status: number; stdout: Buffer; stderr: string } {
  const result = spawnSync(securityBinary(), [...args], {
    input,
    maxBuffer: 1 << 20,
    // Never inherit: an inherited TTY could turn the stdin prompt into an interactive
    // hang, and we want stderr captured so failures can be reported as a single line.
    stdio: ['pipe', 'pipe', 'pipe'],
  })

  if (result.error !== undefined) {
    throw new KeychainError(`could not run ${securityBinary()}: ${result.error.message}`)
  }

  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: (result.stderr ?? Buffer.alloc(0)).toString('utf8').trim(),
  }
}

export class KeychainError extends Error {
  constructor(message: string) {
    super(message)
  }
}

/**
 * The real Keychain, via the `security` CLI.
 *
 * This is not a great long-term design: shelling out per operation adds latency, and
 * `security` has no way to set a biometry ACL, so unlock is gated on the login Keychain
 * password rather than Touch ID. The native helper in v0.2 replaces this. It is the
 * right trade for v0 because it needs no native toolchain, which this machine does not
 * have.
 */
export class MacSecurityKeychain implements KeychainStore {
  readonly #keychainPath: string | undefined

  constructor(keychainPath?: string) {
    this.#keychainPath = keychainPath
  }

  #args(...rest: readonly string[]): string[] {
    // A trailing keychain path is optional; omitting it targets the user's default.
    return this.#keychainPath === undefined ? [...rest] : [...rest, this.#keychainPath]
  }

  has(ref: KeychainRef): boolean {
    const { status } = run(this.#args('find-generic-password', '-s', ref.service, '-a', ref.account))
    return status === 0
  }

  read(ref: KeychainRef): Buffer | undefined {
    // -w writes the password to stdout as a single line. We capture it as bytes so the
    // value never passes through a JS string we might log.
    const { status, stdout, stderr } = run(
      this.#args('find-generic-password', '-s', ref.service, '-a', ref.account, '-w'),
    )

    if (status === 44 || /could not be found/i.test(stderr)) return undefined
    if (status !== 0) {
      throw new KeychainError(`keychain read failed (exit ${status}): ${firstLine(stderr)}`)
    }

    return decodeFromTransport(stdout.toString('utf8'), ref)
  }

  /**
   * Write a keychain item.
   *
   * Two behaviours of `security` drive this implementation, both discovered by probing
   * the real binary rather than from its documentation:
   *
   * 1. `-w` with no value reads the password from stdin. This is what keeps the key out
   *    of argv, and therefore out of `ps`.
   * 2. On *creating* an item, `security` prompts **twice** ("password data for new item"
   *    then "retype password for new item"). Writing the value once yields
   *    "passwords don't match" — and, alarmingly, exits 0 while storing an unusable item.
   *    A silent corrupt write is the worst possible failure here, so we write the value
   *    twice to satisfy the prompt and then verify by reading it back.
   *
   * The alternative, `-X <hex>`, needs no prompt but puts the key in argv in hex form,
   * which is still a `ps` leak. Verified and rejected.
   */
  write(ref: KeychainRef, secret: Buffer): void {
    const encoded = Buffer.from(encodeForTransport(secret), 'utf8')

    // Two copies: one per prompt. `security` consumes them as two lines.
    const stdinInput = Buffer.concat([encoded, Buffer.from('\n'), encoded, Buffer.from('\n')])

    const { status, stderr } = run(
      this.#args('add-generic-password', '-U', '-s', ref.service, '-a', ref.account, '-w'),
      stdinInput,
    )

    if (status !== 0) {
      throw new KeychainError(`keychain write failed (exit ${status}): ${firstLine(stderr)}`)
    }

    // Verify. `security` can exit 0 having stored nothing usable, so a successful exit
    // code is not evidence of a successful write.
    const readBack = this.read(ref)
    if (readBack === undefined || !readBack.equals(secret)) {
      throw new KeychainError(
        `keychain write to ${ref.service}/${ref.account} did not round-trip. ` +
          `The item may now be corrupt; remove it before retrying.`,
      )
    }
  }

  delete(ref: KeychainRef): boolean {
    const { status } = run(this.#args('delete-generic-password', '-s', ref.service, '-a', ref.account))
    return status === 0
  }
}

/**
 * In-memory store for tests and for the not-yet-implemented locked state.
 *
 * Not a security control — it provides no protection at all. It exists so that the test
 * suite can exercise the vault without touching the user's login Keychain.
 */
export class InMemoryKeychain implements KeychainStore {
  readonly #items = new Map<string, Buffer>()

  static #key(ref: KeychainRef): string {
    return `${ref.service}\u0000${ref.account}`
  }

  has(ref: KeychainRef): boolean {
    return this.#items.has(InMemoryKeychain.#key(ref))
  }

  read(ref: KeychainRef): Buffer | undefined {
    const stored = this.#items.get(InMemoryKeychain.#key(ref))
    return stored === undefined ? undefined : decodeFromTransport(stored.toString('utf8'), ref)
  }

  write(ref: KeychainRef, secret: Buffer): void {
    // Store the *encoded* form, matching what the real store persists. A test that
    // round-trips through this class would otherwise miss a transport-encoding bug —
    // which is exactly the class of bug that made random 32-byte keys unrecoverable.
    this.#items.set(InMemoryKeychain.#key(ref), Buffer.from(encodeForTransport(secret), 'utf8'))
  }

  delete(ref: KeychainRef): boolean {
    return this.#items.delete(InMemoryKeychain.#key(ref))
  }
}

function firstLine(text: string): string {
  const [first = ''] = text.split('\n')
  return first.slice(0, 200)
}