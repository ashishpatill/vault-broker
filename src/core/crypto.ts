/**
 * Vault cryptography.
 *
 * Key hierarchy:
 *
 *   KEK  key-encryption key. 32 random bytes, held in the macOS Keychain, never in the
 *        vault file and never in a config file.
 *        │
 *        ├─ HKDF-SHA256(info="vaultbroker:index:v1")  → indexKey
 *        │      used only for HMAC blind indexes, so a lookup key and a decryption key
 *        │      are never the same bytes.
 *        │
 *        └─ HKDF-SHA256(info="<recordId>:<kdfVersion>") → record DEK
 *               used only to encrypt that one record.
 *
 * Each record's DEK is *derived*, never stored. The vault file therefore contains no key
 * material at all — only ciphertext, nonces, tags and blind indexes. This is stricter
 * than wrapping per-record keys and storing the wrapped form, and it means there is no
 * second thing to lose. The cost is that rotating the KEK requires re-encrypting every
 * record, which is the correct trade for a local vault of this size.
 *
 * Algorithm choices, and why:
 * - AES-256-GCM — authenticated, hardware-accelerated on Apple silicon, no dependency.
 *   ChaCha20-Poly1305 would be a fine alternative but buys nothing here given no build step.
 * - 96-bit random nonce per record. With a vault of this size the birthday bound is not
 *   remotely a concern, and a random nonce means we never have to reason about
 *   counter reuse across writes.
 * - AAD binds each ciphertext to its own recordId and kdfVersion, so an attacker with
 *   write access to the vault file cannot move a ciphertext from one record to another.
 */

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto'

/** Cipher suite identifier, stored per record so the format can evolve. */
export const AEAD_ALGORITHM = 'aes-256-gcm'

/** GCM nonce length in bytes. The standard 96-bit recommendation. */
export const NONCE_BYTES = 12

/** GCM authentication tag length in bytes. */
export const TAG_BYTES = 16

/** All keys are 32 bytes (AES-256). */
export const KEY_BYTES = 32

/** Fixed application salt. Per-record separation comes from `info`, not from the salt. */
const HKDF_SALT = Buffer.from('vaultbroker:hkdf-salt:v1', 'utf8')

/** Domain separator for the blind-index key, keeping it distinct from any DEK. */
const INDEX_KEY_INFO = 'vaultbroker:index-key:v1'

/**
 * Base class for vault cryptography failures.
 *
 * `name` is deliberately not overridden: narrowing it to a literal type in the base would
 * prevent the subclass from reporting its own name. `instanceof` is the discriminator.
 */
export class VaultCryptoError extends Error {}

export class VaultIntegrityError extends VaultCryptoError {}

/** Generate a fresh KEK from the OS CSPRNG. */
export function generateKeyEncryptionKey(): Buffer {
  return randomBytes(KEY_BYTES)
}

function hkdf(kek: Buffer, info: string): Buffer {
  return Buffer.from(hkdfSync('sha256', kek, HKDF_SALT, Buffer.from(info, 'utf8'), KEY_BYTES))
}

/**
 * Derive the dedicated blind-index key.
 *
 * Key separation matters here: if one key were used for both HMAC indexes and record
 * decryption, a leaked index would hand an attacker a decryption key.
 */
export function deriveIndexKey(kek: Buffer): Buffer {
  return hkdf(kek, INDEX_KEY_INFO)
}

/** Derive the per-record data key. Deterministic, so nothing needs to be stored. */
export function deriveRecordKey(kek: Buffer, recordId: string, kdfVersion: number): Buffer {
  return hkdf(kek, `${recordId}:${kdfVersion}`)
}

/**
 * Build the domain separator used as AEAD associated data.
 *
 * Binding this into the tag means a ciphertext cannot be relocated to a different record
 * or replayed under a different key version.
 */
export function recordAad(recordId: string, kdfVersion: number): Buffer {
  return Buffer.from(`vaultbroker:record:v1:${recordId}:${kdfVersion}`, 'utf8')
}

export interface AeadSeal {
  readonly algorithm: typeof AEAD_ALGORITHM
  readonly nonce: string
  readonly tag: string
  readonly ciphertext: string
}

/** Encrypt with AES-256-GCM. The returned seal contains no key material. */
export function seal(plaintext: Buffer, key: Buffer, aad: Buffer): AeadSeal {
  if (key.byteLength !== KEY_BYTES) {
    throw new VaultCryptoError(`expected a ${KEY_BYTES}-byte key, got ${key.byteLength}`)
  }

  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv(AEAD_ALGORITHM, key, nonce)
  cipher.setAAD(aad)

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])

  return {
    algorithm: AEAD_ALGORITHM,
    nonce: nonce.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  }
}

/**
 * Decrypt and verify.
 *
 * Throws {@link VaultIntegrityError} on any authentication failure — wrong key, tampered
 * ciphertext, tampered nonce/tag, or mismatched AAD. Never returns partial output, and
 * never substitutes garbage for a failed decrypt: a vault that cannot be authenticated is
 * a vault that must be treated as compromised, not as empty.
 */
export function open(sealData: AeadSeal, key: Buffer, aad: Buffer): Buffer {
  if (key.byteLength !== KEY_BYTES) {
    throw new VaultCryptoError(`expected a ${KEY_BYTES}-byte key, got ${key.byteLength}`)
  }
  if (sealData.algorithm !== AEAD_ALGORITHM) {
    throw new VaultCryptoError(`unsupported algorithm: ${sealData.algorithm}`)
  }

  try {
    const decipher = createDecipheriv(AEAD_ALGORITHM, key, Buffer.from(sealData.nonce, 'base64'))
    decipher.setAAD(aad)
    decipher.setAuthTag(Buffer.from(sealData.tag, 'base64'))

    return Buffer.concat([
      decipher.update(Buffer.from(sealData.ciphertext, 'base64')),
      decipher.final(),
    ])
  } catch {
    // Deliberately opaque. Distinguishing "wrong key" from "tampered ciphertext" would
    // hand an attacker an oracle, and neither case is something we can usefully recover.
    throw new VaultIntegrityError(
      'record failed authentication: wrong key, or the vault file has been modified',
    )
  }
}

/**
 * Compute the blind index for a service + account pair.
 *
 * Lets the broker find "the github/work credential" without decrypting anything and
 * without the vault file containing the service name or account alias in the clear. An
 * attacker holding only the vault file sees opaque HMACs rather than a list of which
 * services you have credentials for.
 */
export function blindIndex(indexKey: Buffer, service: string, accountAlias: string): string {
  // The NUL separator prevents ("git", "hub/work") colliding with ("github/work", "").
  return createHmac('sha256', indexKey)
    .update(service, 'utf8')
    .update('\u0000', 'utf8')
    .update(accountAlias, 'utf8')
    .digest('hex')
}

/** Constant-time string comparison, for comparing indexes and capability ids. */
export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.byteLength !== bufB.byteLength) return false
  return timingSafeEqual(bufA, bufB)
}

/**
 * Wipe a key buffer.
 *
 * Best-effort by nature: V8 may have copied the bytes during crypto operations, and the
 * underlying ArrayBuffer memory is not guaranteed to be scrubbed once released to the
 * garbage collector. Done because it raises the cost of a memory scrape, not because it
 * makes disclosure impossible.
 */
export function wipeKey(key: Buffer): void {
  key.fill(0)
}