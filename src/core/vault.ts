/**
 * Encrypted vault.
 *
 * On-disk shape of `vault.json`:
 *
 * ```json
 * {
 *   "schemaVersion": 1,
 *   "kekRef": { "service": "vaultbroker:kek", "account": "vault:v1" },
 *   "createdAt": "2026-10-08T...",
 *   "records": [
 *     {
 *       "id": "rec_9f3a...",
 *       "index": "<hmac-sha256 hex>",
 *       "kdfVersion": 1,
 *       "aead": { "algorithm": "aes-256-gcm", "nonce": "...", "tag": "...", "ciphertext": "..." }
 *     }
 *   ]
 * }
 * ```
 *
 * Note what is *not* there: no key material (per-record DEKs are derived, not stored) and
 * no plaintext service names or account aliases (those live inside the ciphertext; the
 * `index` is an HMAC so lookup does not require decryption). Someone who copies this file
 * learns how many credentials exist and nothing about which services they are for.
 *
 * Everything a caller is allowed to see about a credential — service, alias, timestamps,
 * note — is returned inside {@link VaultEntry}. The credential itself only ever leaves via
 * {@link Vault.getSecret}, which hands back a `Secret<T>`. The caller decides when to
 * dispose it.
 */

import { existsSync, readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'

import {
  AEAD_ALGORITHM,
  blindIndex,
  deriveIndexKey,
  deriveRecordKey,
  recordAad,
  seal,
  open,
  generateKeyEncryptionKey,
  wipeKey,
  VaultIntegrityError,
  type AeadSeal,
} from './crypto.ts'
import { backupVaultFile, writeFileAtomic } from './fsx.ts'
import { vaultPath } from './runtime-paths.ts'
import type { KeychainRef, KeychainStore } from './keychain.ts'
import { Secret } from './secret.ts'

/** Bumped on an incompatible on-disk change. Older files are refused, never migrated blindly. */
export const VAULT_SCHEMA_VERSION = 1

/** Default keychain coordinates for the KEK. */
export const KEK_REF: KeychainRef = { service: 'vaultbroker:kek', account: 'vault:v1' }

export class VaultError extends Error {}

export class VaultCorruptError extends VaultError {}

interface StoredRecord {
  readonly id: string
  readonly index: string
  readonly kdfVersion: number
  aead: AeadSeal
}

interface VaultFileShape {
  readonly schemaVersion: number
  readonly kekRef: KeychainRef
  readonly createdAt: string
  readonly records: readonly StoredRecord[]
}

/**
 * The decrypted envelope for one credential.
 *
 * `secret` is mutable and holds base64 credential material while an entry is decrypted.
 * It is deliberately NOT readonly so that every call site can blank it in a `finally`
 * block; leaving credential bytes alive in a long-lived object is exactly what this
 * project is trying to avoid.
 */
interface EntryEnvelope {
  readonly service: string
  readonly accountAlias: string
  readonly secretType: string
  readonly note: string
  readonly createdAt: string
  readonly rotatedAt: string | null
  secret: string
}

/**
 * Everything about a credential except the credential.
 *
 * This is what `list_accounts` and any MCP tool surface may return. It contains no
 * secret material, which is why it is a plain serialisable type.
 */
export interface VaultEntry {
  readonly id: string
  readonly service: string
  readonly accountAlias: string
  readonly secretType: string
  readonly note: string
  readonly createdAt: string
  readonly rotatedAt: string | null
}

export interface AddCredentialInput {
  readonly service: string
  readonly accountAlias: string
  readonly secret: Secret
  readonly secretType?: string
  readonly note?: string
}

export class Vault {
  readonly #kek: Buffer
  readonly #indexKey: Buffer
  #records: StoredRecord[]
  readonly #createdAt: string
  /**
   * Where this vault lives.
   *
   * Remembered per instance rather than defaulted from `vaultPath()` at each call site.
   * A `Vault` opened against a specific file must write back to *that* file: a global
   * default meant `vault.add(...)` on a non-default vault silently wrote to the user's
   * real runtime vault instead. This bit once in the CLI tests and once in the daemon
   * tests, so the parameter is removed from the mutating methods entirely.
   */
  readonly #path: string
  #disposed = false

  private constructor(kek: Buffer, records: StoredRecord[], createdAt: string, path: string) {
    this.#kek = kek
    this.#indexKey = deriveIndexKey(kek)
    this.#records = records
    this.#createdAt = createdAt
    this.#path = path
  }

  /** The file this vault is bound to. */
  get path(): string {
    return this.#path
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Open the vault, creating it and its KEK on first run.
   *
   * `kek` is read from the Keychain when the vault file already exists. When it does not,
   * a fresh KEK is generated and written to the Keychain before the file is created —
   * the reverse order would risk a file with no reachable key.
   */
  static open(store: KeychainStore, path: string = vaultPath(), kekRef: KeychainRef = KEK_REF): Vault {
    let kek = store.read(kekRef)

    if (kek === undefined) {
      if (existsSync(path)) {
        throw new VaultError(
          'vault file exists but no key-encryption key is present in the keychain. ' +
            'Refusing to proceed: creating a new KEK would make every existing credential ' +
            'permanently unrecoverable.',
        )
      }
      kek = generateKeyEncryptionKey()
      store.write(kekRef, kek)
    }

    if (kek.byteLength !== 32) {
      wipeKey(kek)
      throw new VaultError(`key-encryption key has unexpected length ${kek.byteLength}, expected 32`)
    }

    if (!existsSync(path)) {
      const created = new Vault(kek, [], new Date().toISOString(), path)
      created.save()
      return created
    }

    const parsed = Vault.#load(path)
    if (parsed.schemaVersion !== VAULT_SCHEMA_VERSION) {
      wipeKey(kek)
      throw new VaultError(
        `vault schema v${parsed.schemaVersion} is not supported by this build ` +
          `(expected v${VAULT_SCHEMA_VERSION}). Refusing to open; back up and migrate manually.`,
      )
    }

    return new Vault(kek, [...parsed.records], parsed.createdAt, path)
  }

  static #load(path: string): VaultFileShape {
    let raw: string
    try {
      raw = readFileSync(path, 'utf8')
    } catch (cause) {
      throw new VaultCorruptError(
        `cannot read vault file at ${path}: ${cause instanceof Error ? cause.message : 'unknown'}`,
      )
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Most likely a partial write from a crash. Point at the backups rather than
      // silently starting with an empty vault, which would look like data loss.
      throw new VaultCorruptError(
        `vault file at ${path} is not valid JSON. It may be truncated by an interrupted write; ` +
          `check for backups alongside it before doing anything else.`,
      )
    }

    if (typeof parsed !== 'object' || parsed === null || !Array.isArray((parsed as VaultFileShape).records)) {
      throw new VaultCorruptError(`vault file at ${path} has an unexpected shape`)
    }

    return parsed as VaultFileShape
  }

  /** Zero the KEK and index key. The Vault is unusable afterwards. */
  dispose(): void {
    if (this.#disposed) return
    wipeKey(this.#kek)
    wipeKey(this.#indexKey)
    this.#records = []
    this.#disposed = true
  }

  /** Guard for use-after-dispose. Returns nothing; the name reads as a check. */
  #assertUsable(): void {
    if (this.#disposed) throw new VaultError('vault has been disposed')
  }

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  #shape(): VaultFileShape {
    return {
      schemaVersion: VAULT_SCHEMA_VERSION,
      kekRef: KEK_REF,
      createdAt: this.#createdAt,
      records: this.#records,
    }
  }

  /**
   * Write the vault atomically, backing up the previous contents first.
   *
   * `path` defaults to the runtime location but every internal caller passes it
   * explicitly, so the vault can never be written somewhere other than where it was
   * opened.
   */
  save(): void {
    this.#assertUsable()
    backupVaultFile(this.#path)
    writeFileAtomic(this.#path, `${JSON.stringify(this.#shape(), null, 2)}\n`)
  }

  // -------------------------------------------------------------------------
  // Records
  // -------------------------------------------------------------------------

  #decryptEntry(record: StoredRecord): EntryEnvelope {
    const key = deriveRecordKey(this.#kek, record.id, record.kdfVersion)
    try {
      const plaintext = open(record.aead, key, recordAad(record.id, record.kdfVersion))
      return JSON.parse(plaintext.toString('utf8')) as EntryEnvelope
    } finally {
      wipeKey(key)
    }
  }

  #entry(record: StoredRecord, envelope: EntryEnvelope): VaultEntry {
    return {
      id: record.id,
      service: envelope.service,
      accountAlias: envelope.accountAlias,
      secretType: envelope.secretType,
      note: envelope.note,
      createdAt: envelope.createdAt,
      rotatedAt: envelope.rotatedAt,
    }
  }

  #findRecord(service: string, accountAlias: string): StoredRecord | undefined {
    const wanted = blindIndex(this.#indexKey, service, accountAlias)
    return this.#records.find((r) => r.index === wanted)
  }

  /**
   * Store a credential.
   *
   * The `Secret` is read through `withBytes` and never converted to a string outside the
   * encryption call, so the plaintext exists only as the bytes we are already holding.
   */
  add(input: AddCredentialInput): VaultEntry {
    this.#assertUsable()

    if (this.#findRecord(input.service, input.accountAlias) !== undefined) {
      throw new VaultError(`a credential for ${input.service}/${input.accountAlias} already exists`)
    }

    const id = `rec_${randomUUID().replaceAll('-', '')}`
    const kdfVersion = 1
    const now = new Date().toISOString()

    const envelope: EntryEnvelope = {
      service: input.service,
      accountAlias: input.accountAlias,
      secretType: input.secretType ?? 'opaque',
      note: input.note ?? '',
      createdAt: now,
      rotatedAt: null,
      secret: '',
    }

    const key = deriveRecordKey(this.#kek, id, kdfVersion)
    try {
      // Base64 rather than utf8-in-JSON: credential bytes need not be valid UTF-8, and
      // JSON string escaping would mangle control characters.
      const sealed = input.secret.withBytes((secretBytes) => {
        const withSecret = { ...envelope, secret: secretBytes.toString('base64') }
        return seal(Buffer.from(JSON.stringify(withSecret), 'utf8'), key, recordAad(id, kdfVersion))
      })

      const record: StoredRecord = {
        id,
        index: blindIndex(this.#indexKey, input.service, input.accountAlias),
        kdfVersion,
        aead: sealed,
      }

      this.#records.push(record)
      this.save()

      return this.#entry(record, { ...envelope, secret: '' })
    } finally {
      wipeKey(key)
    }
  }

  /** List every credential's metadata. Decrypts to reveal service and alias; never returns secrets. */
  list(): VaultEntry[] {
    this.#assertUsable()
    return this.#records.map((record) => this.#entry(record, this.#decryptEntry(record)))
  }

  find(service: string, accountAlias: string): VaultEntry | undefined {
    this.#assertUsable()
    const record = this.#findRecord(service, accountAlias)
    return record === undefined ? undefined : this.#entry(record, this.#decryptEntry(record))
  }

  /**
   * Retrieve a credential for use.
   *
   * Returns a `Secret<T>` the caller must dispose. This is the only path by which
   * credential bytes leave the vault, and even here they are handed over inside a type
   * that cannot be serialised or logged.
   */
  getSecret(service: string, accountAlias: string): Secret {
    this.#assertUsable()
    const record = this.#findRecord(service, accountAlias)
    if (record === undefined) {
      throw new VaultError(`no credential for ${service}/${accountAlias}`)
    }

    const envelope = this.#decryptEntry(record)
    const secret = Secret.fromBuffer(Buffer.from(envelope.secret, 'base64'))
    envelope.secret = ''
    return secret
  }

  /**
   * Replace a credential's secret, keeping its identity.
   *
   * Re-encrypts under the same record id and kdfVersion. Because the blind index is
   * derived from service and alias rather than from the secret, the lookup key does not
   * change, so this needs no reindex.
   */
  rotate(service: string, accountAlias: string, secret: Secret): VaultEntry {
    this.#assertUsable()
    const record = this.#findRecord(service, accountAlias)
    if (record === undefined) {
      throw new VaultError(`no credential for ${service}/${accountAlias}`)
    }

    const existing = this.#decryptEntry(record)
    const key = deriveRecordKey(this.#kek, record.id, record.kdfVersion)

    try {
      const sealed = secret.withBytes((secretBytes) => {
        const updated: EntryEnvelope = {
          ...existing,
          secret: secretBytes.toString('base64'),
          rotatedAt: new Date().toISOString(),
        }
        return seal(Buffer.from(JSON.stringify(updated), 'utf8'), key, recordAad(record.id, record.kdfVersion))
      })

      record.aead = sealed
      this.save()
      return this.#entry(record, this.#decryptEntry(record))
    } finally {
      wipeKey(key)
      existing.secret = ''
    }
  }

  remove(service: string, accountAlias: string): boolean {
    this.#assertUsable()
    const record = this.#findRecord(service, accountAlias)
    if (record === undefined) return false

    this.#records = this.#records.filter((r) => r.id !== record.id)
    this.save()
    return true
  }

  /** Number of stored credentials. */
  get size(): number {
    return this.#records.length
  }
}

/** Re-exported so callers can distinguish a tampering failure from a usage error. */
export { VaultIntegrityError }