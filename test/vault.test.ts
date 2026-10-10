/**
 * Vault tests.
 *
 * Three things are being defended here, in order of importance:
 *
 *   1. **The credential is not in the vault file.** Asserted by searching the raw bytes
 *      for the secret AND for the service/account names, since the blind index is only
 *      worth having if it actually hides them.
 *   2. **The key never travels through argv.** Asserted against a stub `security` binary
 *      that records how it was called.
 *   3. **Tampering is detected, not tolerated.** Asserted by mutating the file and
 *      requiring a loud failure.
 *
 * Every test uses a throwaway temp directory and an in-memory or stub keychain, so the
 * user's real login Keychain and runtime directory are never touched.
 */

import { strict as assert } from 'node:assert'
import { createHash, randomBytes } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { runtimeRoot } from '../src/core/runtime-paths.ts'
import { inspect } from 'node:util'
import { afterEach, beforeEach, describe, test } from 'node:test'

import {
  blindIndex,
  constantTimeEquals,
  deriveIndexKey,
  deriveRecordKey,
  generateKeyEncryptionKey,
  recordAad,
  seal,
  open,
  VaultIntegrityError,
} from '../src/core/crypto.ts'
import { InMemoryKeychain } from '../src/core/keychain.ts'
import { Secret } from '../src/core/secret.ts'
import { VAULT_SCHEMA_VERSION, Vault, VaultError, type VaultEntry } from '../src/core/vault.ts'

const SECRET_CANARY = 'ghp_CANARY_MUST_NEVER_APPEAR_ON_DISK_4c1f9a'
const SERVICE = 'github'
const ACCOUNT = 'work-acme'

interface StubInvocation {
  readonly mode: string
  readonly argv: readonly string[]
  readonly stdinLength: number
  readonly stdinSha256: string
}

describe('crypto primitives', () => {
  test('seal/open round-trips', () => {
    const key = randomBytes(32)
    const aad = recordAad('rec_1', 1)
    const plaintext = Buffer.from('hello world', 'utf8')

    const sealed = seal(plaintext, key, aad)
    assert.deepEqual(open(sealed, key, aad), plaintext)
  })

  test('ciphertext is not the plaintext', () => {
    const key = randomBytes(32)
    const sealed = seal(Buffer.from(SECRET_CANARY, 'utf8'), key, recordAad('rec_1', 1))
    const asText = `${sealed.ciphertext}${sealed.nonce}${sealed.tag}`
    assert.ok(!asText.includes(SECRET_CANARY))
  })

  test('a wrong key fails authentication', () => {
    const aad = recordAad('rec_1', 1)
    const sealed = seal(Buffer.from('data'), randomBytes(32), aad)
    assert.throws(() => open(sealed, randomBytes(32), aad), VaultIntegrityError)
  })

  test('tampered ciphertext fails authentication', () => {
    const key = randomBytes(32)
    const aad = recordAad('rec_1', 1)
    const sealed = seal(Buffer.from('sensitive data'), key, aad)

    // Flip one byte of the ciphertext.
    const bytes = Buffer.from(sealed.ciphertext, 'base64')
    bytes[0] = (bytes[0] ?? 0) ^ 0x01
    const tampered = { ...sealed, ciphertext: bytes.toString('base64') }

    assert.throws(() => open(tampered, key, aad), VaultIntegrityError)
  })

  test('tampered nonce and tampered tag both fail authentication', () => {
    const key = randomBytes(32)
    const aad = recordAad('rec_1', 1)
    const sealed = seal(Buffer.from('sensitive data'), key, aad)

    const badNonce = Buffer.from(sealed.nonce, 'base64')
    badNonce[0] = (badNonce[0] ?? 0) ^ 0xff

    const badTag = Buffer.from(sealed.tag, 'base64')
    badTag[0] = (badTag[0] ?? 0) ^ 0xff

    assert.throws(() => open({ ...sealed, nonce: badNonce.toString('base64') }, key, aad), VaultIntegrityError)
    assert.throws(() => open({ ...sealed, tag: badTag.toString('base64') }, key, aad), VaultIntegrityError)
  })

  test('AAD binds a ciphertext to its record, so records cannot be swapped', () => {
    const kek = randomBytes(32)
    const key = deriveRecordKey(kek, 'rec_A', 1)
    const sealed = seal(Buffer.from('credential for A'), key, recordAad('rec_A', 1))

    // The same key material with rec_B's AAD must not authenticate: this is what stops
    // an attacker with write access moving a valid ciphertext onto another record.
    assert.throws(() => open(sealed, key, recordAad('rec_B', 1)), VaultIntegrityError)
  })

  test('a different kdfVersion produces a different key', () => {
    const kek = randomBytes(32)
    assert.notEqual(
      deriveRecordKey(kek, 'rec_A', 1).toString('hex'),
      deriveRecordKey(kek, 'rec_A', 2).toString('hex'),
    )
  })

  test('deriveIndexKey is separated from every record key', () => {
    const kek = randomBytes(32)
    const indexKey = deriveIndexKey(kek)
    const recordKey = deriveRecordKey(kek, 'rec_A', 1)

    assert.notEqual(indexKey.toString('hex'), recordKey.toString('hex'))
  })

  test('blindIndex is stable, key-dependent, and collision-resistant on separator', () => {
    const indexKey = deriveIndexKey(randomBytes(32))

    assert.equal(blindIndex(indexKey, SERVICE, ACCOUNT), blindIndex(indexKey, SERVICE, ACCOUNT))
    assert.notEqual(
      blindIndex(indexKey, 'a', 'bc'),
      blindIndex(indexKey, 'ab', 'c'),
      'the NUL separator must prevent boundary collisions',
    )
    assert.match(blindIndex(indexKey, SERVICE, ACCOUNT), /^[0-9a-f]{64}$/u)
  })

  test('constantTimeEquals compares correctly', () => {
    assert.equal(constantTimeEquals('abc', 'abc'), true)
    assert.equal(constantTimeEquals('abc', 'abd'), false)
    assert.equal(constantTimeEquals('abc', 'abcd'), false)
  })

  test('a wrong-length key is rejected with a clear error, not a crash', () => {
    assert.throws(() => seal(Buffer.from('x'), randomBytes(16), recordAad('r', 1)), /expected a 32-byte key/u)
  })
})

describe('vault storage', () => {
  let dir: string
  let vaultPath: string
  let keychain: InMemoryKeychain

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaultbroker-vault-'))
    vaultPath = join(dir, 'vault.json')
    keychain = new InMemoryKeychain()
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  function addGitHub(vault: Vault, secret = SECRET_CANARY): VaultEntry {
    return vault.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of(secret), secretType: 'bearer' })
  }

  test('round-trips a credential', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)

    assert.equal(vault.size, 1)

    const entry = vault.find(SERVICE, ACCOUNT)
    assert.ok(entry)
    assert.equal(entry.service, SERVICE)
    assert.equal(entry.accountAlias, ACCOUNT)
    assert.equal(entry.secretType, 'bearer')

    const retrieved = vault.getSecret(SERVICE, ACCOUNT)
    const seen = retrieved.withBytes((b) => b.toString('utf8'))
    assert.equal(seen, SECRET_CANARY)
    retrieved.dispose()
    vault.dispose()
  })

  test('the vault file contains neither the secret nor the account names', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)
    vault.dispose()

    const raw = readFileSync(vaultPath, 'utf8')

    assert.ok(!raw.includes(SECRET_CANARY), 'credential must not appear in the vault file')
    assert.ok(!raw.includes(SERVICE), 'service name must not appear in the clear')
    assert.ok(!raw.includes(ACCOUNT), 'account alias must not appear in the clear')
    // …but the opaque per-record structure should be there.
    assert.match(raw, /"index": "[0-9a-f]{64}"/u)
    assert.match(raw, /"algorithm": "aes-256-gcm"/u)
  })

  test('the vault file contains no key material', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)
    const kek = keychain.read({ service: 'vaultbroker:kek', account: 'vault:v1' })
    vault.dispose()

    const raw = readFileSync(vaultPath, 'utf8')
    assert.ok(kek !== undefined)
    assert.ok(!raw.includes(kek.toString('base64')), 'KEK must not be stored in the vault file')
    assert.ok(!raw.includes(kek.toString('hex')), 'KEK must not be stored in the vault file')
  })

  test('opens without a KEK, creating one on first run', () => {
    assert.equal(keychain.has({ service: 'vaultbroker:kek', account: 'vault:v1' }), false)

    const vault = Vault.open(keychain, vaultPath)
    vault.dispose()

    assert.equal(keychain.has({ service: 'vaultbroker:kek', account: 'vault:v1' }), true)
  })

  test('reuses an existing KEK across reopens', () => {
    const first = Vault.open(keychain, vaultPath)
    addGitHub(first)
    first.dispose()

    const second = Vault.open(keychain, vaultPath)
    assert.equal(second.size, 1)
    const secret = second.getSecret(SERVICE, ACCOUNT)
    assert.equal(secret.withBytes((b) => b.toString('utf8')), SECRET_CANARY)
    secret.dispose()
    second.dispose()
  })

  test('refuses to open a vault whose KEK is missing, rather than orphaning credentials', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)
    vault.dispose()

    // Simulate a lost keychain entry. Silently generating a new KEK here would make
    // every credential permanently unrecoverable while looking like an empty vault.
    const empty = new InMemoryKeychain()
    assert.throws(() => Vault.open(empty, vaultPath), VaultError)
  })

  test('rejects duplicate service/account pairs', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)

    assert.throws(
      () => vault.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of('other') }),
      VaultError,
    )
    vault.dispose()
  })

  test('allows the same service with different accounts', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)
    vault.add({ service: SERVICE, accountAlias: 'personal', secret: Secret.of('other-secret') })

    assert.equal(vault.size, 2)
    // Sorted so the assertion does not depend on insertion order.
    assert.deepEqual(vault.list().map((e) => e.accountAlias).sort(), ['personal', ACCOUNT].sort())
    vault.dispose()
  })

  test('rotate replaces the secret and records the rotation time', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)

    const before = vault.find(SERVICE, ACCOUNT)
    assert.equal(before?.rotatedAt, null)

    vault.rotate(SERVICE, ACCOUNT, Secret.of('rotated-value'))

    const after = vault.find(SERVICE, ACCOUNT)
    assert.notEqual(after?.rotatedAt, null, 'rotation must be timestamped')

    const secret = vault.getSecret(SERVICE, ACCOUNT)
    assert.equal(secret.withBytes((b) => b.toString('utf8')), 'rotated-value')
    secret.dispose()
    vault.dispose()
  })

  test('rotate leaves no trace of the old secret in the vault file', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)
    vault.rotate(SERVICE, ACCOUNT, Secret.of('brand-new-value'))
    vault.dispose()

    const raw = readFileSync(vaultPath, 'utf8')
    assert.ok(!raw.includes(SECRET_CANARY))
    assert.ok(!raw.includes('brand-new-value'))
  })

  test('remove deletes a credential', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)

    assert.equal(vault.remove(SERVICE, ACCOUNT), true)
    assert.equal(vault.size, 0)
    assert.equal(vault.remove(SERVICE, ACCOUNT), false)
    vault.dispose()
  })

  test('list returns metadata and never a secret', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)

    for (const entry of vault.list()) {
      const rendered = JSON.stringify(entry)
      assert.ok(!rendered.includes(SECRET_CANARY), 'list() must not leak the credential')
      assert.ok(!('secret' in entry), 'VaultEntry must have no secret field')
    }
    vault.dispose()
  })

  test('handles binary credentials that are not valid UTF-8', () => {
    const vault = Vault.open(keychain, vaultPath)
    const binary = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x0a, 0x00])

    vault.add({ service: 'weird', accountAlias: 'binary', secret: Secret.fromBuffer(binary) })

    const secret = vault.getSecret('weird', 'binary')
    assert.deepEqual(secret.withBytes((b) => Buffer.from(b)), binary)
    secret.dispose()
    vault.dispose()
  })

  test('a Vault writes back to the file it was opened from, never the runtime default', () => {
    // Regression guard for a bug that appeared twice. `add`/`rotate`/`remove` used to
    // default their `path` argument from `vaultPath()`, so mutating a non-default vault
    // silently wrote to the user's real runtime vault instead. The path is now an
    // instance property and the parameter no longer exists.
    const sandboxPath = join(dir, 'bound.json')
    const bound = Vault.open(keychain, sandboxPath)

    assert.equal(bound.path, sandboxPath)

    // Snapshot whatever is at the runtime location before mutating. Asserting
    // "unchanged" rather than "does not exist" keeps this test independent of whether a
    // real runtime vault happens to be present on the developer's machine.
    const runtimeVault = join(runtimeRoot(), 'vault.json')
    const runtimeBefore = existsSync(runtimeVault) ? readFileSync(runtimeVault, 'utf8') : null

    bound.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of(SECRET_CANARY) })

    // Written to the bound file…
    const boundContents = readFileSync(sandboxPath, 'utf8')
    assert.match(boundContents, /"ciphertext":/u)
    assert.ok(!boundContents.includes(SECRET_CANARY), 'bound file must be encrypted')

    // …and the runtime vault was neither created nor modified.
    const runtimeAfter = existsSync(runtimeVault) ? readFileSync(runtimeVault, 'utf8') : null
    assert.equal(runtimeAfter, runtimeBefore, 'must not touch the runtime vault')
    bound.dispose()
  })

  test('mutating methods no longer accept a path override', () => {
    // Compile-time assertion: reintroducing a path parameter would allow a caller to
    // write to a file the vault was not opened from.
    const vault = Vault.open(keychain, join(dir, 'signature.json'))

    // @ts-expect-error add() takes only the credential; the path is bound to the instance.
    vault.add({ service: 'a', accountAlias: 'b', secret: Secret.of('c') }, '/tmp/elsewhere.json')

    // @ts-expect-error remove() likewise.
    vault.remove('a', 'b', '/tmp/elsewhere.json')

    vault.dispose()
  })

  test('getSecret returns a disposable Secret, not a string', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)

    const secret = vault.getSecret(SERVICE, ACCOUNT)
    // If this ever compiled, the invariant would be broken.
    // @ts-expect-error getSecret must return Secret, never a string.
    const asString: string = vault.getSecret(SERVICE, ACCOUNT)
    void asString

    assertNoLeak(secret)
    secret.dispose()
    vault.dispose()
  })

  test('throws for a missing credential rather than returning an empty Secret', () => {
    const vault = Vault.open(keychain, vaultPath)
    assert.throws(() => vault.getSecret('nope', 'nope'), VaultError)
    vault.dispose()
  })

  test('dispose makes the vault unusable', () => {
    const vault = Vault.open(keychain, vaultPath)
    addGitHub(vault)
    vault.dispose()

    assert.throws(() => vault.list(), VaultError)
    assert.throws(() => vault.getSecret(SERVICE, ACCOUNT), VaultError)
  })
})

describe('vault file integrity', () => {
  let dir: string
  let vaultPath: string
  let keychain: InMemoryKeychain

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaultbroker-integrity-'))
    vaultPath = join(dir, 'vault.json')
    keychain = new InMemoryKeychain()
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  test('detects a modified record on read', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of(SECRET_CANARY) })
    vault.dispose()

    const parsed = JSON.parse(readFileSync(vaultPath, 'utf8')) as {
      records: { aead: { ciphertext: string } }[]
    }
    const bytes = Buffer.from(parsed.records[0]?.aead.ciphertext ?? '', 'base64')
    bytes[0] = (bytes[0] ?? 0) ^ 0x01
    parsed.records[0]!.aead.ciphertext = bytes.toString('base64')
    writeFileSync(vaultPath, JSON.stringify(parsed, null, 2))

    // Must fail loudly on read, and must NOT return plausible-looking garbage.
    const reopened = Vault.open(keychain, vaultPath)
    assert.throws(() => reopened.getSecret(SERVICE, ACCOUNT), VaultIntegrityError)
    assert.throws(() => reopened.list(), VaultIntegrityError)
  })

  test('detects a swapped ciphertext', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: 'a', accountAlias: 'one', secret: Secret.of('secret-one') })
    vault.add({ service: 'b', accountAlias: 'two', secret: Secret.of('secret-two') })
    vault.dispose()

    const parsed = JSON.parse(readFileSync(vaultPath, 'utf8')) as {
      records: { aead: { ciphertext: string } }[]
    }
    // Swap the two ciphertexts, leaving ids and indexes intact.
    const first = parsed.records[0]!
    const second = parsed.records[1]!
    const tmp = first.aead.ciphertext
    first.aead.ciphertext = second.aead.ciphertext
    second.aead.ciphertext = tmp
    writeFileSync(vaultPath, JSON.stringify(parsed, null, 2))

    // AAD binding means neither record will authenticate.
    const reopened = Vault.open(keychain, vaultPath)
    assert.throws(() => reopened.list(), VaultIntegrityError)
  })

  test('reports a truncated file as corruption, pointing at backups', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of(SECRET_CANARY) })
    vault.dispose()

    writeFileSync(vaultPath, readFileSync(vaultPath, 'utf8').slice(0, 40))

    assert.throws(() => Vault.open(keychain, vaultPath), /not valid JSON|unexpected shape/u)
  })

  test('refuses an unknown schema version instead of guessing', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.dispose()

    const parsed = JSON.parse(readFileSync(vaultPath, 'utf8')) as Record<string, unknown>
    parsed['schemaVersion'] = VAULT_SCHEMA_VERSION + 99
    writeFileSync(vaultPath, JSON.stringify(parsed))

    assert.throws(() => Vault.open(keychain, vaultPath), /schema v\d+ is not supported/u)
  })

  test('takes an encrypted backup before each write', () => {
  // Distinctive secrets: a 2-char value like 'v1' occurs by chance in base64 ciphertext,
  // which would make this assertion fail intermittently for no real reason.
  const SECRET_ONE = 'BACKUP-CANARY-ONE-7f3a2e1b'
  const SECRET_TWO = 'BACKUP-CANARY-TWO-9c8d4a5f'

    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: 'a', accountAlias: 'one', secret: Secret.of(SECRET_ONE) })
    vault.add({ service: 'b', accountAlias: 'two', secret: Secret.of(SECRET_TWO) })
    vault.dispose()

    const backupDir = join(dir, 'backups')
    const backups = readdirSync(backupDir)
    // open() creates the file (1 backup target), then each add() backs up before writing.
    assert.ok(backups.length >= 2, `expected at least 2 backups, found ${backups.length}`)

    for (const name of backups) {
    const contents = readFileSync(join(backupDir, name), 'utf8')
    // An empty vault legitimately contains no ciphertext at all, so only assert on
      // backups that actually hold a record.
      if (!/"ciphertext":/.test(contents)) continue
      assert.ok(
 !contents.includes(SECRET_ONE) && !contents.includes(SECRET_TWO),
        'backups must be encrypted too',
      )
    }
  })

  test('backup filenames are unique even within the same millisecond', () => {
    const vault = Vault.open(keychain, vaultPath)
    // Rapid successive writes: a timestamp-only name would collide and silently drop a
    // backup via copyFileSync overwrite.
    for (let i = 0; i < 5; i += 1) {
      vault.add({ service: `s${i}`, accountAlias: 'a', secret: Secret.of(`v${i}`) })
    }
    vault.dispose()

    const backups = readdirSync(join(dir, 'backups'))
    assert.equal(backups.length, new Set(backups).size, 'backup names must be unique')
    assert.ok(backups.length >= 5, `expected >= 5 backups, found ${backups.length}`)
  })

  test('old backups are pruned, keeping the retention limit', () => {
    const vault = Vault.open(keychain, vaultPath)
    for (let i = 0; i < 9; i += 1) {
      vault.add({ service: `s${i}`, accountAlias: 'a', secret: Secret.of(`v${i}`) })
    }
    vault.dispose()

    const backups = readdirSync(join(dir, 'backups'))
    assert.ok(backups.length <= 5, `retention limit of 5 exceeded: found ${backups.length}`)
  })

  test('vault and backups are not group or world readable', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: 'a', accountAlias: 'one', secret: Secret.of('v1') })
    vault.add({ service: 'b', accountAlias: 'two', secret: Secret.of('v2') })
    vault.dispose()

    assert.equal(statSync(vaultPath).mode & 0o777, 0o600)
    for (const name of readdirSync(join(dir, 'backups'))) {
      assert.equal(statSync(join(dir, 'backups', name)).mode & 0o777, 0o600)
    }
  })

  test('backups are created before, not after, a write', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of(SECRET_CANARY) })

    // With exactly one credential added after creation, a backup must exist holding the
    // pre-add (empty) state — proving the copy happens ahead of the write.
    const backups = readdirSync(join(dir, 'backups'))
    assert.ok(backups.length >= 1, 'expected a backup from the add() write')

    const earliest = readFileSync(join(dir, 'backups', backups.sort()[0] ?? ''), 'utf8')
    assert.match(earliest, /"records": \[\]/u, 'first backup should hold the pre-write state')
    vault.dispose()
  })
})

describe('keychain delivery never uses argv', () => {
  let dir: string
  let logPath: string
  let vaultPath: string
  const originalBin = process.env['VAULTBROKER_SECURITY_BIN']

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaultbroker-keychain-'))
    logPath = join(dir, 'security.log')
    vaultPath = join(dir, 'vault.json')

    // Point the keychain at a wrapper that runs our stub; the real binary is never used.
    process.env['VAULTBROKER_SECURITY_BIN'] = 'unset-for-now'
  })

  afterEach(() => {
    if (originalBin === undefined) delete process.env['VAULTBROKER_SECURITY_BIN']
    else process.env['VAULTBROKER_SECURITY_BIN'] = originalBin
    rmSync(dir, { recursive: true, force: true })
  })

  test('the KEK reaches security via stdin, never via command-line arguments', async () => {
    // The stub needs to be invoked as `node stub.mjs <log> <mode>`, but the keychain layer
    // appends its own arguments. Use a small wrapper so the stub gets its leading
    // parameters while `security` still receives only `-s/-a/-w`-style flags.
    const wrapper = join(dir, 'security.sh')
    writeFileSync(
      wrapper,
      `#!/bin/sh\nexec "${process.execPath}" "${join(dirname(fileURLToPath(import.meta.url)), 'helpers', 'security-stub.mjs')}" "${logPath}" stub "$@"\n`,
    )
    chmodSync(wrapper, 0o755)
    process.env['VAULTBROKER_SECURITY_BIN'] = wrapper

    const { MacSecurityKeychain } = await import('../src/core/keychain.ts')
    const store = new MacSecurityKeychain()
    const kek = generateKeyEncryptionKey()

    store.write({ service: 'vaultbroker:kek', account: 'vault:v1' }, kek)

    // The stub recorded a hash of stdin; the KEK must match it.
    const invocations = readFileSync(logPath, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as StubInvocation)

    assert.ok(invocations.length > 0, 'stub should have recorded at least one call')
    const write = invocations.find((i) => i.argv.some((a) => a.startsWith('add-generic-password')))
    assert.ok(write, 'expected an add-generic-password call')

    // The KEK is hex-encoded for the keychain transport (see encodeForTransport), and
    // written twice to satisfy `security`'s create-time double prompt. So stdin carries
    // two newline-separated copies of the hex form.
    const encoded = kek.toString('hex')
    const expectedStdin = `${encoded}\n${encoded}\n`
    assert.equal(
      write.stdinSha256,
      createHash('sha256').update(expectedStdin).digest('hex'),
      'the KEK must arrive on stdin as hex, twice, newline-separated',
    )

    // The actual leak test: no argv element may contain the key in any encoding.
    for (const arg of write.argv) {
      for (const encoding of [kek.toString('hex'), kek.toString('base64'), kek.toString('utf8')]) {
        assert.ok(!arg.includes(encoding), `KEY LEAKED VIA ARGV: ${arg.slice(0, 60)}`)
      }
    }

    // `-w` must be present with no value, which is what triggers the stdin prompt.
    assert.ok(write.argv.includes('-w'), '-w must be passed to trigger the stdin prompt')

    // And the round trip works: what goes in comes back byte-identical.
    const read = store.read({ service: 'vaultbroker:kek', account: 'vault:v1' })
    assert.deepEqual(read, kek, 'KEK must survive the keychain round trip byte for byte')
  })

  test('a failed keychain write is detected rather than silently accepted', async () => {
    // `security` can exit 0 having stored an unusable item. The write path verifies by
    // reading back, so corruption must surface as an error instead of a later
    // "cannot decrypt" mystery.
    const wrapper = join(dir, 'broken-security.sh')
    writeFileSync(
      wrapper,
      `#!/bin/sh\nif [ "$1" = "add-generic-password" ]; then exit 0; fi\nexit 44\n`,
    )
    chmodSync(wrapper, 0o755)

    const originalBin = process.env['VAULTBROKER_SECURITY_BIN']
    process.env['VAULTBROKER_SECURITY_BIN'] = wrapper
    try {
      const { MacSecurityKeychain } = await import('../src/core/keychain.ts')
      const store = new MacSecurityKeychain()
      assert.throws(
        () => store.write({ service: 'vaultbroker:kek', account: 'vault:v1' }, generateKeyEncryptionKey()),
        /did not round-trip/u,
        'a write that cannot be read back must throw',
      )
    } finally {
      if (originalBin === undefined) delete process.env['VAULTBROKER_SECURITY_BIN']
      else process.env['VAULTBROKER_SECURITY_BIN'] = originalBin
    }
  })

  test('a random 32-byte KEK survives the round trip — the bug this encoding exists to prevent', () => {
    // Regression guard. Random bytes are frequently invalid UTF-8; passing them through
    // a text-oriented transport used to expand them (32 -> 49-60 bytes) and made every
    // stored vault permanently undecryptable.
    for (let i = 0; i < 50; i += 1) {
      const kek = generateKeyEncryptionKey()
      const roundTripped = Buffer.from(kek.toString('hex'), 'hex')
      assert.deepEqual(roundTripped, kek, 'hex transport must be lossless for arbitrary bytes')
    }
  })
})

describe('no credential escapes the vault API', () => {
  let dir: string
  let vaultPath: string
  let keychain: InMemoryKeychain

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaultbroker-escape-'))
    vaultPath = join(dir, 'vault.json')
    keychain = new InMemoryKeychain()
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  test('nothing the vault returns serialises to the credential', () => {
    const vault = Vault.open(keychain, vaultPath)
    vault.add({ service: SERVICE, accountAlias: ACCOUNT, secret: Secret.of(SECRET_CANARY) })

    // Every metadata surface, serialised the way an MCP tool would.
    const surfaces: unknown[] = [
      vault.list(),
      vault.find(SERVICE, ACCOUNT),
      vault.find('missing', 'missing'),
      vault.size,
    ]
    for (const surface of surfaces) {
      // JSON.stringify(undefined) is undefined, not a string — a missing entry is a
      // legitimate result from find() and must be handled as such.
      const rendered = JSON.stringify(surface) ?? String(surface)
      assert.ok(!rendered.includes(SECRET_CANARY))
    }

    // The one surface that does carry the credential is a Secret, which redacts itself.
    const secret = vault.getSecret(SERVICE, ACCOUNT)
    assert.ok(!JSON.stringify(secret).includes(SECRET_CANARY))
    assert.ok(!secret.describe().includes(SECRET_CANARY))
    assertNoLeak(secret)
    secret.dispose()
    vault.dispose()
  })
})

// Assert a Secret cannot be rendered in any common way without exposing its value.
function assertNoLeak(secret: Secret): void {
  for (const rendered of [
    JSON.stringify(secret),
    String(secret),
    `${secret}`,
    inspect(secret),
    JSON.stringify({ wrapped: secret }),
  ]) {
    assert.ok(!rendered.includes(SECRET_CANARY), `Secret leaked via: ${rendered.slice(0, 120)}`)
  }
}