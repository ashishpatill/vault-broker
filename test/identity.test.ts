/**
 * Client identity tests.
 *
 * The claim under test: a harness's grant is bound to what its binary *is*, so replacing,
 * re-signing or tampering with that binary is refused — not just at registration, but on
 * every subsequent connection.
 *
 * Real signed binaries on this machine are used where possible (Cursor, OpenCode and Codex
 * are installed and notarised). Tamper cases use a stub `codesign` so the tests can
 * simulate a re-signed or modified binary without needing to corrupt a real install.
 */

import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, test } from 'node:test'

import { AuditLog } from '../src/core/audit.ts'
import { PolicyEngine } from '../src/core/policy.ts'
import { HOME_ENV_VAR } from '../src/core/runtime-paths.ts'
import { ClientRegistry } from '../src/install/registry.ts'
import { detectHarnesses, mainExecutable } from '../src/install/detect.ts'
import {
  describeIdentity,
  inspectProcess,
  inspectSignature,
  processLooksLike,
  verifyIdentity,
  type ClientRegistration,
  type CodeSignatureIdentity,
} from '../src/install/identity.ts'

const originalHome = process.env[HOME_ENV_VAR]
let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vaultbroker-identity-'))
  process.env[HOME_ENV_VAR] = dir
})

afterEach(() => {
  if (originalHome === undefined) delete process.env[HOME_ENV_VAR]
  else process.env[HOME_ENV_VAR] = originalHome
  delete process.env['VAULTBROKER_CODESIGN_BIN']
  rmSync(dir, { recursive: true, force: true })
})

/** A plausible signed identity, so tests can mutate one field at a time. */
function fakeIdentity(overrides: Partial<CodeSignatureIdentity> = {}): CodeSignatureIdentity {
  return Object.freeze({
    identifier: 'com.example.harness',
    teamId: 'ABCDE12345',
    authorities: Object.freeze(['Developer ID Application: Example Inc (ABCDE12345)']),
    notarized: true,
    signatureValid: true,
    designatedRequirement: 'anchor apple generic and certificate leaf[subject.OU] = ABCDE12345',
    contentHash: 'aaaa1111bbbb2222cccc3333dddd4444',
    path: '/Applications/Example.app/Contents/MacOS/Example',
    ...overrides,
  })
}

function fakeRegistration(identity = fakeIdentity()): ClientRegistration {
  return Object.freeze({
    clientId: 'cursor',
    label: 'Example',
    identity,
    registeredAt: new Date().toISOString(),
  })
}

describe('identity inspection against real installed harnesses', () => {
  const harnesses = detectHarnesses()

  test('finds the harnesses installed on this machine', () => {
    // Not asserting a specific list: the point is that detection reports what it actually
    // found rather than assuming a fixed environment.
    assert.ok(harnesses.length > 0, 'expected at least one harness to be detected')
    for (const harness of harnesses) {
      assert.ok(harness.path.startsWith('/'), `expected an absolute path for ${harness.client}`)
    }
  })

  test('reads a real code signature rather than silently returning empty fields', () => {
    // Regression guard for the execFileSync bug: `codesign -dv` writes to stderr and
    // exits 0, so returning stdout alone yielded empty identities that still looked
    // "valid" — a security check that quietly verified nothing.
    const target = harnesses.find((h) => h.client === 'cursor')?.path
    if (target === undefined) {
      // Cursor is not installed on this machine; the stub-based tests below still apply.
      return
    }

    const identity = inspectSignature(mainExecutable(target))

    assert.ok(identity.teamId !== null, 'teamId must be parsed from the real signature')
    assert.ok((identity.teamId ?? '').length > 0)
    assert.ok(identity.identifier !== null, 'identifier must be parsed')
    assert.ok(identity.contentHash !== null, 'contentHash must be captured')
    assert.ok(identity.designatedRequirement !== null, 'designated requirement must be extracted')
    assert.ok(identity.authorities.length > 0, 'authority chain must be captured')
    assert.equal(identity.signatureValid, true)
  })

  test('resolves to the executable inside a bundle, not the bundle directory', () => {
    const app = harnesses.find((h) => h.path.endsWith('.app'))
    if (app === undefined) return

    const executable = mainExecutable(app.path)
    assert.ok(executable.startsWith(app.path), 'executable must live inside the bundle')
    assert.match(executable, /\/Contents\/MacOS\//u)
  })
})

describe('identity verification', () => {
  test('accepts an unchanged binary', () => {
    const registration = fakeRegistration()
    assert.equal(verifyIdentity(registration, registration.identity).ok, true)
  })

  test('refuses a changed team id', () => {
    const registration = fakeRegistration()
    const verdict = verifyIdentity(registration, fakeIdentity({ teamId: 'ZZZZZ99999' }))

    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.reason, 'team-changed')
  })

  test('refuses a changed content hash', () => {
    const registration = fakeRegistration()
    const verdict = verifyIdentity(registration, fakeIdentity({ contentHash: 'dead9999beef0000' }))

    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.reason, 'content-changed')
  })

  test('refuses a re-signed binary via a changed designated requirement', () => {
    const registration = fakeRegistration()
    const verdict = verifyIdentity(
      registration,
      fakeIdentity({ designatedRequirement: 'identifier "com.attacker.tool" and anchor apple generic' }),
    )

    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.reason, 'requirement-changed')
  })

  test('refuses a binary whose signature is no longer valid', () => {
    // The tamper case on Apple silicon: modifying signed code invalidates the signature.
    const registration = fakeRegistration()
    const verdict = verifyIdentity(registration, fakeIdentity({ signatureValid: false }))

    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.reason, 'signature-invalid')
  })

  test('does not refuse a legitimately unsigned-but-signed CLI', () => {
    // The real Claude Code binary on this machine is Developer ID signed but not
    // notarized. A blanket notarization requirement would block a legitimate harness,
    // and a rule that gets turned off protects nothing.
    const registration = fakeRegistration(fakeIdentity({ notarized: false }))
    const verdict = verifyIdentity(registration, fakeIdentity({ notarized: false }))

    assert.equal(verdict.ok, true, 'notarization is compared against registration, not required absolutely')
  })

  test('refuses a binary that lost notarization after registration', () => {
    const registration = fakeRegistration(fakeIdentity({ notarized: true }))
    const verdict = verifyIdentity(registration, fakeIdentity({ notarized: false }))

    assert.equal(verdict.ok, false)
    assert.equal(verdict.ok === false && verdict.reason, 'not-notarized')
  })
})

describe('containment on mismatch', () => {
  /**
   * A registry pre-seeded with a registration.
   *
   * Seeding directly is what makes these tests independent of which harnesses happen to
   * be installed: `verify()` re-inspects the live path and compares, so pointing it at a
   * missing path reaches the containment path without needing a real signed binary.
   */
  function harness(seeded = true) {
    const policy = new PolicyEngine({ audit: new AuditLog() })
    const notifications: string[] = []
    let vaultLocked = 0

    const registry = new ClientRegistry({
      policy,
      lockVault: (): void => {
        vaultLocked += 1
      },
      notify: (message: string): void => {
        notifications.push(message)
      },
      ...(seeded ? { registrations: [fakeRegistration()] } : {}),
    })

    return {
      policy,
      registry,
      notifications,
      vaultLocked: (): number => vaultLocked,
    }
  }

  test('refuses an unregistered client without locking the vault', () => {
    const h = harness(false)
    const outcome = h.registry.verify('cursor', '/Applications/Example.app')

    assert.equal(outcome.allowed, false)
    assert.equal(outcome.reason, 'unregistered-client')
    assert.equal(outcome.vaultLocked, false, 'an unknown client is not evidence of tampering')
  })

  test('refuses to register a binary that is not correctly signed', () => {
    const h = harness()
    const unsigned = join(dir, 'unsigned-tool')
    writeFileSync(unsigned, '#!/bin/sh\necho hi\n')

    // Registering an unverifiable binary would create the appearance of verification.
    assert.throws(() => h.registry.register('cursor', 'Unsigned', unsigned), /not correctly code-signed/u)
  })

  test('a mismatch revokes every grant, locks the vault, and notifies', () => {
    const h = harness()

    // Seed two grants for the client under test.
    h.policy.grant({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operations: ['github.repo.read'],
      projectPath: '/tmp/proj',
      ttlMinutes: 60,
    })
    h.policy.grant({
      clientId: 'cursor',
      service: 'neon',
      accountAlias: 'other',
      operations: ['neon.project.read'],
      projectPath: '/tmp/proj',
      ttlMinutes: 60,
    })
    assert.equal(h.policy.active().length, 2)

    // Force a verification failure by pointing at a path that does not resolve.
    const outcome = h.registry.verify('cursor', join(dir, 'gone', 'not-here'))

    assert.equal(outcome.allowed, false)
    assert.equal(outcome.vaultLocked, true, 'vault must be locked on containment')
    assert.equal(h.vaultLocked(), 1)
    assert.equal(h.policy.active().length, 0, 'every grant for the client must be revoked')
    assert.equal(h.notifications.length, 1, 'the user must be told — a silent refusal is a free retry')
    assert.match(h.notifications[0] ?? '', /grant\(s\) revoked/u)
  })

  test('writes a critical audit event naming the reason', () => {
    const h = harness()
    h.registry.verify('cursor', join(dir, 'missing'))

    // This is the *mismatch* path (the registry is seeded), so the event is the
    // critical one, not the milder "unknown client" warning.
    const events = h.policy.audit.byKind('client.identity-mismatch')
    assert.equal(events.length, 1)
    assert.equal(events[0]?.severity, 'critical')
    assert.equal(events[0]?.clientId, 'cursor')
    assert.equal(events[0]?.decision, 'denied')
    assert.ok(events[0]?.reason !== null, 'the specific reason must be recorded')
  })

test('an unknown client is a warning, not treated as tampering', () => {
    const h = harness(false)
    h.registry.verify('cursor', '/Applications/Example.app')

    assert.equal(h.policy.audit.byKind('client.unknown').length, 1)
    assert.equal(h.policy.audit.byKind('client.identity-mismatch').length, 0)
    assert.equal(
      h.vaultLocked(),
      0,
      'locking the vault because a client is unregistered would be a trivial DoS',
    )
  })

  test('containment survives a failing vault lock and still notifies', () => {
    const policy = new PolicyEngine({ audit: new AuditLog() })
    const notifications: string[] = []

    const registry = new ClientRegistry({
      policy,
      lockVault: (): never => {
        throw new Error('lock failed')
      },
      notify: (message: string): void => {
        notifications.push(message)
      },
      registrations: [fakeRegistration()],
    })

    policy.grant({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operations: ['github.repo.read'],
      projectPath: '/tmp/proj',
      ttlMinutes: 60,
    })

    const outcome = registry.verify('cursor', join(dir, 'missing'))

    // The grant is revoked and the user is warned even though the lock failed — the
    // ordering is chosen so a failure late in containment cannot leave live grants.
    assert.equal(outcome.allowed, false)
    assert.equal(outcome.vaultLocked, false)
    assert.equal(policy.active().length, 0)
    assert.equal(notifications.length, 1)
    assert.match(notifications[0] ?? '', /could NOT be locked/u)
  })

  test('unregistering a client revokes its grants', () => {
    const h = harness()
    h.policy.grant({
      clientId: 'cursor',
      service: 'github',
      accountAlias: 'work',
      operations: ['github.repo.read'],
      projectPath: '/tmp/proj',
      ttlMinutes: 60,
    })

    assert.equal(h.registry.unregister('cursor'), true)
    assert.equal(h.policy.active().length, 0)
    assert.equal(h.registry.unregister('cursor'), false)
  })
})

describe('parent process check (best-effort)', () => {
  test('reports a real process', () => {
    const info = inspectProcess(process.pid)
    assert.ok(info !== undefined, 'expected to inspect our own pid')
    assert.equal(info.pid, process.pid)
  })

  test('returns undefined for a pid that does not exist', () => {
    // 2^22 is above the default pid_max on macOS.
    assert.equal(inspectProcess(4194303), undefined)
  })

  test('matches a process inside a registered bundle', () => {
    const registration = fakeRegistration(
      fakeIdentity({ path: '/Applications/Example.app/Contents/MacOS/Example' }),
    )

    assert.equal(
      processLooksLike({ pid: 1, executablePath: '/Applications/Example.app/Contents/Frameworks/Helper', command: '' }, registration),
      true,
      'an Electron helper inside the bundle should match',
    )
    assert.equal(
      processLooksLike({ pid: 1, executablePath: '/usr/local/bin/evil', command: '' }, registration),
      false,
    )
    assert.equal(processLooksLike(undefined, registration), false)
  })

  test('kernel peer-credential verification is genuinely unavailable, not stubbed', async () => {
    // `peerCredentials()` in src/daemon/server.ts is the seam where definitive uid/pid
    // verification lands in v0.2. Today it must return undefined. Asserted against the
    // real function, so a stub that *claims* to verify fails this test rather than
    // quietly satisfying it.
    const { peerCredentials } = await import('../src/daemon/server.ts')
    assert.equal(
      peerCredentials({} as never),
      undefined,
      'peerCredentials() must not claim to verify identity before v0.2 implements it',
    )
  })
})

describe('identity rendering', () => {
  test('describes an identity without secrets', () => {
    const text = describeIdentity(fakeIdentity())
    assert.match(text, /ABCDE12345/u)
    assert.match(text, /Notarized:\s+yes/u)
  })
})