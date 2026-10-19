/**
 * End-to-end call_api tests: policy decision, secret scoping and the response surface.
 *
 * Drives `Session.handle` directly, with a stub adapter in place of the network, so every
 * unencrypted byte the daemon emits is observable. The invariant under test: the
 * credential is spent on the outbound request and appears in *no* response — allowed,
 * denied or failed.
 */

import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, test } from 'node:test'

import type { Adapter, AdapterRequest } from '../src/adapters/registry.ts'
import { AdapterError, AdapterRegistry } from '../src/adapters/registry.ts'
import { AuditLog } from '../src/core/audit.ts'
import { InMemoryKeychain } from '../src/core/keychain.ts'
import { createLogger } from '../src/core/logging.ts'
import type { Operation } from '../src/core/operations.ts'
import { PolicyEngine } from '../src/core/policy.ts'
import { Secret } from '../src/core/secret.ts'
import { buildRequest } from '../src/daemon/protocol.ts'
import { Session } from '../src/daemon/session.ts'
import { Vault } from '../src/core/vault.ts'
import { TOOL_DEFINITIONS, TOOL_NAMES } from '../src/shim/tools.ts'

createLogger('callapi')

/** A token that exists only inside this suite. Deliberately not a real credential shape. */
const FAKE_TOKEN = 'vbrk-suite-token-0123456789'

/** A canned github.repo.read response. No credential material, by construction. */
const CANNED_REPO = { id: 123456, name: 'acme', full_name: 'owner/acme', private: false }

/**
 * Adapter stub standing in for the provider.
 *
 * Records what the credential spend produced, so the suite can assert that the plaintext
 * reached the outbound header and nowhere else. Failing applies where the suite drives
 * the error path deliberately.
 */
function makeStubAdapter(spendLog: string[], behaviour: 'ok' | 'fail' = 'ok'): Adapter {
  const adapter: Adapter = {
    service: 'github',
    operations: ['github.repo.read', 'github.repo.list'],
    allowedHosts: [],
    async execute(request: AdapterRequest, secret: Secret): Promise<unknown> {
      return await secret.withHeaders(async (headers): Promise<unknown> => {
        // Byte-for-byte what a real outbound request would carry. Appending the header
        // value to an in-memory array is the point: the test must observe the spend.
        spendLog.push(headers.get('Authorization') ?? '')
        if (behaviour === 'fail') {
          throw new AdapterError('upstream-error', 'github GET /repos failed with HTTP 500')
        }
        return { ...CANNED_REPO, operation: request.operation }
      })
    },
  }
  return adapter
}

describe('call_api end to end', () => {
  const scratch: string[] = []
  const spendLog: string[] = []

  afterEach(() => {
    spendLog.length = 0
    while (scratch.length > 0) {
      const dir = scratch.pop()
      if (dir !== undefined) rmSync(dir, { recursive: true, force: true })
    }
  })

  /** Build a session over a fresh in-memory vault holding the suite's fake token. */
  function makeSession(behaviour: 'ok' | 'fail' = 'ok'): { session: Session; policy: PolicyEngine } {
    const root = mkdtempSync(join(tmpdir(), 'callapi-'))
    scratch.push(root)

    const vault = Vault.open(new InMemoryKeychain(), join(root, 'vault.json'))
    vault.add({
      service: 'github',
      accountAlias: 'work',
      secret: Secret.of(FAKE_TOKEN),
      secretType: 'bearer',
    })

    const registry = new AdapterRegistry()
    registry.register(makeStubAdapter(spendLog, behaviour))

    const policy = new PolicyEngine({ audit: new AuditLog() })
    const session = new Session(vault, { policy, adapters: registry })
    return { session, policy }
  }

  interface DriveResult {
    ok: boolean
    result?: unknown
    error?: { code: string; message: string }
  }

  /** The call_api result shape, as the shim consumes it. */
  interface CallOutcome {
    allowed?: boolean
    reason?: string
    message?: string
    auditEventId?: string
    result?: unknown
  }

  async function drive(session: Session, params: Record<string, unknown>): Promise<DriveResult> {
    const frame = buildRequest('test', 'call_api', params)
    return (await session.handle(frame, '/does/not/matter')) as DriveResult
  }

  /** Narrow an untyped response payload once, at the boundary. */
  function outcome(result: unknown): CallOutcome {
    return (result ?? {}) as CallOutcome
  }

  /** One approved, working call. The denial tests below mutate single fields around this. */
  function makeGrant(policy: PolicyEngine, projectPath: string): string {
    const capability = policy.grant({
      clientId: 'test',
      service: 'github',
      accountAlias: 'work',
      operations: ['github.repo.read', 'github.repo.list'] as Operation[],
      projectPath,
      ttlMinutes: 60,
      auditHead: policy.audit.head,
    })
    return capability.id
  }

  test('an allowed call returns a projection and leaks nothing', async () => {
    const { session, policy } = makeSession()

    const projectPath = '/Users/tester/src/acme'
    const capabilityId = makeGrant(policy, projectPath)

    const response = await drive(session, {
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      capabilityId,
      projectPath,
      params: { owner: 'owner', repo: 'acme' },
    })

    assert.equal(response.ok, true)
    const view = outcome(response.result)
    assert.equal(view.allowed, true)
    const payload = (view.result ?? {}) as { full_name?: string }
    assert.equal(payload['full_name'], 'owner/acme')

    // The credential must appear in the outbound request and never in the response.
    assert.equal(spendLog.length, 1)
    assert.ok(spendLog[0]?.endsWith(FAKE_TOKEN))
    const wire = JSON.stringify(response)
    assert.ok(!wire.includes(FAKE_TOKEN), 'response carries the credential')
  })

  test('a denied request never spends the credential', async () => {
    const { session, policy } = makeSession()

    const projectPath = '/Users/tester/src/acme'
    const capabilityId = makeGrant(policy, projectPath)

    const wrongAccount = await drive(session, {
      service: 'github',
      accountAlias: 'personal',
      operation: 'github.repo.read',
      capabilityId,
      projectPath,
      params: { owner: 'owner', repo: 'acme' },
    })
    assert.equal(wrongAccount.ok, true)
    const denied = outcome(wrongAccount.result)
    assert.equal(denied.allowed, false)
    assert.equal(denied.reason, 'operation-not-granted')

    const wrongProject = await drive(session, {
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      capabilityId,
      projectPath: '/Users/tester/src/other',
      params: { owner: 'owner', repo: 'acme' },
    })
    assert.equal(outcome(wrongProject.result).allowed, false)

    const ungranted = await drive(session, {
      service: 'github',
      accountAlias: 'work',
      operation: 'github.issue.read',
      capabilityId,
      projectPath,
      params: { owner: 'owner', repo: 'acme' },
    })
    assert.equal(outcome(ungranted.result).allowed, false)

    assert.deepEqual(spendLog, [], 'denied paths must not touch the credential')
  })

  test('a replayed grant is refused', async () => {
    const { session, policy } = makeSession()

    const projectPath = '/Users/tester/src/acme'
    const capabilityId = makeGrant(policy, projectPath)
    const base = {
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read' as string,
      capabilityId,
      projectPath,
      params: { owner: 'owner', repo: 'acme' },
    }

    const first = await drive(session, base)
    assert.equal(first.ok, true)

    const second = await drive(session, base)
    assert.equal(second.ok, true)
    assert.equal(outcome(second.result).allowed, false)

    // One spend per grant: the nonce-use rules make a second use impossible.
    assert.equal(spendLog.length, 1)
    assert.equal(outcome(second.result).reason, 'nonce-replayed')
  })

  test('an unknown service fails closed with a coarse error', async () => {
    const { session, policy } = makeSession()

    const projectPath = '/Users/tester/src/nowhere'
    const capabilityId = makeGrant(policy, projectPath)

    const response = await drive(session, {
      service: 'not-github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      capabilityId,
      projectPath,
      params: {},
    })

    // The policy engine denies first: no grant was minted for not-github.
    assert.equal(outcome(response.result).allowed, false)
    assert.equal(spendLog.length, 0)
  })

  test('an upstream failure surfaces a coarse error and no credential', async () => {
    const { session, policy } = makeSession('fail')

    const projectPath = '/Users/tester/src/acme'
    const capabilityId = makeGrant(policy, projectPath)

    const response = await drive(session, {
      service: 'github',
      accountAlias: 'work',
      operation: 'github.repo.read',
      capabilityId,
      projectPath,
      params: { owner: 'owner', repo: 'acme' },
    })

    assert.equal(response.ok, false)
    assert.equal(response.error?.code, 'UPSTREAM_ERROR')
    // The stub spent exactly once, inside the header callback that has since ended.
    assert.equal(spendLog.length, 1)
    const wire = JSON.stringify(response)
    assert.ok(!wire.includes(FAKE_TOKEN), 'error response carries the credential')
  })

  test('the tool surface has no credential-returning tool', () => {
    const names = TOOL_DEFINITIONS.map((tool) => tool.name)
    assert.ok(names.includes(TOOL_NAMES.callApi))
    for (const forbidden of ['get_secret', 'show_secret', 'reveal_secret']) {
      assert.ok(!names.includes(forbidden as never), `forbidden tool name present: ${forbidden}`)
    }

    const description = TOOL_DEFINITIONS.find((tool) => tool.name === TOOL_NAMES.callApi)?.description ?? ''
    assert.ok(/never/i.test(description), 'call_api must state the credential is never returned')
  })
})
