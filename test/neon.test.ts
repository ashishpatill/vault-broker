/**
 * Neon adapter tests.
 *
 * Mirrors test/adapter.test.ts deliberately: the same local stub server, the same
 * assertions about the credential, the same fail-closed rules. The invariant under test
 * is that only the allowlisted fields leave the response, and the token appears nowhere —
 * allowed or failed.
 */

import { strict as assert } from 'node:assert'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { after, before, beforeEach, describe, test } from 'node:test'

import { Secret } from '../src/core/secret.ts'
import type { Adapter } from '../src/adapters/registry.ts'
import { AdapterError } from '../src/adapters/registry.ts'
import {
  buildNeonRequest,
  createNeonAdapter,
  NEON_OPERATIONS,
  NEON_UNIMPLEMENTED,
} from '../src/adapters/neon.ts'
import { assertKnownOperation } from '../src/core/operations.ts'

const TOKEN = 'napi_TESTTOKENabcdefghijklmnopqrstuvwxyz0123'

let server: Server
let baseUrl: string
/** Every request the stub server received, for assertions. */
let seen: { url: string; method: string; headers: Record<string, unknown> }[] = []
/** Lets a test choose what the next response is. */
let nextResponse: { status: number; body: unknown } = { status: 200, body: {} }

before(async () => {
  server = createServer((req, res) => {
    seen.push({
      url: req.url ?? '',
      method: req.method ?? '',
      headers: req.headers as Record<string, unknown>,
    })

    res.writeHead(nextResponse.status, { 'Content-Type': 'application/json' })
    res.end(typeof nextResponse.body === 'string' ? nextResponse.body : JSON.stringify(nextResponse.body))
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address() as AddressInfo
  baseUrl = `http://127.0.0.1:${String(address.port)}/`
})

after(async () => {
  // closeAllConnections() before close(): fetch() keeps sockets alive, and close() on its
  // own waits for them to drain, which hangs the run rather than failing it.
  server.closeAllConnections()
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

beforeEach(() => {
  seen = []
  nextResponse = { status: 200, body: {} }
})

/** An adapter pointed at the local stub, with the host allowlist narrowed to it. */
function localNeonAdapter(): Adapter {
  const host = new URL(baseUrl).host
  return createNeonAdapter({ baseUrl, allowedHosts: [host] })
}

const adapterFor = (): Adapter => localNeonAdapter()

describe('neon catalogue integrity', () => {
  test('implemented operations are catalogued with plausible tiers', () => {
    for (const operation of NEON_OPERATIONS) {
      assertKnownOperation(operation)
    }
    for (const operation of NEON_UNIMPLEMENTED) {
      assertKnownOperation(operation)
    }
  })

  test('implemented and unimplemented sets are disjoint', () => {
    for (const op of NEON_OPERATIONS) {
      assert.ok(!NEON_UNIMPLEMENTED.includes(op), `${op} is in both lists`)
    }
  })

  test('implemented operations are all reads if the catalogue is ever widened', () => {
    // v0 ships only GET paths on this adapter; a write tier arriving here silently would
    // bypass the fresh-approval review that every write deserves.
    for (const [op, params] of [
      ['neon.project.list', {}],
      ['neon.project.read', { projectId: 'ep-dark-leaf-123456' }],
      ['neon.branch.list', { projectId: 'ep-dark-leaf-123456' }],
    ] as const) {
      assert.equal(buildNeonRequest(op, params).method, 'GET', `${op} must remain a GET for v0`)
    }
  })
})

describe('neon path and parameter validation', () => {
  test('builds expected paths for read operations', () => {
    assert.deepEqual(buildNeonRequest('neon.project.list', {}), { path: 'projects', method: 'GET' })

    assert.deepEqual(buildNeonRequest('neon.project.read', { projectId: 'ep-dark-leaf-123456' }), {
      path: 'projects/ep-dark-leaf-123456',
      method: 'GET',
    })

    assert.deepEqual(buildNeonRequest('neon.branch.list', { projectId: 'ep-dark-leaf-123456' }), {
      path: 'projects/ep-dark-leaf-123456/branches',
      method: 'GET',
    })
  })

  test('rejects traversal and injection attempts in projectId', () => {
    const attacks = [
      '../../api.keys',
      '..',
      '%2e%2e%2fadmin',
      'projects/../../other/x',
      '',
      'a b',
    ]
    for (const attack of attacks) {
      assert.throws(
        () => buildNeonRequest('neon.project.read', { projectId: attack }),
        AdapterError,
        `expected rejection of ${JSON.stringify(attack)}`,
      )
    }
  })
})

describe('neon request execution', () => {
  test('project.list returns only allowlisted fields, wrapped list navigated once', async () => {
    nextResponse = {
      status: 200,
      body: {
        projects: [
          {
            id: 'ep-dark-leaf-1',
            name: 'acme',
            pg_version: '17',
            region_id: 'aws-us-east-1',
            created_at: '2026-10-01T00:00:00Z',
            org_id: 'org-secret-value',
            store_password: true,
            connection_uris: ['postgresql://user:secret@host/db'],
          },
        ],
        pagination: { cursor: 'next' },
      },
    }

    const secret = Secret.of(TOKEN)
    const result = (await adapterFor().execute(
      { operation: 'neon.project.list', params: {} },
      secret,
    )) as Record<string, unknown>[]

    assert.equal(result.length, 1)
    assert.deepEqual(result[0], {
      id: 'ep-dark-leaf-1',
      name: 'acme',
      pg_version: '17',
      region_id: 'aws-us-east-1',
      created_at: '2026-10-01T00:00:00Z',
    })
    // Absent allowlisted fields are omitted, not filled with undefined.
    assert.ok(!('updated_at' in (result[0] ?? {})))

    secret.dispose()
  })

  test('sends the bearer token on the header and never in the URL', async () => {
    nextResponse = { status: 200, body: { projects: [] } }

    const secret = Secret.of(TOKEN)
    await adapterFor().execute({ operation: 'neon.project.list', params: {} }, secret)
    secret.dispose()

    assert.equal(seen.length, 1)
    const request = seen[0]
    assert.equal(request?.method, 'GET')
    assert.equal(request?.url, '/projects')
    assert.ok(!String(request?.url).includes(TOKEN), 'the token must never ride in a URL')
    assert.equal(request?.headers['authorization'], `Bearer ${TOKEN}`)
  })

  test('project.read projects nested fields and drops the rest', async () => {
    nextResponse = {
      status: 200,
      body: {
        project: {
          id: 'ep-dark-leaf-1',
          name: 'acme',
          pg_version: '17',
          region_id: 'aws-us-east-1',
          created_at: '2026-10-01T00:00:00Z',
          connection_uris: ['postgresql://user:secret@host/db'],
        },
      },
    }

    const secret = Secret.of(TOKEN)
    const result = (await adapterFor().execute(
      {
        operation: 'neon.project.read',
        params: { projectId: 'ep-dark-leaf-1' },
      },
      secret,
    )) as Record<string, unknown>
    secret.dispose()

    assert.deepEqual(result, {
      'project.id': 'ep-dark-leaf-1',
      'project.name': 'acme',
      'project.pg_version': '17',
      'project.region_id': 'aws-us-east-1',
      'project.created_at': '2026-10-01T00:00:00Z',
    })
  })

  test('branch.list drops last_sql_url and friends', async () => {
    nextResponse = {
      status: 200,
      body: {
        branches: [
          {
            id: 'br-main-1',
            name: 'main',
            project_id: 'ep-dark-leaf-1',
            current_state: 'ready',
            created_at: '2026-10-01T00:00:00Z',
            last_sql_url: 'postgresql://user:secret@host/db',
            connection_uris: ['postgresql://user:secret@host/db'],
          },
        ],
        project_info: { id: 'ep-dark-leaf-1', name: 'acme' },
      },
    }

    const secret = Secret.of(TOKEN)
    const result = (await adapterFor().execute(
      { operation: 'neon.branch.list', params: { projectId: 'ep-dark-leaf-1' } },
      secret,
    )) as Record<string, unknown>[]
    secret.dispose()

    const branch = JSON.stringify(result)
    assert.ok(!branch.includes('last_sql_url'), 'a SQL URL is credential-adjacent and must be dropped')
    assert.ok(!branch.includes('postgresql:'), 'no connection payload may survive projection')
    assert.equal(result[0]?.['name'], 'main')
  })
})

describe('neon fail-closed rules', () => {
  test('an error body never reaches the harness, even when upstream echoes the token', async () => {
    nextResponse = { status: 401, body: { message: `bad token ${TOKEN}` } }

    const secret = Secret.of(TOKEN)
    await assert.rejects(
      adapterFor().execute(
        { operation: 'neon.project.list', params: {} },
        secret,
      ),
      (error: unknown) => {
        assert.ok(error instanceof AdapterError)
        assert.equal((error as AdapterError).kind, 'upstream-error')
        // Coarse: status code only, no body fragment.
        assert.match((error as AdapterError).message, /HTTP 401/u)
        assert.ok(!String((error as AdapterError).message).includes(TOKEN))
        return true
      },
    )
    secret.dispose()
  })

  test('a poisoned 200 response that carries the token is refused wholesale', async () => {
    nextResponse = {
      status: 200,
      body: { projects: [], echo: `credential echo: ${TOKEN}` },
    }

    const secret = Secret.of(TOKEN)
    await assert.rejects(
      adapterFor().execute({ operation: 'neon.project.list', params: {} }, secret),
      (error: unknown) => {
        assert.ok(error instanceof AdapterError)
        assert.equal((error as AdapterError).kind, 'response-leaked-credential')
        return true
      },
    )
    secret.dispose()
  })

  test('an unimplemented operation is unreachable, not a silent empty result', async () => {
    const secret = Secret.of(TOKEN)
    for (const op of NEON_UNIMPLEMENTED) {
      await assert.rejects(
        adapterFor().execute({ operation: op, params: {} }, secret),
        (error: unknown) => {
          assert.ok(error instanceof AdapterError)
          assert.equal((error as AdapterError).kind, 'unknown-operation')
          return true
        },
      )
    }
    secret.dispose()
  })
})

describe('live Neon (skipped without a credential)', () => {
  test(
    'lists projects with a real token when one is available',
    { skip: process.env['NEON_API_TOKEN'] === undefined ? 'no NEON_API_TOKEN in the environment' : false },
    async () => {
      const secret = Secret.fromBuffer(Buffer.from(process.env['NEON_API_TOKEN'] ?? '', 'utf8'))
      const adapter = createNeonAdapter()

      const result = (await adapter.execute(
        { operation: 'neon.project.list', params: {} },
        secret,
      )) as Record<string, unknown>[]

      assert.ok(Array.isArray(result))
      assert.ok(!JSON.stringify(result).includes((process.env['NEON_API_TOKEN'] ?? '').slice(0, 10)))
      secret.dispose()
    },
  )
})
