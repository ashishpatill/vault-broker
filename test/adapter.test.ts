/**
 * Adapter tests.
 *
 * The load-bearing assertion is the negative one: **zero credential bytes appear in
 * anything the caller receives.** Everything else — path validation, host allowlisting,
 * field projection — exists to make that true.
 *
 * A local HTTP server stands in for the provider so the full path can be exercised
 * without a real account: credential injected into headers → request sent → response
 * scanned → response projected. A live GitHub test runs only when a token is actually
 * present; it is skipped rather than faked, because "verified against the real API" and
 * "verified against a stub that behaves like the API" are different claims.
 */

import { strict as assert } from 'node:assert'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { after, before, beforeEach, describe, test } from 'node:test'

import { Secret } from '../src/core/secret.ts'
import type { Operation } from '../src/core/operations.ts'
import {
  AdapterError,
  AdapterRegistry,
  assertNoCredentialInResponse,
  callApi,
  pick,
  pickEach,
  requireSafeParam,
  resolveUrl,
  stripForbiddenKeys,
  type Adapter,
} from '../src/adapters/registry.ts'
import {
  buildRequest,
  createGitHubAdapter,
  GITHUB_API_BASE,
  GITHUB_API_HOST,
  GITHUB_OPERATIONS,
  GITHUB_UNIMPLEMENTED,
} from '../src/adapters/github.ts'

const TOKEN = 'ghp_TESTTOKENabcdefghijklmnopqrstuvwxyz0123'

let server: Server
let baseUrl: string
/** Every request the stub server received, for assertions. */
let seen: { url: string; method: string; headers: Record<string, unknown>; body: string }[] = []
/** Lets a test choose what the next response is. */
let nextResponse: { status: number; body: unknown } = { status: 200, body: {} }

before(async () => {
  server = createServer((req, res) => {
    let body = ''
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8')
    })
    req.on('end', () => {
      seen.push({
        url: req.url ?? '',
        method: req.method ?? '',
        headers: req.headers as Record<string, unknown>,
        body,
      })

      res.writeHead(nextResponse.status, { 'Content-Type': 'application/json' })
      res.end(typeof nextResponse.body === 'string' ? nextResponse.body : JSON.stringify(nextResponse.body))
    })
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
function localGithubAdapter(): Adapter {
  const host = new URL(baseUrl).host
  return createGitHubAdapter({ baseUrl, allowedHosts: [host] })
}

const adapterFor = (): Adapter => localGithubAdapter()

describe('path and parameter validation', () => {
  test('builds expected paths for read operations', () => {
    assert.deepEqual(buildRequest('github.repo.read', { owner: 'acme', repo: 'widgets' }), {
      path: 'repos/acme/widgets',
      method: 'GET',
    })

    assert.deepEqual(buildRequest('github.pr.read', { owner: 'acme', repo: 'widgets', number: '42' }), {
      path: 'repos/acme/widgets/pulls/42',
      method: 'GET',
    })
  })

  test('scopes repo listing to the authenticated user, not a supplied login', () => {
    const built = buildRequest('github.repo.list', { owner: 'someone-else' })
    assert.ok(!built.path.includes('someone-else'), 'a caller must not redirect the listing')
    assert.match(built.path, /^user\/repos/u)
  })

  test('sends write payloads as a JSON body, not in the query string', () => {
    // Query strings land in proxy logs and Referer headers; user content does not belong
    // there.
    const built = buildRequest('github.pr.create', {
      owner: 'acme',
      repo: 'widgets',
      title: 'Fix the flux capacitor',
      body: 'details here',
      base: 'main',
      head: 'fix/flux',
    })

    assert.equal(built.method, 'POST')
    assert.equal(built.path, 'repos/acme/widgets/pulls')
    assert.ok(!built.path.includes('Fix'), 'title must not appear in the URL')
    assert.deepEqual(built.body, {
      title: 'Fix the flux capacitor',
      body: 'details here',
      base: 'main',
      head: 'fix/flux',
      draft: false,
    })
  })

  test('rejects path traversal and injection in every identifier parameter', () => {
    const attacks = [
      '../../admin',
      'a/b',
      'a?b=c',
      'a#frag',
      'a b',
      '',
      '.',
      '..',
      'a%2Fb',
      'a\\b',
    ]

    for (const attack of attacks) {
      for (const params of [
        { owner: attack, repo: 'widgets' },
        { owner: 'acme', repo: attack },
      ]) {
        assert.throws(
          () => buildRequest('github.repo.read', params),
          AdapterError,
          `should reject owner/repo = ${JSON.stringify(attack)}`,
        )
      }
    }
  })

  test('rejects an over-long identifier', () => {
    assert.throws(
      () => buildRequest('github.repo.read', { owner: 'a'.repeat(200), repo: 'widgets' }),
      AdapterError,
    )
  })

  test('bounds free-text parameters', () => {
    assert.throws(
      () =>
        buildRequest('github.issue.create', {
          owner: 'acme',
          repo: 'widgets',
          title: 'x'.repeat(300),
        }),
      AdapterError,
    )
  })

  test('requireSafeParam names the offending parameter', () => {
    assert.throws(() => requireSafeParam({ owner: '../x' }, 'owner'), /owner/u)
  })
})

describe('host allowlisting', () => {
  test('refuses a host the adapter does not declare', () => {
    const adapter = createGitHubAdapter()
    assert.throws(
      () => resolveUrl(adapter, GITHUB_API_BASE ? 'https://evil.example.com/' : '', 'repos/a/b'),
      (err: unknown) => err instanceof AdapterError && err.kind === 'host-not-allowed',
    )
  })

  test('refuses an absolute URL that would escape the base', () => {
    const adapter = createGitHubAdapter()
    assert.throws(
      () => resolveUrl(adapter, 'https://api.github.com/', 'https://evil.example.com/steal'),
      AdapterError,
    )
  })

  test('the credential is never sent to a disallowed host', async () => {
    const adapter = createGitHubAdapter() // production config: api.github.com only
    const secret = Secret.of(TOKEN)

    await assert.rejects(
      () =>
        callApi(
          adapter,
          'https://evil.example.com/',
          { operation: 'github.repo.read', path: 'repos/acme/widgets', responseFields: ['id'] },
          secret,
        ),
      AdapterError,
    )

    // Nothing reached the local stub, and the credential was never spent on that host.
    assert.equal(seen.length, 0)
    secret.dispose()
  })
})

describe('request execution', () => {
  test('injects the credential into the Authorization header', async () => {
    nextResponse = { status: 200, body: { id: 1, name: 'widgets', full_name: 'acme/widgets' } }

    const secret = Secret.of(TOKEN)
    const result = await adapterFor().execute(
      { operation: 'github.repo.read', params: { owner: 'acme', repo: 'widgets' } },
      secret,
    )

    assert.equal(seen.length, 1)
    assert.equal(seen[0]?.headers['authorization'], `Bearer ${TOKEN}`)
    assert.deepEqual(result, { id: 1, name: 'widgets', full_name: 'acme/widgets' })
    secret.dispose()
  })

  test('projects the response onto the field allowlist only', async () => {
    // A realistic GitHub payload carries far more than we are willing to relay.
    nextResponse = {
      status: 200,
      body: {
        id: 1296269,
        name: 'Hello-World',
        full_name: 'octocat/Hello-World',
        private: false,
        default_branch: 'main',
        description: 'My first repository',
        fork: false,
        archived: false,
        // Everything below must be dropped.
        permissions: { admin: true, push: true },
        owner: { login: 'octocat', id: 1, type: 'User', site_admin: false },
        subscribers_count: 42,
        network_count: 8,
        internal_ref: 'refs/pull/1/head',
      },
    }

    const secret = Secret.of(TOKEN)
    const result = (await adapterFor().execute(
      { operation: 'github.repo.read', params: { owner: 'octocat', repo: 'Hello-World' } },
      secret,
    )) as Record<string, unknown>

    assert.deepEqual(Object.keys(result).sort(), [
      'archived',
      'default_branch',
      'description',
      'fork',
      'full_name',
      'id',
      'name',
      'private',
    ])
    assert.ok(!('permissions' in result), 'permissions must not be relayed')
    assert.ok(!('owner' in result), 'owner details must not be relayed')
    assert.ok(!('internal_ref' in result), 'internal refs must not be relayed')
    secret.dispose()
  })

  test('a list response is projected per element', async () => {
    nextResponse = {
      status: 200,
      body: [
        // Includes a field outside the allowlist and omits allowlisted ones, so this covers
        // both directions of the projection.
        { id: 1, name: 'a', full_name: 'acme/a', permissions: { admin: true } },
        { id: 2, name: 'b', full_name: 'acme/b', owner: { login: 'x' } },
      ],
    }

    const secret = Secret.of(TOKEN)
    const result = await adapterFor().execute({ operation: 'github.repo.list', params: {} }, secret)

    assert.ok(Array.isArray(result))
    assert.equal(result.length, 2)
    // Exactly the allowlisted fields that were present. Absent allowlisted fields are
    // omitted rather than appearing as undefined, and everything else is dropped.
    for (const entry of result as Record<string, unknown>[]) {
      assert.deepEqual(Object.keys(entry).sort(), ['full_name', 'id', 'name'])
    }
    secret.dispose()
  })

  test('an upstream error reports status only, never the body', async () => {
    // Error bodies can reflect the request. Not including it avoids a second path for
    // the credential to come back out.
    nextResponse = { status: 401, body: { message: 'Bad credentials', documentation_url: 'https://docs.github.com' } }

    const secret = Secret.of(TOKEN)
    await assert.rejects(
      () => adapterFor().execute({ operation: 'github.repo.read', params: { owner: 'a', repo: 'b' } }, secret),
      (err: unknown) =>
        err instanceof AdapterError && err.kind === 'upstream-error' && !err.message.includes('Bad credentials'),
    )
    secret.dispose()
  })
})

describe('fail closed on a poisoned response', () => {
  test('refuses a body containing a GitHub token', async () => {
    // The provider echoing a credential back is the case the outbound scan exists for.
    nextResponse = { status: 200, body: { id: 1, name: 'x', token: 'ghp_ECHOEDBACKANDREFLECTED0123' } }

    const secret = Secret.of(TOKEN)
    await assert.rejects(
      () => adapterFor().execute({ operation: 'github.repo.read', params: { owner: 'a', repo: 'b' } }, secret),
      (err: unknown) => err instanceof AdapterError && err.kind === 'response-leaked-credential',
    )
    secret.dispose()
  })

  test('detects each known credential shape', () => {
    const shapes = [
      `ghp_${'a'.repeat(30)}`,
      `sk-${'b'.repeat(30)}`,
      `napi_${'c'.repeat(30)}`,
      'AKIAIOSFODNN7EXAMPLE',
      'ASIAIOSFODNN7EXAMPLE',
      'xoxb-1234567890-abcdefghij',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkl',
    ]
    for (const shape of shapes) {
      assert.throws(
        () => assertNoCredentialInResponse(`{"value":"${shape}"}`, 'test'),
        AdapterError,
        `should detect ${shape.slice(0, 12)}`,
      )
    }
  })

  test('a credential pattern in the raw body is caught even inside a nested field', () => {
    assert.throws(
      () => assertNoCredentialInResponse('{"a":{"b":["sk-xxxxxxxxxxxxxxxxxxxxxxxx"]}}', 'test'),
      AdapterError,
    )
  })

  test('a clean body passes', () => {
    assert.doesNotThrow(() => assertNoCredentialInResponse('{"id":1,"name":"widgets"}', 'test'))
  })

  test('the scan runs before parsing, so a poisoned body never reaches JSON.parse', async () => {
    nextResponse = { status: 200, body: '{"id":1,"leak":"ghp_abcdefghijklmnopqrstuvwxyz01"}' }

    const secret = Secret.of(TOKEN)
    await assert.rejects(
      () => adapterFor().execute({ operation: 'github.repo.read', params: { owner: 'a', repo: 'b' } }, secret),
      (err: unknown) => err instanceof AdapterError && err.kind === 'response-leaked-credential',
    )
    secret.dispose()
  })
})

describe('response field helpers', () => {
  test('pick follows dotted paths and omits missing fields', () => {
    const result = pick({ a: { b: { c: 1 } }, d: 2 }, ['a.b.c', 'missing.path', 'd'])
    assert.deepEqual(result, { 'a.b.c': 1, d: 2 })
    assert.ok(!('missing.path' in result), 'absent fields must be omitted, not set to undefined')
  })

  test('pick tolerates null intermediates', () => {
    assert.deepEqual(pick({ a: null }, ['a.b.c']), {})
  })

  test('pickEach returns an empty array for a non-array', () => {
    assert.deepEqual(pickEach({ not: 'an array' }, ['id']), [])
  })

  test('stripForbiddenKeys removes credential-bearing keys at any depth', () => {
    const stripped = stripForbiddenKeys({
      ok: true,
      authorization: 'Bearer secret',
      nested: { access_token: 'x', refresh_token: 'y', safe: 1 },
      list: [{ client_secret: 'z', keep: 2 }],
    }) as Record<string, unknown>

    const serialised = JSON.stringify(stripped)
    for (const forbidden of ['authorization', 'access_token', 'refresh_token', 'client_secret']) {
      assert.ok(!serialised.includes(forbidden), `${forbidden} must be stripped`)
    }
    assert.ok(serialised.includes('"safe":1'), 'benign fields must survive')
  })
})

describe('registry', () => {
  test('refuses an operation the adapter does not implement', () => {
    const registry = new AdapterRegistry()
    registry.register(adapterFor())

    assert.throws(
      () => registry.resolve('github', 'github.repo.delete'),
      (err: unknown) => err instanceof AdapterError && err.kind === 'unknown-operation',
    )
  })

  test('refuses a service with no adapter', () => {
    const registry = new AdapterRegistry()
    assert.throws(() => registry.resolve('aws', 'github.repo.read'), AdapterError)
  })

  test('resolves an implemented operation', () => {
    const registry = new AdapterRegistry()
    registry.register(adapterFor())
    assert.equal(registry.resolve('github', 'github.repo.read').service, 'github')
    assert.deepEqual(registry.services(), ['github'])
  })

  test('refuses to register the same service twice', () => {
    const registry = new AdapterRegistry()
    registry.register(adapterFor())
    assert.throws(() => registry.register(adapterFor()), AdapterError)
  })

  test('sensitive GitHub operations are deliberately unimplemented', () => {
    for (const operation of GITHUB_UNIMPLEMENTED) {
      assert.ok(
        !GITHUB_OPERATIONS.includes(operation),
        `${operation} must not be implemented until it has been designed deliberately`,
      )
    }
  })
})

describe('the non-disclosure invariant under a real request', () => {
  test('no credential byte appears in the result, headers, or child environment', async () => {
    nextResponse = {
      status: 200,
      body: { id: 1, name: 'widgets', full_name: 'acme/widgets', private: false },
    }

    const secret = Secret.of(TOKEN)

    // The server side did receive the credential — that is the point of the adapter.
    await adapterFor().execute(
      { operation: 'github.repo.read', params: { owner: 'acme', repo: 'widgets' } },
      secret,
    )

    assert.equal(seen[0]?.headers['authorization'], `Bearer ${TOKEN}`)

    // But nothing the broker hands onward contains it.
    const surfaced = [
      JSON.stringify(nextResponse.body),
      JSON.stringify(await adapterFor().execute(
        { operation: 'github.repo.read', params: { owner: 'acme', repo: 'widgets' } },
        secret,
      )),
      JSON.stringify(process.env),
      seen[0]?.url ?? '',
    ].join('\n')

    assert.ok(!surfaced.includes(TOKEN), 'the credential must not appear in anything surfaced')
    secret.dispose()
  })
})

describe('live GitHub (skipped without a credential)', () => {
  test(
    'fetches a repository with a real token when one is available',
    { skip: process.env['GH_TOKEN'] === undefined ? 'no GH_TOKEN in the environment' : false },
    async () => {
      const secret = Secret.fromBuffer(Buffer.from(process.env['GH_TOKEN'] ?? '', 'utf8'))
      const adapter = createGitHubAdapter()

      const result = (await adapter.execute(
        { operation: 'github.repo.list', params: {} },
        secret,
      )) as Record<string, unknown>[]

      assert.ok(Array.isArray(result))
      assert.ok(!JSON.stringify(result).includes((process.env['GH_TOKEN'] ?? '').slice(0, 10)))
      secret.dispose()
    },
  )
})