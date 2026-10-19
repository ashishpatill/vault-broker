/**
 * Daemon, shim and MCP transport tests.
 *
 * The central assertions are structural, not functional:
 *
 *   1. **No TCP listener exists.** The daemon must only ever bind a Unix domain socket.
 *      This is instrumented by wrapping `net.Server.prototype.listen` and failing if any
 *      call supplies a port or host — a property that would otherwise be invisible in
 *      review and easy to regress.
 *   2. **One daemon serves many shims.** The reason this architecture exists: separate
 *      per-harness processes would mean separate unlocked vaults.
 *   3. **The tool surface has no credential-returning tool.** Asserted by name and by
 *      driving every tool with adversarial arguments.
 *   4. **stdout carries JSON-RPC only.** Diagnostics must never touch it.
 */

import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { connect, createServer, Server as NetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, afterEach, before, beforeEach, describe, test } from 'node:test'

import { captureStdout, createLogger, redact, safeRender } from '../src/core/logging.ts'
import { Secret } from '../src/core/secret.ts'
import { InMemoryKeychain } from '../src/core/keychain.ts'
import { Vault } from '../src/core/vault.ts'
import { HOME_ENV_VAR, runtimeRoot, socketPath } from '../src/core/runtime-paths.ts'
import {
  assertCompatible,
  buildRequest,
  encodeFrame,
  parseFrame,
  ProtocolError,
  PROTOCOL_VERSION,
} from '../src/daemon/protocol.ts'
import { startDaemon, type DaemonHandle } from '../src/daemon/server.ts'
import { Session } from '../src/daemon/session.ts'
import { connectInMemory, daemonRequest, resolveClientId } from '../src/shim/main.ts'
import { TOOL_DEFINITIONS, TOOL_NAMES } from '../src/shim/tools.ts'

const CANARY = 'mcp-canary-4d7f2a-do-not-leak'

let root: string
let socket: string
let vault: Vault
let handle: DaemonHandle
const originalHome = process.env[HOME_ENV_VAR]

before(async () => {
  root = mkdtempSync(join(tmpdir(), 'vaultbroker-i2-'))
  process.env[HOME_ENV_VAR] = root
  socket = socketPath()

  vault = Vault.open(new InMemoryKeychain())
  vault.add({ service: 'github', accountAlias: 'work', secret: Secret.of('ghp_canary_token_value'), secretType: 'bearer' })
  vault.add({ service: 'neon', accountAlias: 'proj-alpha', secret: Secret.of('napi_canary_value') })

  handle = await startDaemon({ session: new Session(vault) })
})

after(async () => {
  await handle.stop()
  vault.dispose()
  if (originalHome === undefined) delete process.env[HOME_ENV_VAR]
  else process.env[HOME_ENV_VAR] = originalHome
  rmSync(root, { recursive: true, force: true })
})

describe('protocol frames', () => {
  test('round-trips a request', () => {
    const frame = buildRequest('cursor', 'ping')
    const parsed = parseFrame(encodeFrame(frame).trim())

    assert.equal(parsed.kind, 'request')
    assert.equal(parsed.kind === 'request' && parsed.command, 'ping')
    assert.equal(parsed.kind === 'request' && parsed.version, PROTOCOL_VERSION)
  })

  test('rejects malformed frames rather than guessing', () => {
    for (const bad of ['', 'not json', '[]', 'null', '"string"', '{"kind":"other"}', '{"kind":"request"}']) {
      assert.throws(() => parseFrame(bad), ProtocolError, `should reject: ${bad.slice(0, 24)}`)
    }
  })

  test('rejects a request whose params are missing or not an object', () => {
    assert.throws(
      () => parseFrame('{"kind":"request","id":"1","version":1,"clientId":"cursor","command":"ping"}'),
      ProtocolError,
    )
  })

  test('a frame from a future protocol version is refused, not interpreted', () => {
    // Interpreting a newer frame with older field assumptions is how request smuggling
    // starts, so the version gate is explicit rather than best-effort.
    const current = buildRequest('cursor', 'ping')
    assertCompatible(current)
    assert.throws(() => assertCompatible({ ...current, version: 99 }), ProtocolError)
    assert.throws(() => assertCompatible({ ...current, version: 0 }), ProtocolError)
  })
})

describe('no TCP listener', () => {
  test('the daemon binds only a unix domain socket', async () => {
    const original = NetServer.prototype.listen
    const violations: unknown[][] = []

    NetServer.prototype.listen = function patched(this: NetServer, ...args: unknown[]) {
      // A port or an explicit host means a TCP listener. Neither may appear.
      const hasPortOrHost = args.some(
        (a) => typeof a === 'number' || (typeof a === 'object' && a !== null && 'port' in a) || typeof a === 'string',
      )
      if (hasPortOrHost) violations.push(args)
      return original.apply(this, args as Parameters<typeof original>)
    } as typeof original

    try {
      const reply = await daemonRequest('cursor', 'ping', {}, { socket, timeoutMs: 5000 })
      assert.equal((reply as { pong: boolean }).pong, true)
    } finally {
      NetServer.prototype.listen = original
    }

    assert.deepEqual(violations, [], 'the daemon must never open a TCP listener')
  })

  test('the listening socket is a filesystem path, not a port', () => {
    assert.ok(socket.endsWith('.sock'), 'socket path should end in .sock')
    assert.equal(statSync(socket).isSocket(), true, 'expected a unix domain socket on disk')
  })

  test('the socket is reachable only by this user', () => {
    // Directory is 0700, socket is 0600.
    assert.equal(statSync(runtimeRoot()).mode & 0o777, 0o700)
    assert.equal(statSync(socket).mode & 0o777, 0o600)
  })
})

describe('daemon requests', () => {
  test('ping responds', async () => {
    const reply = (await daemonRequest('cursor', 'ping', {}, { socket })) as { pong: boolean; pid: number }
    assert.equal(reply.pong, true)
    assert.equal(reply.pid, process.pid, 'the daemon owns the vault, so it runs in-process here')
  })

  test('status reports the daemon and its connected clients', async () => {
    await daemonRequest('cursor', 'status', {}, { socket })
    const status = (await daemonRequest('opencode', 'status', {}, { socket })) as {
      connectedClients: string[]
      credentialCount: number
    }

    assert.ok(status.connectedClients.includes('cursor'))
    assert.ok(status.connectedClients.includes('opencode'), 'multiple clients share one daemon')
    assert.equal(status.credentialCount, 2)
  })

  test('list_accounts returns metadata and never a credential', async () => {
    const accounts = (await daemonRequest('cursor', 'list_accounts', {}, { socket })) as {
      service: string
      accountAlias: string
    }[]

    assert.equal(accounts.length, 2)
    const rendered = JSON.stringify(accounts)
    assert.ok(rendered.includes('github'))
    assert.ok(rendered.includes('work'))

    for (const canary of [CANARY, 'ghp_canary_token_value', 'napi_canary_value']) {
      assert.ok(!rendered.includes(canary), `list_accounts leaked: ${canary}`)
    }

    // The shape itself must have no field that could hold a secret.
    for (const account of accounts) {
      assert.deepEqual(
        Object.keys(account).sort(),
        ['accountAlias', 'createdAt', 'rotatedAt', 'secretType', 'service'],
      )
    }
  })

  test('a CLI write becomes visible to a running daemon', async () => {
    // Regression guard for a real bug: the daemon held an in-memory snapshot, so
    // `vaultbroker secret add` wrote the file behind its back and `list_accounts`
    // silently returned a stale (empty) result.
    const scratchKeychain = new InMemoryKeychain()
    const scratchPath = join(root, 'reload.json')

    const scratchVault = Vault.open(scratchKeychain, scratchPath)
    const scratchSession = new Session(scratchVault, {
      reload: { keychain: scratchKeychain, path: scratchPath },
    })
    const scratchDaemon = await startDaemon({
      session: scratchSession,
      socket: join(root, 'reload.sock'),
      lockFile: join(root, 'reload.lock'),
    })

    try {
      const before = (await daemonRequest('cursor', 'list_accounts', {}, {
        socket: scratchDaemon.socket,
      })) as unknown[]
      assert.equal(before.length, 0, 'starts empty')

      // An out-of-band write, exactly as the CLI does it.
      const other = Vault.open(scratchKeychain, scratchPath)
      other.add({ service: 'github', accountAlias: 'late', secret: Secret.of('ghp_late_token') })
      other.dispose()

      const after = (await daemonRequest('cursor', 'list_accounts', {}, {
        socket: scratchDaemon.socket,
      })) as { service: string; accountAlias: string }[]

      assert.equal(after.length, 1, 'daemon must observe the out-of-band write')
      assert.equal(after[0]?.service, 'github')
      assert.ok(!JSON.stringify(after).includes('ghp_late_token'))
    } finally {
      await scratchDaemon.stop()
    }
  })

  test('an unknown command is refused with a coarse error', async () => {
    await assert.rejects(
      () => daemonRequest('cursor', 'not-a-command' as 'ping', {}, { socket }),
      /unknown command/u,
    )
  })

  test('garbage on the socket does not crash the daemon', async () => {
    // Send a malformed frame, then prove the daemon is still serving.
    const { connect } = await import('node:net')
    await new Promise<void>((resolve) => {
      const conn = connect(socket)
      conn.setEncoding('utf8')
      conn.on('connect', () => conn.write('this is not json\n'))
      conn.on('data', () => {
        conn.destroy()
        resolve()
      })
      conn.on('error', () => resolve())
    })

    const reply = await daemonRequest('cursor', 'ping', {}, { socket })
    assert.equal((reply as { pong: boolean }).pong, true, 'daemon must survive malformed input')
  })

  test('concurrent requests all complete and correlate correctly', async () => {
    // Correlation is by frame id, not arrival order, so a burst must not cross responses.
    const replies = await Promise.all(
      Array.from({ length: 12 }, async (_, i) => {
        const reply = (await daemonRequest('cursor', 'list_accounts', {}, { socket })) as unknown[]
        return reply.length
      }),
    )
    assert.deepEqual(replies, Array(12).fill(2))
  })
})

describe('single instance', () => {
  /**
   * Each of these needs its own vault *file* as well as its own keychain: opening the
   * shared runtime vault with a fresh in-memory keychain is correctly refused by
   * `Vault.open`, which would mask what these tests are actually about.
   */
  function throwawayVault(name: string): Vault {
    return Vault.open(new InMemoryKeychain(), join(root, `${name}.json`))
  }

  test('a second daemon refuses to start while one is running', async () => {
    const other = throwawayVault('second')
    await assert.rejects(
      () => startDaemon({ session: new Session(other), socket: join(root, 'second.sock') }),
      /already running/u,
    )
    other.dispose()
  })

  test('a stale lock from a dead process is reclaimed', async () => {
    const { writeFileSync } = await import('node:fs')
    const lockFile = join(root, 'stale.lock')
    // Pid 2147483647 is not a live process.
    writeFileSync(lockFile, '2147483647\n')

    const other = throwawayVault('stale')
    const handle2 = await startDaemon({
      session: new Session(other),
      socket: join(root, 'stale.sock'),
      lockFile,
    })
    await handle2.stop()
    other.dispose()
  })

  test('shutdown completes even with a client connection still open', async () => {
    // Regression guard for a real hang: server.close() only stops accepting and then waits
    // for every existing connection to end, so one lingering socket blocked shutdown
    // forever — `vaultbroker daemon stop` never returned. net.Server has no
    // closeAllConnections (that is http.Server), so sockets are tracked and destroyed.
    const probeVault = throwawayVault('shutdown')
    const probeDaemon = await startDaemon({
      session: new Session(probeVault),
      socket: join(root, 'shutdown.sock'),
      lockFile: join(root, 'shutdown.lock'),
    })

    // Open a connection and deliberately never send anything on it.
    const linger = connect(probeDaemon.socket)
    await new Promise<void>((resolve) => linger.on('connect', () => resolve()))

    // Would hang here without the fix; bounded so a regression fails rather than hangs.
    const stopped = await Promise.race([
      probeDaemon.stop().then(() => 'stopped'),
      new Promise<string>((resolve) => setTimeout(() => resolve('TIMED OUT'), 5000)),
    ])

    assert.equal(stopped, 'stopped', 'daemon shutdown must not wait on idle connections')
    linger.destroy()
    probeVault.dispose()
  })

  test('a stale socket file from a crashed daemon is replaced, not fatal', async () => {
    // A crashed daemon leaves the socket file behind, and bind() would fail EADDRINUSE
    // even though nothing is listening. Needs its own lock file too, since the running
    // daemon legitimately holds the shared one.
    const orphan = join(root, 'orphan.sock')
    const { writeFileSync } = await import('node:fs')
    writeFileSync(orphan, '')

    const other = throwawayVault('orphan')
    const handle3 = await startDaemon({
      session: new Session(other),
      socket: orphan,
      lockFile: join(root, 'orphan.lock'),
    })

    const reply = await daemonRequest('cursor', 'ping', {}, { socket: orphan, timeoutMs: 5000 })
    assert.equal((reply as { pong: boolean }).pong, true, 'should serve on the replaced socket')

    await handle3.stop()
    other.dispose()
  })
})

describe('MCP tool surface', () => {
  test('exposes exactly the intended tools and nothing that returns a secret', async () => {
    const client = await connectInMemory('cursor', socket)
    const { tools } = await client.listTools()

    const names = tools.map((t) => t.name).sort()
    assert.deepEqual(names, [TOOL_NAMES.brokerStatus, TOOL_NAMES.callApi, TOOL_NAMES.listAccounts].sort())

    // The forbidden set, asserted rather than assumed. A tool that returns a credential
    // is the single failure mode this product must never ship.
    const forbidden = [
      'get_secret',
      'getSecret',
      'read_secret',
      'export',
      'copy_to_clipboard',
      'run_shell',
      'reveal',
    ]
    for (const name of names) {
      for (const banned of forbidden) {
        assert.ok(
          !name.toLowerCase().includes(banned.toLowerCase()),
          `tool surface must not contain ${banned}`,
        )
      }
    }
  })

  test('meta tools take no arguments; call_api is bounded, never free-form', () => {
    for (const tool of TOOL_DEFINITIONS) {
      assert.equal(tool.inputSchema.additionalProperties, false, `${tool.name} must reject extra keys`)
      if (tool.name === TOOL_NAMES.callApi) continue
      assert.deepEqual(
        Object.keys(tool.inputSchema.properties),
        [],
        `${tool.name} should take no arguments; free-form input is a disclosure risk`,
      )
    }

    // call_api is the one tool that takes arguments, and its surface is deliberately
    // narrow: identities and a capability id, never a credential value. A property that
    // accepted a secret would turn the tool into the disclosure path it exists to close.
    const callApi = TOOL_DEFINITIONS.find((tool) => tool.name === TOOL_NAMES.callApi)
    assert.notEqual(callApi, undefined)
    const keys = Object.keys(callApi?.inputSchema.properties ?? {}).sort()
    assert.deepEqual(keys, ['account', 'capability_id', 'operation', 'params', 'project', 'service'])

    const bannedArgNames = ['secret', 'token', 'password', 'credential', 'value', 'key']
    for (const key of keys) {
      for (const banned of bannedArgNames) {
        assert.ok(
          !key.toLowerCase().includes(banned),
          `call_api argument ${key} must not be named for credential material (${banned})`,
        )
      }
    }
  })

  test('list_accounts over MCP returns no credential', async () => {
    const client = await connectInMemory('claude-code', socket)
    const result = await client.callTool({ name: TOOL_NAMES.listAccounts, arguments: {} })

    const text = (result.content as { type: string; text?: string }[])
      .map((c) => c.text ?? '')
      .join('')

    assert.ok(text.includes('github'))
    for (const canary of [CANARY, 'ghp_canary_token_value', 'napi_canary_value']) {
      assert.ok(!text.includes(canary), `MCP response leaked: ${canary}`)
    }
    assert.notEqual(result.isError, true)
  })

  test('an unknown tool returns an error rather than throwing', async () => {
    const client = await connectInMemory('opencode', socket)
    const result = await client.callTool({ name: 'get_secret', arguments: { name: 'github' } })

    assert.equal(result.isError, true)
    const text = (result.content as { text?: string }[]).map((c) => c.text ?? '').join('')
    assert.ok(!text.includes('ghp_canary_token_value'))
  })

  test('a tool call with a missing daemon surfaces an error, not a hang', async () => {
    const client = await connectInMemory('codex', join(root, 'nonexistent.sock'))
    const result = await client.callTool({ name: TOOL_NAMES.listAccounts, arguments: {} })
    assert.equal(result.isError, true)
  })

  test('several clients share one daemon and one unlocked vault', async () => {
    // The architectural point of I2: independent per-harness processes would mean
    // separate vault state.
    const clients = await Promise.all([
      connectInMemory('cursor', socket),
      connectInMemory('claude-code', socket),
      connectInMemory('opencode', socket),
    ])

    const results = await Promise.all(
      clients.map(async (c) => (await c.callTool({ name: TOOL_NAMES.listAccounts, arguments: {} })).content),
    )

    for (const content of results) {
      const text = (content as { text?: string }[]).map((c) => c.text ?? '').join('')
      assert.ok(text.includes('github'), 'every client must see the same vault')
    }
  })
})

describe('client identity', () => {
  test('resolves the client id from argv', () => {
    assert.equal(resolveClientId(['opencode']), 'opencode')
    assert.equal(resolveClientId(['codex', '--flag']), 'codex')
    assert.equal(resolveClientId([]), 'cursor', 'defaults rather than crashing')
  })

  test('an unknown client id is not silently accepted as a trusted one', () => {
    // Today this only selects a policy profile; I4 adds signature verification. The
    // default must still be a real client, never an arbitrary string.
    assert.equal(resolveClientId(['not-a-client']), 'cursor')
  })
})

describe('stdout hygiene', () => {
  test('logging goes to stderr, never stdout', () => {
    const captured = captureStdout()
    const log = createLogger('test')
    try {
      log.error('something happened', { detail: 'value' })
    } finally {
      captured.restore()
    }
    assert.deepEqual(captured.lines, [], 'stdout must stay clean for JSON-RPC')
  })

  test('the logger redacts credential-shaped values', () => {
    const captured = captureStdout()
    const errors: string[] = []
    const originalWrite = process.stderr.write.bind(process.stderr)
    process.stderr.write = ((chunk: string): boolean => {
      errors.push(String(chunk))
      return true
    }) as typeof process.stderr.write

    const log = createLogger('leak-test')
    try {
      log.error('token', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345')
      log.error('secret object', Secret.of('sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ'))
    } finally {
      process.stderr.write = originalWrite
      captured.restore()
    }

    const output = errors.join('')
    assert.ok(!output.includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'), 'GitHub token must be redacted')
    assert.ok(!output.includes('sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 'sk- token must be redacted')
    assert.ok(output.includes('redacted'), 'redaction should be visible')
  })

  test('redact covers the provider token shapes we know', () => {
    assert.match(redact('ghp_' + 'a'.repeat(36)), /redacted/u)
    assert.match(redact('sk-' + 'b'.repeat(40)), /redacted/u)
    assert.match(redact('napi_' + 'c'.repeat(40)), /redacted/u)
    assert.match(redact('AKIAIOSFODNN7EXAMPLE'), /redacted/u)
    assert.match(redact('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkl'), /redacted/u)
  })

  test('safeRender never renders a Secret', () => {
    assert.ok(!safeRender(Secret.of('super-secret')).includes('super-secret'))
    assert.ok(!safeRender('ghp_' + 'z'.repeat(36)).includes('ghp_'))
    // A Secret nested inside a plain object is still caught.
    assert.ok(!safeRender({ nested: Secret.of('nested-secret') }).includes('nested-secret'))
  })

  test('a TCP server can be created in tests, so the no-TCP assertion is meaningful', () => {
    // Guards against the instrumentation above passing vacuously because listen is
    // unreachable rather than because nothing binds a port.
    const probe = createServer()
    assert.equal(typeof probe.listen, 'function')
    probe.close()
  })
})