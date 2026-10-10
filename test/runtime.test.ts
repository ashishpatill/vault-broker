/**
 * Tests for runtime path resolution and filesystem defaults.
 *
 * The permissions assertions are the point of this file: a credential vault that is
 * accidentally world-readable is worse than no vault, and `mkdir`'s mode argument is
 * silently modified by the process umask — which is exactly the bug these catch.
 */

import { strict as assert } from 'node:assert'
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { ensureDir0700, readJsonIfExists, writeFileAtomic } from '../src/core/fsx.ts'
import {
  auditLogPath,
  clientsDir,
  runtimePaths,
  runtimeRoot,
  socketPath,
  vaultPath,
  HOME_ENV_VAR,
} from '../src/core/runtime-paths.ts'
import { runInit, STATE_SCHEMA_VERSION } from '../src/cli/commands/init.ts'

describe('runtime paths', () => {
  const original = process.env[HOME_ENV_VAR]
  let sandbox: string

  before(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vaultbroker-paths-'))
    process.env[HOME_ENV_VAR] = sandbox
  })

  after(() => {
    if (original === undefined) delete process.env[HOME_ENV_VAR]
    else process.env[HOME_ENV_VAR] = original
    rmSync(sandbox, { recursive: true, force: true })
  })

  test('honours VAULTBROKER_HOME so tests never touch the real runtime dir', () => {
    assert.equal(runtimeRoot(), sandbox)
  })

  test('ignores an empty VAULTBROKER_HOME rather than resolving to cwd', () => {
    process.env[HOME_ENV_VAR] = ''
    // Falls through to the macOS standard location, NOT the process cwd.
    assert.match(runtimeRoot(), /Library\/Application Support\/VaultBroker$/u)
    process.env[HOME_ENV_VAR] = sandbox
  })

  test('resolves every path inside the runtime root', () => {
    const paths = runtimePaths()
    for (const [name, value] of Object.entries(paths)) {
      assert.ok(value.startsWith(sandbox), `${name} escaped the runtime root: ${value}`)
    }
  })

  test('the daemon socket lives on the filesystem, not a TCP port', () => {
    assert.ok(socketPath().endsWith('.sock'), 'socket must be a unix domain socket path')
    assert.equal(socketPath(), join(sandbox, 'broker.sock'))
  })

  test('distinct files do not collide', () => {
    const all = [vaultPath(), auditLogPath(), clientsDir(), socketPath()]
    assert.equal(new Set(all).size, all.length, 'runtime paths must not collide')
  })
})

describe('filesystem defaults', () => {
  let sandbox: string

  before(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vaultbroker-fsx-'))
  })

  after(() => {
    rmSync(sandbox, { recursive: true, force: true })
  })

  test('ensureDir0700 sets 0700 even under a permissive umask', () => {
    const previousUmask = process.umask(0o000)
    try {
      const dir = join(sandbox, 'permissive')
      ensureDir0700(dir)
      const mode = statSync(dir).mode & 0o777
      assert.equal(mode, 0o700, `expected 0700, got 0${mode.toString(8)}`)
    } finally {
      process.umask(previousUmask)
    }
  })

  test('ensureDir0700 tightens an existing loose directory', () => {
    const dir = join(sandbox, 'loose')
    ensureDir0700(dir)
    // Simulate a pre-existing world-readable directory.
    chmodSync(dir, 0o755)
    ensureDir0700(dir)
    assert.equal(statSync(dir).mode & 0o777, 0o700)
  })

  test('writeFileAtomic writes 0600 and leaves no temp files behind', () => {
    const target = join(sandbox, 'sub', 'data.json')
    writeFileAtomic(target, '{"ok":true}\n')

    assert.equal(statSync(target).mode & 0o777, 0o600)
    assert.equal(readFileSync(target, 'utf8'), '{"ok":true}\n')

    const leftovers = readdirSync(join(sandbox, 'sub')).filter((f) => f.endsWith('.tmp'))
    assert.deepEqual(leftovers, [], 'temp files must be renamed away, not left on disk')
  })

  test('writeFileAtomic replaces existing content atomically', () => {
    const target = join(sandbox, 'sub2', 'data.json')
    writeFileAtomic(target, 'first')
    writeFileAtomic(target, 'second')
    assert.equal(readFileSync(target, 'utf8'), 'second')
  })

  test('readJsonIfExists returns undefined for a missing file', () => {
    assert.equal(readJsonIfExists(join(sandbox, 'nope.json')), undefined)
  })
})

describe('init', () => {
  let sandbox: string
  const original = process.env[HOME_ENV_VAR]

  before(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vaultbroker-init-'))
    process.env[HOME_ENV_VAR] = join(sandbox, 'runtime')
  })

  after(() => {
    if (original === undefined) delete process.env[HOME_ENV_VAR]
    else process.env[HOME_ENV_VAR] = original
    rmSync(sandbox, { recursive: true, force: true })
  })

  test('creates the runtime directory with 0700', () => {
    const result = runInit()

    assert.equal(result.created, true)
    assert.equal(result.state.schemaVersion, STATE_SCHEMA_VERSION)
    assert.equal(result.state.product, 'vaultbroker')
    assert.equal(statSync(result.root).mode & 0o777, 0o700)
    assert.equal(statSync(clientsDir()).mode & 0o777, 0o700)
  })

  test('is idempotent and preserves existing state', () => {
    const first = runInit()
    const second = runInit()

    assert.equal(second.created, false)
    assert.equal(second.state.createdAt, first.state.createdAt, 'createdAt must not change')
  })

  test('writes a self-ignoring .gitignore', () => {
    runInit()
    const ignorePath = join(runtimeRoot(), '.gitignore')
    assert.ok(existsSync(ignorePath))
    assert.match(readFileSync(ignorePath, 'utf8'), /^\*$/mu)
  })

  test('does NOT create a vault file — that is iteration I1', () => {
    runInit()
    assert.equal(existsSync(vaultPath()), false, 'an empty vault placeholder would look valid but hold no key material')
  })
})