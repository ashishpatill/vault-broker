/**
 * Installer tests.
 *
 * The harness CLIs are replaced by stub scripts that record their argv to a log file, so
 * every client is exercised the way its production path works — spawn, flags, exit code —
 * against a disposable home directory. Nothing here touches a real harness config.
 */

import { strict as assert } from 'node:assert'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, beforeEach, describe, test } from 'node:test'

import {
  alreadyInstalled,
  applyInstall,
  applyRollback,
  applyUninstall,
  brokerLauncherEntry,
  configPathFor,
  diffLines,
  planInstall,
  renderPlan,
  rewriteCursorConfigText,
  SERVER_NAME,
} from '../src/install/install.ts'
import { HOME_ENV_VAR, runtimeRoot } from '../src/core/runtime-paths.ts'

type Client = 'cursor' | 'claude-code' | 'opencode' | 'codex'

const ALL_CLIENTS: readonly Client[] = ['cursor', 'claude-code', 'opencode', 'codex']

/** A stub harness CLI: records each argv element on its own line, exits 0. */
const STUB_BODY = `#!/bin/sh
printf '%s\\n' "$@" >> "$VBSTUB_ARGV"
exit 0
`

describe('diff rendering', () => {
  test('shows only the changed lines and marks them', () => {
    const before = ['{', '  "mcpServers": {', '    "icm": 1,', '  }', '}']
    const after = ['{', '  "mcpServers": {', '    "icm": 1,', '    "vaultbroker": 2', '  }', '}']

    const diff = diffLines(before, after)
    assert.ok(diff.some((line) => line.startsWith('+ ')), 'addition missing')
    assert.ok(!diff.some((line) => line.startsWith('- ')), 'an insert-only change must not delete')

    const added = diff.filter((line) => line.startsWith('+ ')).join('\n')
    assert.ok(added.includes('vaultbroker'), 'the diff must name the new entry')
  })

  test('a real substitution produces both marks', () => {
    const diff = diffLines(['a', 'b', 'c'], ['a', 'x', 'c'])
    assert.ok(diff.includes('- b'))
    assert.ok(diff.includes('+ x'))
  })

  test('identical inputs report that instead of an empty diff', () => {
    assert.deepEqual(diffLines(['a', 'b'], ['a', 'b']), ['  a', '  b'])
  })
})

describe('broker launcher entry', () => {
  test('is absolute, argv-only, and carries no secret surface', () => {
    const entry = brokerLauncherEntry('cursor')
    assert.ok(entry.command.startsWith('/'), 'command must be an absolute path')
    assert.ok(entry.args[0]?.endsWith('vaultbroker.mjs'), 'launcher must be the repo binary')
    assert.equal(entry.args[1], 'mcp')
    assert.equal(entry.args[2], 'cursor')
    assert.ok(!('env' in entry), 'no env block on the entry')
  })
})

describe('cursor file installation', () => {
  const scratch: string[] = []
  let priorHome: string | undefined

  beforeEach(() => {
    priorHome = process.env[HOME_ENV_VAR]
    const root = mkdtempSync(join(tmpdir(), 'vbinstall-'))
    scratch.push(root)
    process.env[HOME_ENV_VAR] = root
  })

  afterEach(() => {
    if (priorHome === undefined) delete process.env[HOME_ENV_VAR]
    else process.env[HOME_ENV_VAR] = priorHome
    while (scratch.length > 0) {
      const dir = scratch.pop()
      if (dir !== undefined) rmSync(dir, { recursive: true, force: true })
    }
  })

  /** A cursor-shaped config carrying other servers, plus its path. */
  function seedCursorConfig(home: string): { path: string; before: string; bytes: Buffer } {
    const path = configPathFor('cursor', home)
    mkdirSync(dirname(path), { recursive: true })
    const before = JSON.stringify(
      { mcpServers: { icm: { command: 'npx' }, tell: { command: 'npx' } } },
      null,
      2,
    )
    writeFileSync(path, before)
    return { path, before, bytes: readFileSync(path) }
  }

  test('plan diff shows exactly the inserted entry; apply matches it', () => {
    const home = scratch[scratch.length - 1] as string
    const seeded = seedCursorConfig(home)

    const plan = planInstall('cursor', { home })
    assert.ok(plan.fileDiff !== undefined)
    assert.ok(!plan.fileDiff.some((line) => line.startsWith('- ')), 'install must not delete existing lines')

    const applied = applyInstall('cursor', { home })
    assert.equal(applied.changed, true, applied.summary)

    // Applying must produce the exact text the plan's own entry computes: shown diff =
    // landed diff.
    const expected = rewriteCursorConfigText(seeded.before, SERVER_NAME, plan.entry)
    assert.equal(readFileSync(seeded.path, 'utf8'), expected)
  })

  test('other servers survive the install and the entry has no env block', () => {
    const home = scratch[scratch.length - 1] as string
    const seeded = seedCursorConfig(home)

    const was = JSON.parse(seeded.before) as { mcpServers: Record<string, object> }
    assert.equal(applyInstall('cursor', { home }).changed, true)
    const now = JSON.parse(readFileSync(seeded.path, 'utf8')) as { mcpServers: Record<string, object> }

    assert.deepEqual(now.mcpServers['icm'], was.mcpServers['icm'])
    assert.deepEqual(now.mcpServers['tell'], was.mcpServers['tell'])
    assert.ok(now.mcpServers[SERVER_NAME] !== undefined)
    assert.ok(!('env' in (now.mcpServers[SERVER_NAME] as object)), 'installed entry carries an env block')
  })

  test('re-install is idempotent', () => {
    const home = scratch[scratch.length - 1] as string
    seedCursorConfig(home)

    assert.equal(applyInstall('cursor', { home }).changed, true)
    const afterFirst = readFileSync(configPathFor('cursor', home), 'utf8')

    const second = applyInstall('cursor', { home })
    assert.equal(second.changed, false, second.summary)
    assert.equal(readFileSync(configPathFor('cursor', home), 'utf8'), afterFirst)
    assert.ok(alreadyInstalled('cursor', SERVER_NAME, home))
  })

  test('uninstall removes only the broker entry, keeping the others', () => {
    const home = scratch[scratch.length - 1] as string
    const seeded = seedCursorConfig(home)

    assert.equal(applyInstall('cursor', { home }).changed, true)

    const removed = applyUninstall('cursor', { home })
    assert.equal(removed.changed, true)

    const now = JSON.parse(readFileSync(seeded.path, 'utf8')) as { mcpServers: Record<string, unknown> }
    assert.ok(!(SERVER_NAME in now.mcpServers))
    assert.deepEqual(Object.keys(now.mcpServers), ['icm', 'tell'])
  })

  test('rollback restores the pre-install bytes', () => {
    const home = scratch[scratch.length - 1] as string
    const seeded = seedCursorConfig(home)

    assert.equal(applyInstall('cursor', { home }).changed, true)
    assert.ok(!readFileSync(seeded.path).equals(seeded.bytes), 'install did not change anything')

    const restored = applyRollback('cursor', home)
    assert.ok(restored.startsWith('restored'), restored)
    assert.ok(readFileSync(seeded.path).equals(seeded.bytes), 'rollback is not byte-identical')
  })

  test('a corrupted snapshot aborts the rollback and leaves the target alone', () => {
    const home = scratch[scratch.length - 1] as string
    const seeded = seedCursorConfig(home)

    assert.equal(applyInstall('cursor', { home }).changed, true)

    const backupsDir = join(runtimeRoot(), 'backups')
    const backups = readdirSync(backupsDir).filter((name) => name.endsWith('.bak')).sort()
    assert.ok(backups.length > 0, 'expected an install snapshot')

    const victim = join(backupsDir, backups.at(-1) as string)
    const bytes = readFileSync(victim)
    const last = bytes[bytes.length - 1]
    assert.ok(last !== undefined, 'snapshot payload is empty')
    bytes[bytes.length - 1] = last ^ 0x01
    writeFileSync(victim, bytes)

    const refused = applyRollback('cursor', home)
    assert.ok(!refused.startsWith('restored'), 'rollback accepted corrupt bytes')
    assert.ok(!readFileSync(seeded.path).equals(seeded.bytes), 'a refused rollback must not write')
  })
})

describe('cli-driven installation (claude-code, opencode, codex)', () => {
  const scratch: string[] = []
  let priorHome: string | undefined

  beforeEach(() => {
    priorHome = process.env[HOME_ENV_VAR]
    const root = mkdtempSync(join(tmpdir(), 'vbinstallcli-'))
    scratch.push(root)
    const binDir = join(root, 'bin')
    mkdirSync(binDir, { recursive: true })
    for (const name of ['claude-test-stub', 'opencode-test-stub', 'codex-test-stub']) {
      const path = join(binDir, name)
      writeFileSync(path, STUB_BODY)
      chmodSync(path, 0o755)
    }
    writeFileSync(join(root, 'argv.log'), '')
    process.env['VBSTUB_ARGV'] = join(root, 'argv.log')
    process.env[HOME_ENV_VAR] = root
  })

  afterEach(() => {
    if (priorHome === undefined) delete process.env[HOME_ENV_VAR]
    else process.env[HOME_ENV_VAR] = priorHome
    while (scratch.length > 0) {
      const dir = scratch.pop()
      if (dir !== undefined) rmSync(dir, { recursive: true, force: true })
    }
  })

  for (const client of ALL_CLIENTS) {
    if (client === 'cursor') continue
    test(`${client}: plan shows the exact CLI invocation and no credential text`, () => {
      const home = scratch[scratch.length - 1] as string

      const plan = planInstall(client, { home })
      const argv = plan.argv as string[]
      assert.ok(argv[0]?.endsWith('-test-stub'), `probe chose the wrong binary: ${String(argv[0])}`)

      const rendered = renderPlan(plan)
      assert.ok(rendered.includes(SERVER_NAME), rendered)
      assert.ok(rendered.includes('vaultbroker.mjs'), rendered)
      assert.ok(!rendered.toLowerCase().includes('token'), 'plan text mentions a credential')
      // Exactly one `--` separator: the launcher command and its args ride after it.
      assert.equal(argv.filter((part) => part === '--').length, 1)
    })

    test(`${client}: apply spawns the recorded argv and the entry holds no secret`, () => {
      const home = scratch[scratch.length - 1] as string
      const logPath = join(home, 'argv.log')

      const plan = planInstall(client, { home })
      const applied = applyInstall(client, { home })
      assert.equal(applied.changed, true, applied.summary)
      assert.ok(applied.summary.includes('verified credential-free'), applied.summary)

      const recorded = readFileSync(logPath, 'utf8').split('\n').filter(Boolean)
      const expected = (plan.argv as string[]).length - 1 // minus the stub binary itself
      assert.equal(recorded.length, expected, recorded.join(' | '))

      for (const part of recorded) {
        assert.ok(!part.toLowerCase().includes('token'), 'spawned argv carries credential text')
      }
    })
  }

  test('a missing harness CLI refuses to fabricate an install', () => {
    const emptyHome = mkdtempSync(join(tmpdir(), 'vbnonests-'))
    try {
      // No stub binaries under this home: both probe candidates are absent.
      assert.throws(() => applyInstall('claude-code', { home: emptyHome }), /no claude-code CLI/u)
    } finally {
      rmSync(emptyHome, { recursive: true, force: true })
    }
  })
})