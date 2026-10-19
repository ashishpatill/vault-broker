/**
 * Import and config-migration tests.
 *
 * These cover the plaintext-token migration path with a synthetic credential. The
 * candidate below keeps the `napi_` prefix so the sweep patterns fire on it, and nothing
 * else about it is provider-shaped; its listing in `.pushguard-allow` attests that it is
 * a fixture, not a real credential.
 */

import { strict as assert } from 'node:assert'
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, test } from 'node:test'

import {
  findServiceEntry,
  runConfigMigration,
  runConfigRollback,
  runImport,
  sweepCredentialPatterns,
} from '../src/cli/commands/config.ts'
import { HOME_ENV_VAR, runtimeRoot } from '../src/core/runtime-paths.ts'

/**
 * Synthetic token for this suite only. Only the `napi_` prefix matches a provider
 * pattern; the body is an unmistakable fixture string.
 */
const FAKE_TOKEN = 'napi_TESTFIXTUREabcdef0123456789ghij'

function fakeConfig(withNeon: boolean = true): string {
  return JSON.stringify(
    {
      composerDisabled: false,
      mcpServers: {
        icm: { command: 'npx', args: ['-y', 'icm-mcp'] },
        tell: { command: 'npx', args: ['-y', 'tell-mcp'] },
        ...(withNeon
          ? { Neon: { command: 'npx', args: ['-y', 'neon-mcp'], env: { NEON_API_TOKEN: FAKE_TOKEN } } }
          : {}),
      },
    },
    null,
    2,
  )
}

function output(result: { output: string }): string {
  return `output was: ${result.output}`
}

describe('import from config', () => {
  const scratch: string[] = []
  let priorHome: string | undefined

  beforeEach(() => {
    priorHome = process.env[HOME_ENV_VAR]
    const root = mkdtempSync(join(tmpdir(), 'vbimport-'))
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

  test('stores the token and reports metadata without printing it', () => {
    const configPath = join(runtimeRoot(), 'cursor-mcp.json')
    writeFileSync(configPath, fakeConfig())

    const result = runImport([
      '--from-config',
      '--service',
      'neon',
      '--account',
      'work',
      '--memory',
      '--config',
      configPath,
    ])

    assert.equal(result.exitCode, 0, output(result))
    assert.ok(result.output.includes('imported neon/work'), output(result))
    assert.ok(result.output.includes('bearer'), output(result))
    assert.ok(!result.output.includes(FAKE_TOKEN), 'output carries the credential')
    assert.ok(result.output.includes('bytes'), output(result))
  })

  test('the sweep counts the token in the source before migration', () => {
    const configPath = join(runtimeRoot(), 'cursor-mcp.json')
    writeFileSync(configPath, fakeConfig())

    const counts = sweepCredentialPatterns([configPath])
    assert.equal(counts[configPath], 1)
  })

  test('a config with no matching entry fails coarsely', () => {
    const configPath = join(runtimeRoot(), 'cursor-mcp.json')
    writeFileSync(configPath, fakeConfig(false))

    const result = runImport(['--from-config', '--memory', '--config', configPath])
    assert.notEqual(result.exitCode, 0)
    assert.ok(result.output.includes('no server entry'), output(result))
  })

  test('entry lookup tolerates real-world naming variants', () => {
    const found = findServiceEntry(JSON.parse(fakeConfig(true)), 'neon')
    assert.ok(!(found instanceof Error), 'expected the Neon entry to be found')
    if (!(found instanceof Error)) assert.equal(found.name, 'Neon')
  })

  test('import leaves the source config untouched', () => {
    const configPath = join(runtimeRoot(), 'cursor-mcp.json')
    writeFileSync(configPath, fakeConfig())
    const original = readFileSync(configPath, 'utf8')

    const result = runImport(['--from-config', '--memory', '--config', configPath])
    assert.equal(result.exitCode, 0)
    assert.equal(readFileSync(configPath, 'utf8'), original, 'import rewrote the source config')
  })
})

describe('config migrate', () => {
  const scratch: string[] = []
  let priorHome: string | undefined

  beforeEach(() => {
    priorHome = process.env[HOME_ENV_VAR]
    const root = mkdtempSync(join(tmpdir(), 'vbmigrate-'))
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

  /** Write the fixture config and snapshot the original bytes for later comparisons. */
  function prepareConfig(): { path: string; bytes: Buffer; mode: number } {
    const configPath = join(runtimeRoot(), 'cursor-mcp.json')
    writeFileSync(configPath, fakeConfig())
    return { path: configPath, bytes: readFileSync(configPath), mode: statSync(configPath).mode & 0o7777 }
  }

  test('dry run proposes the removal and writes nothing', () => {
    const config = prepareConfig()

    const result = runConfigMigration(['--config', config.path])
    assert.equal(result.exitCode, 0, output(result))
    assert.ok(result.output.includes('dry run'), output(result))
    assert.ok(result.output.includes('Neon'), output(result))
    assert.ok(!result.output.includes(FAKE_TOKEN), 'output carries the credential')
    assert.ok(
      readFileSync(config.path).equals(config.bytes),
      'the dry run wrote to the config',
    )
  })

  test('--yes removes only the Neon entry and the token with it', () => {
    const config = prepareConfig()

    const result = runConfigMigration(['--config', config.path, '--yes'])
    assert.equal(result.exitCode, 0, output(result))

    const parsed = JSON.parse(readFileSync(config.path, 'utf8')) as {
      mcpServers: Record<string, { command: string }>
    }
    assert.deepEqual(Object.keys(parsed.mcpServers), ['icm', 'tell'])
    assert.equal(parsed.mcpServers['icm']?.command, 'npx')
    assert.ok(!readFileSync(config.path, 'utf8').includes(FAKE_TOKEN), 'the token survived the rewrite')

    const counts = sweepCredentialPatterns([config.path])
    assert.equal(counts[config.path], 0)
  })

  test('a verified backup exists after migration and matches the original bytes', () => {
    const config = prepareConfig()
    const originalDigest = createHash('sha256').update(config.bytes).digest('hex')

    const result = runConfigMigration(['--config', config.path, '--yes'])
    assert.equal(result.exitCode, 0, output(result))

    const backupsDir = join(runtimeRoot(), 'backups')
    assert.ok(existsSync(backupsDir), 'no backup directory was created')

    const names = readdirSync(backupsDir)
    const metaName = names.find((name) => name.endsWith('.json'))
    assert.ok(metaName !== undefined, 'no backup metadata was written')

    const meta = JSON.parse(readFileSync(join(backupsDir, metaName), 'utf8')) as {
      sha256: string
      originalPath: string
    }
    assert.equal(meta.sha256, originalDigest, 'the backup hash does not match the original')
    assert.equal(meta.originalPath, config.path)

    const bakName = names.find((name) => name.endsWith('.bak'))
    assert.ok(bakName !== undefined, 'no backup payload was written')
    assert.ok(
      readFileSync(join(backupsDir, bakName)).equals(config.bytes),
      'the backup payload is not byte-identical',
    )
  })

  test('rollback restores the original bytes and file mode', () => {
    const config = prepareConfig()

    const migrated = runConfigMigration(['--config', config.path, '--yes'])
    assert.equal(migrated.exitCode, 0, output(migrated))

    const undone = runConfigRollback([])
    assert.equal(undone.exitCode, 0, undone.output)

    assert.ok(
      readFileSync(config.path).equals(config.bytes),
      'rollback is not byte-identical to the original',
    )
    assert.equal(statSync(config.path).mode & 0o7777, config.mode, 'rollback changed the file mode')

    const counts = sweepCredentialPatterns([config.path])
    assert.equal(counts[config.path], 1, 'the restored file should carry the fixture again')
  })

  test('a corrupted backup refuses to restore', () => {
    const config = prepareConfig()

    const migrated = runConfigMigration(['--config', config.path, '--yes'])
    assert.equal(migrated.exitCode, 0, output(migrated))
    const backupsDir = join(runtimeRoot(), 'backups')
    const backups = readdirSync(backupsDir).filter((name) => name.endsWith('.bak'))
    assert.ok(backups.length > 0)
    const victim = join(backupsDir, backups.sort().at(-1) as string)
    const bytes = readFileSync(victim)
    const first = bytes[0]
    assert.ok(first !== undefined, 'the backup payload is empty')
    bytes[0] = first ^ 0x01
    writeFileSync(victim, bytes)

    const refused = runConfigRollback([])
    assert.notEqual(refused.exitCode, 0, 'rollback accepted a corrupted backup')
    assert.ok(refused.output.includes('does not match'), output(refused))

    // The config stays in its migrated state: refusing a bad restore must not half-apply.
    const after = JSON.parse(readFileSync(config.path, 'utf8')) as { mcpServers: Record<string, unknown> }
    assert.ok(!('Neon' in after.mcpServers), 'a refused rollback rewrote the config')
  })

  test('no migration output ever carries the plaintext token', () => {
    const config = prepareConfig()

    const migrated = runConfigMigration(['--config', config.path, '--yes'])
    assert.ok(!migrated.output.includes(FAKE_TOKEN), 'migration output carries the credential')

    const undone = runConfigRollback([])
    assert.ok(!undone.output.includes(FAKE_TOKEN), 'rollback output carries the credential')
  })
})
