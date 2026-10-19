/**
 * Status command tests.
 *
 * The assertion that matters most here: a canary planted in a config surface shows up
 * as a *count* in the residual section and as nothing else. `status` is the operator's
 * window into the broker; a window that leaks the thing it secures would be self-defeating.
 */

import { strict as assert } from 'node:assert'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, beforeEach, describe, test } from 'node:test'

import { runStatus } from '../src/cli/commands/status.ts'
import { auditLogPath, HOME_ENV_VAR, runtimeRoot } from '../src/core/runtime-paths.ts'
import { configPathFor } from '../src/install/install.ts'
import { AuditLog } from '../src/core/audit.ts'

/** Planted only to catch it escaping; must appear nowhere in output. */
const CANARY = 'napi_CONFORMANCETOKENABCDEFGHIJKLMNOPQRSTUVWXYZ0123'

function seedGrantFile(grants: object[]): void {
  mkdirSync(dirname(auditLogPath()), { recursive: true })
  writeFileSync(join(dirname(auditLogPath()), 'grants.json'), JSON.stringify(grants, null, 2))
}

describe('vaultbroker status', () => {
  const scratch: string[] = []
  let priorHome: string | undefined

  beforeEach(() => {
    priorHome = process.env[HOME_ENV_VAR]
    const root = mkdtempSync(join(tmpdir(), 'vbstatus-'))
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

  test('runs clean on an empty runtime and states every section', () => {
    const result = runStatus(['--memory'])
    assert.equal(result.exitCode, 0)
    for (const section of ['runtime', 'vault', 'grants', 'audit', 'clients', 'adapters', 'residual']) {
      assert.ok(result.output.includes(section), `missing section: ${section}`)
    }
    assert.ok(result.output.includes('neon: 3 op(s)'), 'adapter panel inventories operations')
  })

  test('reports live versus expired grants', () => {
    seedGrantFile([
      { id: 'cap-future', clientId: 'cursor', expiresAt: '2099-01-01T00:00:00Z' },
      { id: 'cap-past', clientId: 'cursor', expiresAt: '2020-01-01T00:00:00Z' },
    ])

    const result = runStatus(['--memory'])
    assert.ok(result.output.includes('1 live, 1 expired'), result.output)
  })

  test('verifies the audit chain when one exists', () => {
    mkdirSync(dirname(auditLogPath()), { recursive: true })
    // AuditLog.open with an explicit path appends and writes through; two events bind a chain.
    const log = AuditLog.open(auditLogPath())
    log.append({ kind: 'test.event', severity: 'info' }, new Date())
    log.append({ kind: 'test.event', severity: 'info' }, new Date())

    const result = runStatus(['--memory'])
    assert.ok(result.output.includes('chain verified'), result.output)
    assert.ok(result.output.includes('2 event(s)'), result.output)
  })

  test('a planted config token shows as a residual count and never as a value', () => {
    const configPath = configPathFor('cursor')
    mkdirSync(dirname(configPath), { recursive: true })
    writeFileSync(configPath, JSON.stringify({ mcpServers: { Neon: { env: { NEON_API_TOKEN: CANARY } } } }))

    const result = runStatus(['--memory'])
    assert.equal(result.exitCode, 0)
    assert.ok(result.output.includes(`FOUND ${String(1)}`), `residual count missing:\n${result.output}`)
    assert.ok(!result.output.includes(CANARY), 'status output carries the credential')
    assert.ok(result.output.includes(configPath), 'residual panel must name the file')
  })

  test('unregistered clients say so rather than hiding the panel', () => {
    const result = runStatus(['--memory'])
    assert.ok(result.output.includes('none registered'), result.output)
  })

  test('the runtime mode finding fires when the directory is too open', () => {
    mkdirSync(runtimeRoot(), { recursive: true, mode: 0o700 })
    chmodSync(runtimeRoot(), 0o755)

    const result = runStatus(['--memory'])
    assert.ok(result.output.includes('TOO PERMISSIVE'), result.output)
  })
})
