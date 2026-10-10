/**
 * CLI tests.
 *
 * These exercise the commands against a real vault on disk in a temp directory, using
 * the in-memory keychain. Two things are asserted throughout:
 *
 *   - command output never contains the credential;
 *   - the credential never appears in argv, which is why `--value` is rejected outright.
 */

import { strict as assert } from 'node:assert'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, test } from 'node:test'

import { CliError, parseArgs, runSecret, type CommandResult } from '../src/cli/commands/secret.ts'
import { InMemoryKeychain, type KeychainStore } from '../src/core/keychain.ts'

import { HOME_ENV_VAR, runtimeRoot, vaultPath } from '../src/core/runtime-paths.ts'

const CANARY = 'cli-canary-8a2f6e1b-do-not-print'
let dir: string
let tokenFile: string
let runtime: string
const originalHome = process.env[HOME_ENV_VAR]

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vaultbroker-cli-'))
  tokenFile = join(dir, 'token.txt')
  runtime = join(dir, 'runtime')
  writeFileSync(tokenFile, CANARY)

  // Point the runtime directory at the sandbox. `--memory` only isolates the keychain —
  // without this the tests would write a real vault into ~/Library/Application Support.
  process.env[HOME_ENV_VAR] = runtime
})

afterEach(() => {
  if (originalHome === undefined) delete process.env[HOME_ENV_VAR]
  else process.env[HOME_ENV_VAR] = originalHome
  rmSync(dir, { recursive: true, force: true })
})

/**
 * Run a command against a throwaway vault.
 *
 * The keychain must persist *across* calls within a test — each `runSecret` opens a
 * fresh Vault, so a per-call InMemoryKeychain would lose the KEK between commands and the
 * second call would correctly refuse. One store per test is created lazily and reused.
 */
let sharedKeychain: InMemoryKeychain | undefined

function run(...argv: string[]) {
  sharedKeychain ??= new InMemoryKeychain()
  return runSecretWith(argv, sharedKeychain)
}

/** Invoke the command with an injected keychain, bypassing `--memory`. */
function runSecretWith(argv: readonly string[], keychain: KeychainStore): CommandResult {
  // Inject through the documented flag path rather than a private backdoor.
  return runSecret(argv, keychain)
}

describe('parseArgs', () => {
  test('separates positionals from flags', () => {
    const { positional, flags } = parseArgs(['add', '--service', 'github', '--account', 'work'])
    assert.deepEqual(positional, ['add'])
    assert.equal(flags.get('service'), 'github')
    assert.equal(flags.get('account'), 'work')
  })

  test('supports --flag=value', () => {
    const { flags } = parseArgs(['--service=github', '--account=work'])
    assert.equal(flags.get('service'), 'github')
    assert.equal(flags.get('account'), 'work')
  })

  test('supports boolean flags', () => {
    const { flags } = parseArgs(['--from-stdin', '--memory'])
    assert.equal(flags.get('from-stdin'), true)
    assert.equal(flags.get('memory'), true)
  })

  test('does not swallow the next positional as a flag value', () => {
    // `--memory` is a boolean, so `list` must survive as a positional. A greedy parser
    // would consume it and `runSecret` would never see the subcommand.
    const { positional, flags } = parseArgs(['list', '--memory'])
    assert.deepEqual(positional, ['list'])
    assert.equal(flags.get('memory'), true)
  })
})

describe('secret commands', () => {
  test('add, list, show, rotate and remove work end to end', () => {
    const added = run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile, '--type', 'bearer')
    assert.equal(added.exitCode, 0)
    assert.match(added.output, /added github\/work \(bearer\)/u)

    const listed = run('list')
    assert.match(listed.output, /github/u)
    assert.match(listed.output, /work/u)

    const shown = run('show', '--service', 'github', '--account', 'work')
    assert.equal(shown.exitCode, 0)
    assert.match(shown.output, /"accountAlias": "work"/u)

    writeFileSync(tokenFile, 'rotated-value')
    const rotated = run('rotate', '--service', 'github', '--account', 'work', '--from-file', tokenFile)
    assert.equal(rotated.exitCode, 0)

    const removed = run('remove', '--service', 'github', '--account', 'work')
    assert.equal(removed.exitCode, 0)

    const after = run('list')
    assert.match(after.output, /no credentials stored/u)
  })

  test('no command output ever contains the credential', () => {
    run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile)

    const outputs = [
      run('list'),
      run('show', '--service', 'github', '--account', 'work'),
      run('show', '--service', 'nope', '--account', 'nope'),
      run('remove', '--service', 'nope', '--account', 'nope'),
      run('rotate', '--service', 'nope', '--account', 'nope', '--from-file', tokenFile),
    ]

    for (const result of outputs) {
      assert.ok(!result.output.includes(CANARY), `CLI leaked the credential: ${result.output}`)
    }
  })

  test('rejects --value, which would put the credential in argv', () => {
    assert.throws(
      () => run('add', '--service', 'github', '--account', 'work', '--value', CANARY),
      (err: unknown) => err instanceof CliError && /visible in `ps`/u.test(err.message),
    )
  })

  test('requires --from-file or --from-stdin', () => {
    assert.throws(
      () => run('add', '--service', 'github', '--account', 'work'),
      (err: unknown) => err instanceof CliError && /from-file/u.test(err.message),
    )
  })

  test('requires --service and --account', () => {
    assert.throws(
      () => run('add', '--account', 'work', '--from-file', tokenFile),
      (err: unknown) => err instanceof CliError && /--service is required/u.test(err.message),
    )
  })

  test('reports a missing file without leaking anything', () => {
    assert.throws(
      () => run('add', '--service', 'github', '--account', 'work', '--from-file', join(dir, 'nope.txt')),
      (err: unknown) => err instanceof CliError && /could not read --from-file/u.test(err.message),
    )
  })

  test('rejects an unknown subcommand', () => {
    assert.throws(
      () => run('frobnicate'),
      (err: unknown) => err instanceof CliError && /unknown subcommand/u.test(err.message),
    )
  })

  test('refuses to add a duplicate credential', () => {
    run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile)
    assert.throws(() => run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile))
  })

  test('the vault lands in the sandboxed runtime dir, not the real one', () => {
    run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile)

    // Guards the test harness itself: if this regressed, every CLI test would be writing
    // into the user's real runtime directory.
    assert.equal(runtimeRoot(), runtime)
    assert.ok(readFileSync(vaultPath(), 'utf8').length > 0)
  })

  test('the stored credential never appears in the vault file on disk', () => {
    run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile)

    const contents = readFileSync(vaultPath(), 'utf8')
    assert.ok(!contents.includes(CANARY), 'vault file must not contain the plaintext')
    assert.ok(!contents.includes('github'), 'service name must not appear in the clear')
  })

  test('list renders a table with aligned columns', () => {
    run('add', '--service', 'github', '--account', 'work', '--from-file', tokenFile)
    run('add', '--service', 'neon', '--account', 'a-very-long-account-alias', '--from-file', tokenFile)

    const listed = run('list')
    const [header, divider, ...rows] = listed.output.trimEnd().split('\n')

    assert.ok(header?.includes('SERVICE'), 'expected a header row')
    assert.ok(divider?.startsWith('---'), 'expected a divider row')
    assert.equal(rows.length, 2)

    // Header column positions must line up with the data beneath them. Asserting per
    // service rather than "both appear in every row" — the second row legitimately does
    // not contain 'github', so that formulation tested nothing.
    const serviceColumn = header?.indexOf('SERVICE') ?? -1
    assert.ok(serviceColumn >= 0, 'header must contain SERVICE')

    for (const row of rows) {
      for (const service of ['github', 'neon']) {
        if (row.startsWith(service)) {
          assert.equal(
            row.indexOf(service),
            serviceColumn,
            `column for ${service} should start at ${serviceColumn}`,
          )
        }
      }
    }

    // And every row must line up with the divider under its header.
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i] ?? ''
      const dividerRow = divider ?? ''
      assert.equal(
        row.slice(0, serviceColumn),
        dividerRow.slice(0, serviceColumn),
        `row ${i} does not align with the header`,
      )
    }
  })
})