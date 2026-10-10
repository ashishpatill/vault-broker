/**
 * `vaultbroker secret` — add, list, rotate and remove credentials.
 *
 * Every command here handles credential material, so the shape of this file matters:
 * a credential is accepted as a `Secret<T>` and leaves only through
 * {@link Secret.withEnvVar}, which scopes it to a single child-process read. Nothing in
 * this file may log, echo, or interpolate a plaintext value — including in error paths.
 *
 * Input handling note: secrets are read from a file descriptor rather than from argv or
 * an argument, for the same `ps`-visibility reason that governs the keychain. Accepting
 * `--token abc123` would put the credential in the process table and in shell history.
 */

import { readFileSync } from 'node:fs'

import { InMemoryKeychain, MacSecurityKeychain, type KeychainStore } from '../../core/keychain.ts'
import { Secret } from '../../core/secret.ts'
import { Vault, VaultError, type VaultEntry } from '../../core/vault.ts'

export class CliError extends Error {}

interface ParsedArgs {
  readonly positional: readonly string[]
  readonly flags: ReadonlyMap<string, string | true>
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const positional: string[] = []
  const flags = new Map<string, string | true>()

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === undefined) continue

    if (arg.startsWith('--')) {
      const body = arg.slice(2)
      const eq = body.indexOf('=')
      if (eq !== -1) {
        flags.set(body.slice(0, eq), body.slice(eq + 1))
        continue
      }
      // `--flag value`, but only when the next token is not itself a flag.
      const next = argv[i + 1]
      if (next !== undefined && !next.startsWith('--')) {
        flags.set(body, next)
        i += 1
      } else {
        flags.set(body, true)
      }
      continue
    }

    positional.push(arg)
  }

  return { positional, flags }
}

function required(flags: ReadonlyMap<string, string | true>, name: string): string {
  const value = flags.get(name)
  if (value === undefined || value === true) {
    throw new CliError(`--${name} is required`)
  }
  return value
}

/**
 * Read a credential without materialising it in a string we control.
 *
 * Supports `--from-file <path>` and stdin (`--from-stdin`). Rejects `--value` outright:
 * offering it would invite the exact argv leak this product exists to prevent, and a
 * flag that exists will eventually be used.
 */
function readSecretInput(flags: ReadonlyMap<string, string | true>): Secret {
  if (flags.has('value')) {
    throw new CliError(
      '--value is not supported: command-line arguments are visible in `ps` and shell ' +
        'history. Use --from-file <path> or --from-stdin.',
    )
  }

  const fromFile = flags.get('from-file')
  if (fromFile !== undefined && fromFile !== true) {
    try {
      return Secret.fromBuffer(readFileSync(fromFile))
    } catch (cause) {
      throw new CliError(
        `could not read --from-file: ${cause instanceof Error ? cause.message : 'unknown error'}`,
      )
    }
  }

  if (flags.get('from-stdin') === true) {
    try {
      return Secret.fromBuffer(readFileSync(0))
    } catch (cause) {
      throw new CliError(
        `could not read stdin: ${cause instanceof Error ? cause.message : 'unknown error'}`,
      )
    }
  }

  throw new CliError('provide the credential via --from-file <path> or --from-stdin')
}

/**
 * Resolve the keychain.
 *
 * `override` exists so tests can supply a store that survives across calls. Without it a
 * test that runs `add` then `list` would lose the KEK between the two and the second
 * command would correctly refuse — which is the right production behaviour but makes
 * multi-command tests impossible to write.
 */
function openKeychain(flags: ReadonlyMap<string, string | true>, override?: KeychainStore): KeychainStore {
  if (override !== undefined) return override
  return flags.get('memory') === true ? new InMemoryKeychain() : new MacSecurityKeychain()
}

export interface CommandResult {
  readonly exitCode: number
  readonly output: string
}

/**
 * `vaultbroker secret <add|list|show|rotate|remove> ...`
 *
 * Returns a string rather than writing directly, so tests can assert on the exact
 * output and confirm no credential is ever part of it.
 */
export function runSecret(argv: readonly string[], keychainOverride?: KeychainStore): CommandResult {
  const [subcommand, ...rest] = argv
  const { flags } = parseArgs(rest)
  const keychain = openKeychain(flags, keychainOverride)

  switch (subcommand) {
    case 'add': {
      const vault = Vault.open(keychain)
      try {
        const secret = readSecretInput(flags)
        try {
          const entry = vault.add({
            service: required(flags, 'service'),
            accountAlias: required(flags, 'account'),
            secret,
            ...(typeof flags.get('type') === 'string' ? { secretType: flags.get('type') as string } : {}),
            ...(typeof flags.get('note') === 'string' ? { note: flags.get('note') as string } : {}),
          })
          return { exitCode: 0, output: `added ${entry.service}/${entry.accountAlias} (${entry.secretType})\n` }
        } finally {
          secret.dispose()
        }
      } finally {
        vault.dispose()
      }
    }

    case 'list': {
      const vault = Vault.open(keychain)
      try {
        const entries = vault.list()
        if (entries.length === 0) {
          return { exitCode: 0, output: 'no credentials stored\n' }
        }
        return { exitCode: 0, output: renderTable(entries) }
      } finally {
        vault.dispose()
      }
    }

    case 'show': {
      const vault = Vault.open(keychain)
      try {
        const entry = vault.find(required(flags, 'service'), required(flags, 'account'))
        if (entry === undefined) {
          return { exitCode: 1, output: 'not found\n' }
        }
        return { exitCode: 0, output: `${JSON.stringify(entry, null, 2)}\n` }
      } finally {
        vault.dispose()
      }
    }

    case 'rotate': {
      const vault = Vault.open(keychain)
      try {
        const service = required(flags, 'service')
        const account = required(flags, 'account')

        // Check existence before prompting for the credential, so a typo does not ask
        // the user to paste a token that cannot be stored.
        if (vault.find(service, account) === undefined) {
          return { exitCode: 1, output: `not found: ${service}/${account}\n` }
        }

        const secret = readSecretInput(flags)
        try {
          const entry = vault.rotate(service, account, secret)
          return { exitCode: 0, output: `rotated ${entry.service}/${entry.accountAlias}\n` }
        } finally {
          secret.dispose()
        }
      } finally {
        vault.dispose()
      }
    }

    case 'remove': {
      const vault = Vault.open(keychain)
      try {
        const removed = vault.remove(required(flags, 'service'), required(flags, 'account'))
        return removed
          ? { exitCode: 0, output: 'removed\n' }
          : { exitCode: 1, output: 'not found\n' }
      } finally {
        vault.dispose()
      }
    }

    default:
      throw new CliError(
        `unknown subcommand: ${subcommand ?? '(none)'}. Expected add, list, show, rotate or remove.`,
      )
  }
}

/** Render credential metadata as an aligned table. Contains no secret values. */
function renderTable(entries: readonly VaultEntry[]): string {
  const headers = ['SERVICE', 'ACCOUNT', 'TYPE', 'CREATED', 'ROTATED'] as const
  const rows = entries.map((e) => [
    e.service,
    e.accountAlias,
    e.secretType,
    e.createdAt.slice(0, 10),
    e.rotatedAt === null ? '-' : e.rotatedAt.slice(0, 10),
  ])

  const widths = headers.map((header, i) =>
    Math.max(header.length, ...rows.map((row) => (row[i] ?? '').length)),
  )

  const line = (cells: readonly string[]): string =>
    cells.map((cell, i) => cell.padEnd(widths[i] ?? 0)).join('  ').trimEnd()

  return [line(headers), line(widths.map((w) => '-'.repeat(w))), ...rows.map(line)].join('\n') + '\n'
}

export { VaultError }