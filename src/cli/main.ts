#!/usr/bin/env node
/**
 * VaultBroker CLI entry point.
 *
 * Kept deliberately thin: argument parsing and dispatch only. Anything that touches
 * credentials lives behind a `Secret<T>` (src/core/secret.ts) so that no command handler
 * can accidentally print one.
 */

import { runInit, printInit } from './commands/init.ts'
import { runPolicy } from './commands/policy.ts'
import { runClient } from './commands/client.ts'
import { CliError, runSecret, type CommandResult } from './commands/secret.ts'
import { runImport, runConfigMigration, runConfigRollback } from './commands/config.ts'
import { AuditLog } from '../core/audit.ts'
import { PolicyEngine } from '../core/policy.ts'
import { auditLogPath } from '../core/runtime-paths.ts'
import { ClientRegistry } from '../install/registry.ts'

const USAGE = `vaultbroker — local credential broker for AI harnesses

Usage:
  vaultbroker init                       Create the runtime directory
  vaultbroker secret list                List stored credentials (metadata only)
  vaultbroker secret add                 Store a credential
  vaultbroker secret show                Show one credential's metadata
  vaultbroker secret rotate              Replace a credential's secret
  vaultbroker secret remove              Delete a credential
  vaultbroker policy grant               Create a scoped, expiring grant
  vaultbroker policy list                List active grants
  vaultbroker policy describe --id <id>  Show one grant in full
  vaultbroker policy approve             Approve one sensitive operation, once
  vaultbroker policy revoke              Revoke a grant, or every grant for a client
  vaultbroker policy audit               Show recent audit events
  vaultbroker policy verify              Verify the audit hash chain
  vaultbroker client detect              List installed harnesses and their signatures
  vaultbroker client register            Bind a harness to its verified code signature
  vaultbroker client list                Show registered clients
  vaultbroker client verify             Re-verify one client's identity now
  vaultbroker client unregister         Remove a client and revoke its grants

Token migration:
  vaultbroker import --from-config      Move a plaintext token into the vault
  vaultbroker config migrate            Rewrite a config to stop carrying the token
  vaultbroker config rollback           Restore the pre-migration config byte-for-byte

Credential input (never argv — argv is visible in \`ps\` and shell history):
  --from-file <path>   Read the credential from a file
  --from-stdin         Read the credential from stdin

Common flags:
  --service <name>     Service identifier, e.g. github
  --account <alias>    Account alias, e.g. work
  --type <kind>        Credential type, e.g. bearer
  --note <text>        Free-form note
  --memory             Use a throwaway in-memory vault (testing)

Policy flags:
  --client <id>        cursor | claude-code | opencode | codex
  --project <path>     Directory the grant is bound to
  --operations <list>  Comma-separated, e.g. github.repo.read,github.pr.create
  --ttl <minutes>      Grant lifetime, capped at 480

Approving an operation is a CLI-only command on purpose: an approval a model could
request would not be an approval.

Examples:
  vaultbroker secret add --service github --account work --from-file ./token
  pbpaste | vaultbroker secret add --service github --account work --from-stdin
  vaultbroker policy grant --client cursor --service github --account work \\
    --project ~/src/acme --operations github.repo.read,github.pr.create --ttl 60
  vaultbroker policy approve --client cursor --service github --account work \\
    --project ~/src/acme --operation github.release.create

Status: v0.1 — call_api brokered end to end; installer lands with I7.
`

async function main(argv: string[]): Promise<number> {
  const [command = 'help', ...rest] = argv

  switch (command) {
    case 'init': {
      if (rest.length > 0) {
        process.stderr.write(`init takes no arguments (got: ${rest.join(' ')})\n`)
        return 2
      }
      printInit(runInit())
      return 0
    }

    case 'secret': {
      const result: CommandResult = runSecret(rest)
      // stdout for success, stderr for a "not found" style failure, so the command is
      // scriptable.
      const stream = result.exitCode === 0 ? process.stdout : process.stderr
      stream.write(result.output)
      return result.exitCode
    }

    case 'policy': {
      const result: CommandResult = runPolicy(rest)
      const stream = result.exitCode === 0 ? process.stdout : process.stderr
      stream.write(result.output)
      return result.exitCode
    }

    case 'client': {
      // The registry is constructed here rather than imported as a singleton so a CLI
      // invocation reads the persisted registrations instead of mutating daemon state.
      const policy = new PolicyEngine({ audit: AuditLog.open(auditLogPath()) })
      const registry = ClientRegistry.load({ policy })

      const result = runClient(rest, { registry })
      const stream = result.exitCode === 0 ? process.stdout : process.stderr
      stream.write(result.output)
      return result.exitCode
    }

    case 'import': {
      const result: CommandResult = runImport(rest)
      const stream = result.exitCode === 0 ? process.stdout : process.stderr
      stream.write(result.output)
      return result.exitCode
    }

    case 'config': {
      // `config migrate` and `config rollback` share one dispatcher: argv[0] selects.
      const [subcommand, ...sub] = rest
      const result: CommandResult =
        subcommand === 'migrate'
          ? runConfigMigration(sub)
          : subcommand === 'rollback'
            ? runConfigRollback(sub)
            : {
                exitCode: 2,
                output: `unknown config command: ${String(subcommand)} (use migrate or rollback)\n`,
              }
      const stream = result.exitCode === 0 ? process.stdout : process.stderr
      stream.write(result.output)
      return result.exitCode
    }

    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(USAGE)
      return 0

    default:
      process.stderr.write(`Unknown command: ${command}\n\n${USAGE}`)
      return 2
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code
  })
  .catch((err: unknown) => {
    // Never echo a possibly-sensitive value out of an error object. Only our own typed
    // errors are printed verbatim; anything else is reported by category, because an
    // unexpected error may have a credential embedded in its message.
    if (err instanceof CliError) {
      process.stderr.write(`vaultbroker: ${err.message}\n`)
    } else if (err instanceof Error) {
      process.stderr.write(`vaultbroker: unexpected error (${err.constructor.name})\n`)
    } else {
      process.stderr.write('vaultbroker: unexpected error\n')
    }
    process.exitCode = 1
  })