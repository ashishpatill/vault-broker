/**
 * `vaultbroker client` — register, list and verify harnesses.
 *
 * This is where a harness's grant gets bound to what its binary actually is. Registration
 * inspects the code signature; every subsequent connection is re-verified.
 */

import { CliError, parseArgs, type CommandResult } from './secret.ts'
import { detectHarnesses, mainExecutable, type KnownClient } from '../../install/detect.ts'
import { describeIdentity, inspectSignature } from '../../install/identity.ts'

const KNOWN_CLIENTS: readonly KnownClient[] = ['cursor', 'claude-code', 'opencode', 'codex']

export interface ClientCommandDeps {
  /** Resolve the registration store. Injected so tests avoid the real runtime dir. */
  registry: {
    list(): { clientId: string; label: string; identity: unknown; registeredAt: string }[]
    register(clientId: string, label: string, target: string): { clientId: string; label: string }
    verify(clientId: string, target: string): {
      allowed: boolean
      reason: string | null
      message: string | null
      vaultLocked: boolean
    }
    unregister(clientId: string): boolean
    save(): void
  }
}

function requiredFlag(flags: ReadonlyMap<string, string | true>, name: string): string {
  const value = flags.get(name)
  if (value === undefined || value === true) throw new CliError(`--${name} is required`)
  return value
}

function parseClient(value: string): KnownClient {
  if (!(KNOWN_CLIENTS as readonly string[]).includes(value)) {
    throw new CliError(
      `unknown client: ${value}. Expected one of ${KNOWN_CLIENTS.join(', ')}.`,
    )
  }
  return value as KnownClient
}

export function runClient(
  argv: readonly string[],
  deps: ClientCommandDeps,
): CommandResult {
  const [subcommand, ...rest] = argv
  const { flags } = parseArgs(rest)

  switch (subcommand) {
    case 'detect':
      return runDetect()

    case 'register': {
      const client = parseClient(requiredFlag(flags, 'client'))
      const detected = detectHarnesses().find((h) => h.client === client)
      const target = typeof flags.get('path') === 'string' ? (flags.get('path') as string) : detected?.path

      if (target === undefined) {
        return {
          exitCode: 1,
          output: `${client} is not installed, and no --path was given\n`,
        }
      }

      // Bind to the executable, not the bundle directory: the bundle contains variable
      // content while Contents/MacOS/<name> is the thing that is signed.
      const executable = mainExecutable(target)
      const registration = deps.registry.register(client, detected?.label ?? client, executable)
      deps.registry.save()

      return {
        exitCode: 0,
        output:
          `registered ${registration.label} (${registration.clientId})\n` +
          describeIdentity(inspectSignature(executable)) +
          '\n',
      }
    }

    case 'list': {
      const registrations = deps.registry.list()
      if (registrations.length === 0) {
        return { exitCode: 0, output: 'no clients registered\n' }
      }
      const lines = registrations.map((r) => {
        const identity = r.identity as { teamId: string | null; notarized: boolean }
        return (
          `${r.clientId.padEnd(12)} ${r.label.padEnd(14)} team=${identity.teamId ?? 'none'}` +
          ` notarized=${identity.notarized ? 'yes' : 'no'}  since ${r.registeredAt.slice(0, 10)}`
        )
      })
      return { exitCode: 0, output: `${lines.join('\n')}\n` }
    }

    case 'verify': {
      const client = parseClient(requiredFlag(flags, 'client'))
      const detected = detectHarnesses().find((h) => h.client === client)
      const target = typeof flags.get('path') === 'string' ? (flags.get('path') as string) : detected?.path

      if (target === undefined) {
        return { exitCode: 1, output: `${client} is not installed\n` }
      }

      const outcome = deps.registry.verify(client, mainExecutable(target))
      if (outcome.allowed) {
        return { exitCode: 0, output: `${client}: identity verified\n` }
      }
      return {
        exitCode: 1,
        output: `${client}: REFUSED (${outcome.reason ?? 'unknown'})\n${outcome.message ?? ''}\n`,
      }
    }

    case 'unregister': {
      const client = parseClient(requiredFlag(flags, 'client'))
      const removed = deps.registry.unregister(client)
      deps.registry.save()
      return {
        exitCode: removed ? 0 : 1,
        output: removed ? `unregistered ${client}; its grants were revoked\n` : `${client} was not registered\n`,
      }
    }

    default:
      throw new CliError(
        `unknown subcommand: ${subcommand ?? '(none)'}. Expected detect, register, list, verify or unregister.`,
      )
  }
}

function runDetect(): CommandResult {
  const found = detectHarnesses()
  if (found.length === 0) {
    return { exitCode: 0, output: 'no supported harnesses detected\n' }
  }

  const lines = found.map((h) => {
    let status = 'unknown'
    try {
      const identity = inspectSignature(mainExecutable(h.path))
      status = identity.signatureValid
        ? `${identity.teamId ?? 'no-team'}${identity.notarized ? ', notarized' : ''}`
        : 'INVALID SIGNATURE'
    } catch (error) {
      status = `error: ${error instanceof Error ? error.message : 'unknown'}`
    }
    return `${h.client.padEnd(12)} ${h.label.padEnd(14)} ${status.padEnd(28)} ${h.path}`
  })

  return { exitCode: 0, output: `${lines.join('\n')}\n` }
}

