/**
 * The shim: a disposable stdio MCP server in front of the daemon.
 *
 * Launched by a harness (Cursor, Claude Code, OpenCode, Codex) as an MCP stdio server, so
 * its stdin and stdout belong to the MCP protocol. It holds **no secret material** — it
 * owns no vault, opens no keychain item and decrypts nothing. It translates MCP tool calls
 * into daemon requests and hands back the results verbatim.
 *
 * If the shim dies, nothing is lost: the daemon holds all state, and the harness simply
 * restarts the shim.
 */

import { connect } from 'node:net'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'

import { createLogger } from '../core/logging.ts'
import { daemonLockPath, socketPath } from '../core/runtime-paths.ts'
import { buildRequest, encodeFrame, parseFrame, type ClientId } from '../daemon/protocol.ts'
import { TOOL_DEFINITIONS, TOOL_NAMES, type ToolName } from './tools.ts'

const log = createLogger('shim')

/** MCP protocol revision this shim implements. */
const MCP_PROTOCOL_VERSION = '2025-06-18'

const SERVER_INFO = { name: 'vaultbroker', version: '0.1.0' }

/** How long to wait for the daemon to answer before reporting a failure. */
const REQUEST_TIMEOUT_MS = 15_000

export class ShimError extends Error {}

/**
 * One request/response exchange with the daemon.
 *
 * Correlates on the frame `id` rather than assuming responses arrive in order, so a
 * concurrent burst of tool calls cannot be mismatched.
 */
export async function daemonRequest(
  clientId: ClientId,
  command: Parameters<typeof buildRequest>[1],
  params: Readonly<Record<string, unknown>> = {},
  options: { socket?: string | undefined; timeoutMs?: number | undefined } = {},
): Promise<unknown> {
  const target = options.socket ?? socketPath()
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS

  return await new Promise<unknown>((resolve, reject) => {
    const conn = connect(target)
    const frame = buildRequest(clientId, command, params)

    let buffer = ''
    let settled = false

    const finish = (fn: () => void): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      conn.destroy()
      fn()
    }

    const timer = setTimeout(() => {
      finish(() => reject(new ShimError(`daemon did not respond within ${String(timeoutMs)}ms`)))
    }, timeoutMs)
    timer.unref()

    conn.setEncoding('utf8')
    conn.on('connect', () => conn.write(encodeFrame(frame)))

    conn.on('data', (chunk: string) => {
      buffer += chunk
      const newline = buffer.indexOf('\n')
      if (newline === -1) return

      const line = buffer.slice(0, newline)

      try {
        const response = parseFrame(line)
        if (response.kind !== 'response') {
          finish(() => reject(new ShimError('expected a response frame')))
          return
        }

        if (response.ok) {
          finish(() => resolve(response.result))
        } else {
          // Surface the daemon's coarse code, not its internals.
          finish(() => reject(new ShimError(response.error?.message ?? 'daemon reported failure')))
        }
      } catch (error) {
        finish(() =>
          reject(new ShimError(error instanceof Error ? error.message : 'malformed daemon response')),
        )
      }
    })

    conn.on('error', (err: Error) => {
      finish(() => reject(new ShimError(`cannot reach the broker daemon: ${err.message}`)))
    })

    conn.on('close', () => {
      finish(() => reject(new ShimError('daemon closed the connection')))
    })
  })
}

/** Map a tool name to the daemon command that serves it. */
const TOOL_COMMANDS: Readonly<Record<ToolName, Parameters<typeof buildRequest>[1]>> = {
  [TOOL_NAMES.listAccounts]: 'list_accounts',
  [TOOL_NAMES.brokerStatus]: 'status',
  [TOOL_NAMES.callApi]: 'call_api',
}

/**
 * Typed nullable access on a value the SDK gives us as `unknown`, without `any`.
 *
 * The daemon validates every field again — this only keeps the handler from crashing on a
 * malformed `arguments` value.
 */
const arg = (args: unknown, name: string): unknown =>
  args !== null && typeof args === 'object' && !Array.isArray(args)
    ? (args as Record<string, unknown>)[name]
    : undefined

/**
 * Build the MCP server that fronts the daemon.
 *
 * Exported so tests can drive it over an in-memory transport instead of spawning a
 * process, which makes the tool surface assertable without parsing stdio.
 */
export function createShimServer(clientId: ClientId, socket?: string): Server {
  const server = new Server(
    { name: SERVER_INFO.name, version: SERVER_INFO.version },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    })),
  }))

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const requested = request.params.name
    const command = TOOL_COMMANDS[requested as ToolName]

    if (command === undefined) {
      return {
        isError: true,
        content: [{ type: 'text', text: `unknown tool: ${String(requested)}` }],
      }
    }

    try {
      // Meta tools take no arguments. `call_api` forwards the harness's arguments to the
      // daemon, which validates every field before it acts on any of them — the shim does
      // not inspect, log or transform a single value in between.
      const rawArgs = request.params.arguments
      const params: Record<string, unknown> =
        command === 'call_api'
          ? {
              service: arg(rawArgs, 'service'),
              // The tool speaks `account` to a model; the daemon speaks `accountAlias`.
              accountAlias: arg(rawArgs, 'account'),
              operation: arg(rawArgs, 'operation'),
              capabilityId: arg(rawArgs, 'capability_id'),
              projectPath: arg(rawArgs, 'project') ?? process.cwd(),
              params: arg(rawArgs, 'params') ?? {},
            }
          : {}

      const result = await daemonRequest(clientId, command, params, { socket })

      // The daemon's result is returned as-is. There is no credential in it by
      // construction: `list_accounts` returns an explicit field list, never a spread.
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'request failed'
      log.warn('tool call failed', { tool: requested, message })
      return {
        isError: true,
        content: [{ type: 'text', text: message }],
      }
    }
  })

  return server
}

/**
 * Entry point when launched by a harness.
 *
 * The MCP stdio transport owns stdout from here on: nothing else may write to it.
 */
export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const clientId = resolveClientId(argv)
  log.debug('shim starting', { clientId, socket: socketPath(), lock: daemonLockPath() })

  const server = createShimServer(clientId)
  const transport = new StdioServerTransport()

  // Connect before announcing readiness so a missing daemon surfaces as a tool error
  // rather than a silently dead server.
  await server.connect(transport)
  log.info('shim ready', { clientId, protocol: MCP_PROTOCOL_VERSION })
}

/**
 * Determine which harness launched us.
 *
 * Best-effort from argv. Real identity binding — code signature, install path — is I4;
 * today this only selects the policy profile, and a wrong answer is not yet a security
 * boundary. Recorded honestly in README.md.
 */
export function resolveClientId(argv: readonly string[]): ClientId {
  const known: readonly ClientId[] = ['cursor', 'claude-code', 'opencode', 'codex']
  const provided = argv.find((arg) => known.includes(arg as ClientId))
  return (provided as ClientId | undefined) ?? 'cursor'
}

/**
 * Connect an MCP client to a shim in-process.
 *
 * Used by tests to assert the tool surface and its outputs without spawning a process or
 * parsing stdio.
 */
export async function connectInMemory(clientId: ClientId, socket?: string): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createShimServer(clientId, socket)
  await server.connect(serverTransport)

  const client = new Client({ name: 'test-harness', version: '0.0.0' })
  await client.connect(clientTransport)
  return client
}

/**
 * True when this module is the process entry point.
 *
 * Comparing `import.meta.url` to `process.argv[1]` by suffix is fragile: the URL
 * percent-encodes spaces, so a repo checked out under a path containing a space silently
 * never matches and the module quietly does nothing when run directly. Resolve both sides
 * to real paths instead.
 */
function isEntryPoint(): boolean {
  if (process.argv[1] === undefined) return false
  try {
    return fileURLToPath(import.meta.url) === resolve(process.argv[1])
  } catch {
    return false
  }
}

if (isEntryPoint()) {
  main().catch((err: unknown) => {
    // stderr only — stdout belongs to MCP.
    log.error('shim failed to start', { error: err instanceof Error ? err.message : 'unknown' })
    process.exit(1)
  })
}