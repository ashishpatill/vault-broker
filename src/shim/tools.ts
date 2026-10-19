/**
 * MCP tool surface exposed to harnesses.
 *
 * This is the trust boundary a harness sees, so the list is short and deliberate.
 *
 * Tools that must never appear here:
 *   get_secret / read_secret / export / copy_to_clipboard — anything returning a credential.
 *   A generic run_shell(command, with_credential) — unrestricted secret delegation, which
 *   defeats the entire product. Written into the spec as an automatic failure.
 *
 * What IS here is capability-shaped: the harness asks for an *action*, the broker performs
 * it, and only the business result comes back.
 */

import type { AccountSummary, DaemonStatus } from '../daemon/session.ts'

/**
 * Tool names.
 *
 * A const object rather than string literals scattered across handlers, so the tool
 * surface can be enumerated in one place and asserted on in tests.
 */
export const TOOL_NAMES = {
  listAccounts: 'list_accounts',
  brokerStatus: 'broker_status',
  callApi: 'call_api',
} as const

export type ToolName = (typeof TOOL_NAMES)[keyof typeof TOOL_NAMES]

export interface ToolDefinition {
  readonly name: ToolName
  readonly description: string
  readonly inputSchema: {
    readonly type: 'object'
    readonly properties: Readonly<Record<string, unknown>>
    readonly additionalProperties: false
  }
}

/**
 * Tool definitions.
 *
 * Descriptions are written for a model reading them at request time, so they say what the
 * tool returns as well as what it does. `list_accounts` explicitly states it does not
 * return secret values — a model that believes otherwise will work around it.
 */
export const TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  {
    name: TOOL_NAMES.listAccounts,
    description:
      'List the credential accounts available through the broker, as service and account ' +
      'alias pairs with metadata. Returns NO secret values: the broker holds credentials ' +
      'and never discloses them. Use the names returned here when asking the broker to ' +
      'perform an action.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: TOOL_NAMES.brokerStatus,
    description:
      'Report broker status: whether it is running, how many credentials it holds, and ' +
      'which clients are connected. Contains no secret values.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: TOOL_NAMES.callApi,
    description:
      'Perform one allowlisted operation against a provider API on behalf of an account ' +
      'held by the broker. The credential is spent by the broker and never appears in the ' +
      'arguments or the result. Requires a capability id from the user, and fails closed ' +
      'unless policy allows it. Returns a projection of the provider response, never the ' +
      'credential. NOT for fetching secrets: there is no tool here that discloses one.',
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: 'Service name, e.g. github' },
        account: { type: 'string', description: 'Account alias, e.g. work' },
        operation: { type: 'string', description: 'Allowlisted operation, e.g. github.repo.read' },
        capability_id: { type: 'string', description: 'Capability id minted by the user via vaultbroker policy grant' },
        project: { type: 'string', description: 'Project directory the grant is bound to; defaults to the current directory' },
        params: { type: 'object', description: 'Operation parameters, e.g. owner/repo/number' },
      },
      additionalProperties: false,
    },
  },
]

/** Structured content returned by a tool call. Never contains credential material. */
export type ToolResultContent = AccountSummary[] | DaemonStatus | { error: string }