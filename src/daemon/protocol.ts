/**
 * Wire protocol between the per-harness shim and the daemon.
 *
 * This is deliberately NOT MCP. MCP is the protocol a harness speaks to the shim over
 * stdio; this is VaultBroker's own internal protocol between the shim and the single
 * daemon that owns the vault. Keeping them separate means a compromised harness sees only
 * the tool surface, and a change to MCP tooling cannot silently alter the internal trust
 * boundary.
 *
 * Every frame is newline-delimited JSON, matching how the shim frames MCP messages. No
 * length prefixes, no binary framing: this travels over a Unix domain socket between two
 * processes we control, not over a network where framing errors would be a security
 * concern.
 */

import { randomUUID } from 'node:crypto'

/** Protocol version. Bumped on an incompatible change; mismatches are refused. */
export const PROTOCOL_VERSION = 1

/** Which harness is asking. Drives policy in I3; authenticated properly in I4. */
export type ClientId = 'cursor' | 'claude-code' | 'opencode' | 'codex' | 'test'

/**
 * Operations the shim may ask the daemon to perform.
 *
 * Note what is absent: there is no command that performs a provider operation. The daemon
 * can grant, authorise and audit, but acting on a credential is I5's adapter work, reached
 * only through an authorisation decision made here.
 */
export type DaemonCommand =
  | 'ping'
  | 'status'
  | 'list_accounts'
  | 'grant'
  | 'authorise'
  | 'audit_recent'
  | 'shutdown'

export interface RequestFrame {
  readonly kind: 'request'
  readonly id: string
  readonly version: number
  readonly clientId: ClientId
  readonly command: DaemonCommand
  readonly params: Readonly<Record<string, unknown>>
}

export interface ResponseFrame {
  readonly kind: 'response'
  readonly id: string
  readonly ok: boolean
  readonly result?: unknown
  readonly error?: { readonly code: string; readonly message: string }
}

export type Frame = RequestFrame | ResponseFrame

export class ProtocolError extends Error {}

/** Validate a frame's shape without trusting any of it. */
export function parseFrame(line: string): Frame {
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    throw new ProtocolError('frame is not valid JSON')
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new ProtocolError('frame is not an object')
  }

  const frame = parsed as Record<string, unknown>

  if (frame['kind'] === 'request') {
    if (typeof frame['id'] !== 'string') throw new ProtocolError('request.id must be a string')
    if (typeof frame['version'] !== 'number') throw new ProtocolError('request.version must be a number')
    if (typeof frame['clientId'] !== 'string') throw new ProtocolError('request.clientId must be a string')
    if (typeof frame['command'] !== 'string') throw new ProtocolError('request.command must be a string')
    if (typeof frame['params'] !== 'object' || frame['params'] === null) {
      throw new ProtocolError('request.params must be an object')
    }
    return frame as unknown as RequestFrame
  }

  if (frame['kind'] === 'response') {
    if (typeof frame['id'] !== 'string') throw new ProtocolError('response.id must be a string')
    if (typeof frame['ok'] !== 'boolean') throw new ProtocolError('response.ok must be a boolean')
    return frame as unknown as ResponseFrame
  }

  throw new ProtocolError('frame.kind must be "request" or "response"')
}

export function encodeFrame(frame: Frame): string {
  return `${JSON.stringify(frame)}\n`
}

/**
 * Refuse a frame from a protocol version we do not understand.
 *
 * Better to fail closed on a version mismatch than to interpret a newer frame's fields
 * with older assumptions — that is how request-smuggling bugs start.
 */
export function assertCompatible(frame: RequestFrame): void {
  if (frame.version !== PROTOCOL_VERSION) {
    throw new ProtocolError(
      `unsupported protocol version ${frame.version}; this daemon speaks ${PROTOCOL_VERSION}`,
    )
  }
}

/** Build a request frame with a fresh correlation id. */
export function buildRequest(
  clientId: ClientId,
  command: DaemonCommand,
  params: Readonly<Record<string, unknown>> = {},
): RequestFrame {
  return {
    kind: 'request',
    id: randomUUID(),
    version: PROTOCOL_VERSION,
    clientId,
    command,
    params,
  }
}