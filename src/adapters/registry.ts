/**
 * Adapter framework.
 *
 * An adapter is the only component allowed to touch a credential for a provider call,
 * and it is deliberately constrained:
 *
 *   - **Fixed operations.** An adapter declares which `Operation`s it implements. An
 *     operation it does not declare cannot be called at all.
 *   - **Fixed hosts.** Requests go only to hosts on the adapter's allowlist. A
 *     model-supplied URL is never used to build a request — parameters are interpolated
 *     into a *path*, against a base URL the adapter chose.
 *   - **Allowlisted response fields.** Results are projected onto an explicit field list.
 *     Not a blocklist: a blocklist only knows about fields someone thought of, and GitHub
 *     (or any provider) can add a field at any time.
 *   - **Outbound secret scan.** If a response body contains something credential-shaped,
 *     the request fails closed. This is defence against a provider echoing a token back —
 *     it is why the response never reaches the model even though the credential never
 *     left the adapter.
 *
 * Credentials reach an adapter as a `Secret<T>` and are spent through
 * `Secret.withHeaders`. There is no API here that returns a credential.
 *
 * ## What an adapter must never grow
 *
 * A generic `run(command, env)` entry point. That is unrestricted secret delegation and
 * it would collapse the entire security model. If a provider cannot be modelled as fixed
 * operations against a fixed host, it does not get an adapter.
 */

import { Secret } from '../core/secret.ts'
import { createLogger, redact } from '../core/logging.ts'
import { tierOf, type Operation } from '../core/operations.ts'

const log = createLogger('adapters')

export interface AdapterRequest {
  readonly operation: Operation
  readonly params: Readonly<Record<string, unknown>>
  readonly signal?: AbortSignal | undefined
}

export interface Adapter {
  readonly service: string
  /** Operations this adapter implements. Anything else is unreachable. */
  readonly operations: readonly Operation[]
  /** Hosts this adapter may contact. Exact match, HTTPS unless explicitly allowed. */
  readonly allowedHosts: readonly string[]
  execute(request: AdapterRequest, secret: Secret): Promise<unknown>
}

export class AdapterError extends Error {
  readonly kind:
    | 'unknown-operation'
    | 'host-not-allowed'
    | 'invalid-param'
    | 'upstream-error'
    | 'response-leaked-credential'
    | 'network'

  constructor(kind: AdapterError['kind'], message: string) {
    super(message)
    this.kind = kind
  }
}

/**
 * Credential-shaped substrings that must never appear in a response we return.
 *
 * Deliberately pattern-based rather than tied to specific providers: an unrecognised
 * credential is still a credential. This runs on every outbound body because it is the
 * last line of defence before data reaches a model.
 */
const RESPONSE_CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9]{16,}/u,
  /\bsk-[A-Za-z0-9_-]{16,}/u,
  /\bnapi_[A-Za-z0-9]{16,}/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bASIA[0-9A-Z]{16}\b/u,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/u,
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u,
]

/** Header names whose values must never be echoed back in an error or result. */
const FORBIDDEN_RESPONSE_KEYS: readonly string[] = [
  'authorization',
  'auth',
  'token',
  'access_token',
  'refresh_token',
  'private_key',
  'client_secret',
  'password',
  'api_key',
  'apikey',
  'secret',
]

/**
 * Fail closed if a response looks like it carries credential material.
 *
 * Returns nothing on success and throws on detection, so it is hard to call in a way that
 * ignores it.
 */
export function assertNoCredentialInResponse(body: string, operation: string): void {
  for (const pattern of RESPONSE_CREDENTIAL_PATTERNS) {
    const match = pattern.exec(body)
    if (match !== null) {
      // The pattern name is logged, never the matched text.
      log.error('response contained credential-shaped data; failing closed', {
        operation,
        pattern: pattern.source.slice(0, 30),
      })
      throw new AdapterError(
        'response-leaked-credential',
        `the upstream response for ${operation} contained credential-shaped data, so it was discarded`,
      )
    }
  }
}

/** Recursively drop forbidden keys from an object. Applied before the field allowlist. */
export function stripForbiddenKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripForbiddenKeys)
  if (value === null || typeof value !== 'object') return value

  const output: Record<string, unknown> = {}
  for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_RESPONSE_KEYS.includes(key.toLowerCase())) continue
    output[key] = stripForbiddenKeys(inner)
  }
  return output
}

/**
 * Project an object onto an explicit field list, following dotted paths.
 *
 * Missing fields are omitted rather than becoming `undefined` entries, so the response
 * shape is stable and a provider adding fields cannot change it.
 */
export function pick(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const source = value as Record<string, unknown> | null
  const output: Record<string, unknown> = {}

  for (const field of fields) {
    let cursor: unknown = source
    let present = true

    for (const segment of field.split('.')) {
      if (cursor === null || typeof cursor !== 'object') {
        present = false
        break
      }
      cursor = (cursor as Record<string, unknown>)[segment]
    }

    if (present && cursor !== undefined) output[field] = cursor
  }

  return output
}

/** Apply pick to each element of an array. */
export function pickEach(value: unknown, fields: readonly string[]): Record<string, unknown>[] {
  if (!Array.isArray(value)) return []
  return value.map((entry) => pick(entry, fields))
}

/**
 * Validate a path parameter before it is interpolated into a URL.
 *
 * This is the injection boundary. A parameter that fails this never reaches a URL, so a
 * value like `../../admin` or `a/../b` cannot climb out of the intended path. The
 * allowlist is deliberately narrow rather than "percent-encode and hope".
 */
const SAFE_PARAM = /^[A-Za-z0-9._-]{1,128}$/u

export function requireSafeParam(params: Readonly<Record<string, unknown>>, name: string): string {
  const value = params[name]
  if (typeof value !== 'string' || !SAFE_PARAM.test(value)) {
    throw new AdapterError(
      'invalid-param',
      `${name} must be 1-128 characters of letters, digits, dot, underscore or hyphen`,
    )
  }
  // Belt and braces: reject relative segments even though the pattern above excludes
  // slashes, so tightening the pattern later cannot silently reopen this.
  if (value.includes('..') || value === '.' || value === '-') {
    throw new AdapterError('invalid-param', `${name} is not a valid identifier`)
  }
  return value
}

export function optionalSafeParam(
  params: Readonly<Record<string, unknown>>,
  name: string,
): string | undefined {
  if (params[name] === undefined) return undefined
  return requireSafeParam(params, name)
}

/**
 * Resolve a path against the base URL and assert the host is allowed.
 *
 * Even though the base URL is chosen by the adapter and the path is built from validated
 * parameters, the host check is re-asserted here. Defence in depth for the one property
 * that matters most: a credential must never be sent to an address we did not choose.
 */
export function resolveUrl(adapter: Adapter, baseUrl: string, path: string): URL {
  const url = new URL(path, baseUrl)

  if (!adapter.allowedHosts.includes(url.host)) {
    log.error('adapter attempted a request to a disallowed host', {
      host: url.host,
      service: adapter.service,
    })
    throw new AdapterError(
      'host-not-allowed',
      `${adapter.service} is not permitted to contact ${url.host}`,
    )
  }

  return url
}

/** Registry of available adapters, keyed by service. */
export class AdapterRegistry {
  readonly #adapters = new Map<string, Adapter>()

  register(adapter: Adapter): void {
    if (this.#adapters.has(adapter.service)) {
      throw new AdapterError('invalid-param', `adapter for ${adapter.service} is already registered`)
    }
    this.#adapters.set(adapter.service, adapter)
  }

  get(service: string): Adapter | undefined {
    return this.#adapters.get(service)
  }

  services(): string[] {
    return [...this.#adapters.keys()].sort()
  }

  /**
   * Resolve an adapter and assert it implements the operation.
   *
   * Both checks live here so no caller can skip them: an adapter that does not declare an
   * operation cannot be asked to perform it.
   */
  resolve(service: string, operation: Operation): Adapter {
    const adapter = this.#adapters.get(service)
    if (adapter === undefined) {
      throw new AdapterError('unknown-operation', `no adapter for service ${service}`)
    }
    if (!adapter.operations.includes(operation)) {
      throw new AdapterError(
        'unknown-operation',
        `${service} does not implement ${operation} (tier ${tierOf(operation)})`,
      )
    }
    return adapter
  }
}

/**
 * Perform a request and return a sanitised, field-limited result.
 *
 * The single path every provider call goes through. Order is deliberate:
 *
 *   1. resolve the URL and check the host - before the credential is touched;
 *   2. spend the credential - inside `withHeaders`;
 *   3. scan the response body - before parsing;
 *   4. strip forbidden keys;
 *   5. project onto the allowlist.
 *
 * Step 1 before step 2 matters: there is no reason to spend a credential on a request that
 * is going to be refused anyway.
 *
 * `path` is built by the adapter from validated parameters, never supplied by a caller.
 * There is deliberately no way to pass a URL in.
 */
export async function callApi(
  adapter: Adapter,
  baseUrl: string,
  spec: {
    readonly operation: Operation
    readonly path: string
    readonly method?: string
    readonly body?: unknown
    readonly responseFields?: readonly string[]
    readonly responseIsList?: boolean
    readonly signal?: AbortSignal | undefined
  },
  secret: Secret,
): Promise<unknown> {
  const url = resolveUrl(adapter, baseUrl, spec.path)
  const method = spec.method ?? 'GET'

  const raw = await secret.withHeaders(async (headers): Promise<string> => {
    headers.set('Accept', 'application/vnd.github+json')
    headers.set('X-GitHub-Api-Version', '2022-11-28')
    headers.set('User-Agent', 'vaultbroker')

    const init: RequestInit = { method, headers }
    if (spec.body !== undefined) {
      headers.set('Content-Type', 'application/json')
      init.body = JSON.stringify(spec.body)
    }
    if (spec.signal !== undefined) init.signal = spec.signal

    const response = await fetch(url, init)
    const text = await response.text()

    if (!response.ok) {
      // Upstream error bodies can reflect the request. Report status only and never
      // include the body: it is not needed to diagnose a failure and could echo the
      // credential straight back at us.
      throw new AdapterError(
        'upstream-error',
        `${adapter.service} ${method} ${redact(url.pathname)} failed with HTTP ${String(response.status)}`,
      )
    }

    return text
  })

  // 3. Scan before parsing: a poisoned body should not reach a JSON parser that might
  //    echo fragments into an error message.
  assertNoCredentialInResponse(raw, spec.operation)

  const parsed: unknown = JSON.parse(raw)

  // 4, 5.
  const stripped = stripForbiddenKeys(parsed)
  const fields = spec.responseFields ?? []
  return spec.responseIsList === true ? pickEach(stripped, fields) : pick(stripped, fields)
}
