/**
 * Neon adapter: allowlisted reads against the Neon API.
 *
 * Deliberately the same shape as the GitHub adapter — fixed hosts, a per-operation field
 * allowlist, and error messages that never quote a response body — so a reader can compare
 * the two and find no difference in how the credential is handled.
 */

import type { Operation } from '../core/operations.ts'
import type { Adapter, AdapterRequest } from './registry.ts'
import { AdapterError, callApi, requireSafeParam } from './registry.ts'
import type { Secret } from '../core/secret.ts'

export const NEON_API_HOST = 'api.neon.tech'

export const NEON_API_BASE = `https://${NEON_API_HOST}/api/v2/`

/** Operations this adapter implements. Deliberately a subset of the catalogue. */
export const NEON_OPERATIONS: readonly Operation[] = [
  'neon.project.list',
  'neon.project.read',
  'neon.branch.list',
]

/**
 * Field allowlists per operation.
 *
 * Neon's project and branch objects carry connection strings, roles and pooler URIs;
 * `connection_uris`, `last_sql_url` and friends are on purpose NOT in these lists — a
 * connection string is a credential-shaped value and the response scan would discard the
 * whole call for it anyway. Ask for less.
 */
const RESPONSE_FIELDS: Readonly<
  Record<string, { readonly fields: readonly string[]; readonly list: boolean; readonly listPath?: string }>
> = {
  'neon.project.list': {
    list: true,
    listPath: 'projects',
    fields: ['id', 'name', 'pg_version', 'region_id', 'created_at', 'updated_at'],
  },
  'neon.project.read': {
    list: false,
    fields: [
      'project.id',
      'project.name',
      'project.pg_version',
      'project.region_id',
      'project.created_at',
    ],
  },
  'neon.branch.list': {
    list: true,
    listPath: 'branches',
    fields: ['id', 'name', 'project_id', 'current_state', 'created_at'],
  },
}

/**
 * Build the request for an operation.
 *
 * Split from `execute` for the same reason as GitHub's: path and parameter choices are
 * unit-testable on their own, and this is where a traversal or injection bug would live.
 */
export function buildNeonRequest(
  operation: Operation,
  params: Readonly<Record<string, unknown>>,
): { path: string; method: 'GET' | 'POST'; body?: Record<string, unknown> } {
  // projectId naming follows the Neon API itself, so an operation's parameters read the
  // same in a harness instruction and in an API reference.

  switch (operation) {
    case 'neon.project.list':
      return { path: 'projects', method: 'GET' }

    case 'neon.project.read': {
      const projectId = requireSafeParam(params, 'projectId')
      return { path: `projects/${projectId}`, method: 'GET' }
    }

    case 'neon.branch.list': {
      const projectId = requireSafeParam(params, 'projectId')
      return { path: `projects/${projectId}/branches`, method: 'GET' }
    }

    default:
      throw new AdapterError('unknown-operation', `neon does not implement ${operation}`)
  }
}

export interface NeonAdapterOptions {
  /** Overridable for tests against a local server. Production never sets this. */
  readonly baseUrl?: string
  readonly allowedHosts?: readonly string[]
}

export function createNeonAdapter(options: NeonAdapterOptions = {}): Adapter {
  const baseUrl = options.baseUrl ?? NEON_API_BASE
  const allowedHosts = options.allowedHosts ?? [NEON_API_HOST]

  const adapter: Adapter = {
    service: 'neon',
    operations: NEON_OPERATIONS,
    allowedHosts,
    async execute(request: AdapterRequest, secret: Secret): Promise<unknown> {
      if (!NEON_OPERATIONS.includes(request.operation)) {
        throw new AdapterError('unknown-operation', `neon does not implement ${request.operation}`)
      }

      const shape = RESPONSE_FIELDS[request.operation]
      if (shape === undefined) {
        // Unreachable given the membership check above, but failing loudly is better than
        // silently returning an empty object if the two tables ever drift apart.
        throw new AdapterError('unknown-operation', `no response shape for ${request.operation}`)
      }

      const built = buildNeonRequest(request.operation, request.params)

      return await callApi(
        adapter,
        baseUrl,
        {
          operation: request.operation,
          path: built.path,
          method: built.method,
          responseFields: shape.fields,
          responseIsList: shape.list,
          ...(shape.listPath === undefined ? {} : { listPath: shape.listPath }),
          headers: (headers) => {
            headers.set('Accept', 'application/json')
          },
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        },
        secret,
      )
    },
  }

  return adapter
}

/**
 * Operations registered in the catalogue but deliberately not implemented.
 *
 * `neon.query.execute` is the interesting hole: SQL over the API would need the
 * credential inside a connection string assembled from the response, which is precisely
 * the flow the broker exists to prevent. It needs a one-shot file-descriptor design
 * before it can be implemented honestly — deferred to v0.2 with the other write paths.
 */
export const NEON_UNIMPLEMENTED: readonly Operation[] = [
  'neon.query.execute',
  'neon.branch.delete',
  'neon.project.create',
  'neon.billing.read',
]
