/**
 * GitHub adapter.
 *
 * Fixed operations against a fixed host. Nothing here accepts a URL, and every path
 * parameter is validated against a narrow identifier pattern before interpolation.
 *
 * ## Response field allowlists
 *
 * Each operation declares exactly which fields may be returned. This is an allowlist, not
 * a blocklist, because GitHub can add fields to any response at any time and a blocklist
 * only knows about the fields someone already thought of. A repository object contains
 * URLs, permissions, owner details and more; almost none of it is needed to answer "does
 * this repo exist and what is it called".
 *
 * ## Operations not implemented
 *
 * `github.repo.delete`, `github.release.create`, `github.billing.read` and
 * `github.member.admin` are registered in the operation catalogue but deliberately NOT
 * implemented here. That is the correct state: an unimplemented operation is refused by
 * the registry, whereas a half-implemented one invites a mistake at the worst moment.
 */

import type { Operation } from '../core/operations.ts'
import { Secret } from '../core/secret.ts'
import {
  AdapterError,
  callApi,
  requireSafeParam,
  type Adapter,
  type AdapterRequest,
} from './registry.ts'

/** The only host this adapter may ever contact in production. */
export const GITHUB_API_HOST = 'api.github.com'

export const GITHUB_API_BASE = `https://${GITHUB_API_HOST}/`

/** Operations this adapter implements. Deliberately a subset of the catalogue. */
export const GITHUB_OPERATIONS: readonly Operation[] = [
  'github.repo.read',
  'github.repo.list',
  'github.pr.read',
  'github.pr.create',
  'github.issue.read',
  'github.issue.create',
  'github.branch.create',
]

/**
 * Field allowlists per operation.
 *
 * Written as explicit arrays rather than derived from a schema, because the schema
 * describes what GitHub *sends* and this describes what we are willing to *relay*.
 */
const RESPONSE_FIELDS: Readonly<Record<string, { readonly fields: readonly string[]; readonly list: boolean }>> = {
  'github.repo.read': {
    list: false,
    fields: ['id', 'name', 'full_name', 'private', 'default_branch', 'description', 'fork', 'archived'],
  },
  'github.repo.list': {
    list: true,
    fields: ['id', 'name', 'full_name', 'private', 'default_branch', 'fork', 'archived'],
  },
  'github.pr.read': {
    list: false,
    fields: ['number', 'title', 'state', 'draft', 'user.login', 'created_at', 'updated_at', 'merged_at'],
  },
  'github.pr.create': {
    list: false,
    fields: ['number', 'title', 'state', 'html_url', 'created_at'],
  },
  'github.issue.read': {
    list: false,
    fields: ['number', 'title', 'state', 'user.login', 'created_at', 'closed_at'],
  },
  'github.issue.create': {
    list: false,
    fields: ['number', 'title', 'state', 'html_url', 'created_at'],
  },
  'github.branch.create': {
    list: false,
    fields: ['ref', 'object.sha', 'object.type'],
  },
}

/**
 * Build the request for an operation.
 *
 * Split out from `execute` so path and body construction are unit-testable on their own
 * — this is where a traversal or injection bug would live.
 *
 * Write operations send a JSON body rather than query parameters. Query strings end up in
 * access logs, proxy logs and `Referer` headers, so putting an issue title there would leak
 * user content to places the user never chose.
 */
export function buildRequest(
  operation: Operation,
  params: Readonly<Record<string, unknown>>,
): { path: string; method: 'GET' | 'POST'; body?: Record<string, unknown> } {
  // owner/repo are validated per-branch rather than up front: `github.repo.list` scopes to
  // the authenticated user and needs neither, so demanding them would reject a legitimate
  // request for a missing parameter.
  const ownerRepo = (): { owner: string; repo: string } => ({
    owner: requireSafeParam(params, 'owner'),
    repo: requireSafeParam(params, 'repo'),
  })

  switch (operation) {
    case 'github.repo.read': {
      const { owner, repo } = ownerRepo()
      return { path: `repos/${owner}/${repo}`, method: 'GET' }
    }

    case 'github.repo.list':
      // Scoped to the authenticated user rather than accepting a user-supplied login, so a
      // grant cannot be pointed at somebody else's private repositories by changing a
      // parameter.
      return { path: 'user/repos?per_page=50&affiliation=owner,collaborator,organization_member', method: 'GET' }

    case 'github.pr.read': {
      const { owner, repo } = ownerRepo()
      return {
        path: `repos/${owner}/${repo}/pulls/${requireSafeParam(params, 'number')}`,
        method: 'GET',
      }
    }

    case 'github.pr.create': {
      const { owner, repo } = ownerRepo()
      return {
        path: `repos/${owner}/${repo}/pulls`,
        method: 'POST',
        body: {
          title: requireText(params, 'title'),
          body: optionalText(params, 'body'),
          base: requireSafeRef(params, 'base'),
          head: requireSafeRef(params, 'head'),
          draft: params['draft'] === true,
        },
      }
    }

    case 'github.issue.read': {
      const { owner, repo } = ownerRepo()
      return {
        path: `repos/${owner}/${repo}/issues/${requireSafeParam(params, 'number')}`,
        method: 'GET',
      }
    }

    case 'github.issue.create': {
      const { owner, repo } = ownerRepo()
      return {
        path: `repos/${owner}/${repo}/issues`,
        method: 'POST',
        body: {
          title: requireText(params, 'title'),
          body: optionalText(params, 'body'),
        },
      }
    }

    case 'github.branch.create': {
      const { owner, repo } = ownerRepo()
      return {
        path: `repos/${owner}/${repo}/git/refs`,
        method: 'POST',
        body: {
          ref: `refs/heads/${requireSafeRef(params, 'branch')}`,
          sha: requireSafeParam(params, 'from'),
        },
      }
    }

    default:
      throw new AdapterError('unknown-operation', `github does not implement ${operation}`)
  }
}

/**
 * Validate a git ref (branch name).
 *
 * Separate from {@link requireSafeParam} because branch names legitimately contain
 * slashes — `fix/flux` is ordinary, not an attack. What is still rejected is anything
 * that could change meaning: `..`, a leading slash, a trailing slash, empty segments,
 * and backslashes. Going through URL encoding as well is deliberate belt-and-braces.
 */
const SAFE_REF = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u

export function requireSafeRef(params: Readonly<Record<string, unknown>>, name: string): string {
  const value = params[name]
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    throw new AdapterError('invalid-param', `${name} must be 1-255 characters`)
  }
  if (!SAFE_REF.test(value)) {
    throw new AdapterError(
      'invalid-param',
      `${name} must be slash-separated alphanumeric segments with no traversal`,
    )
  }
  if (value.includes('..')) {
    throw new AdapterError('invalid-param', `${name} must not contain '..'`)
  }
  return value
}

/** Free text that goes in a query string. Bounded so it cannot be used as a payload. */
function requireText(params: Readonly<Record<string, unknown>>, name: string): string {
  const value = params[name]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new AdapterError('invalid-param', `${name} is required`)
  }
  if (value.length > 256) {
    throw new AdapterError('invalid-param', `${name} must be 256 characters or fewer`)
  }
  return value
}

function optionalText(params: Readonly<Record<string, unknown>>, name: string): string {
  const value = params[name]
  if (value === undefined || value === null) return ''
  if (typeof value !== 'string') {
    throw new AdapterError('invalid-param', `${name} must be a string`)
  }
  if (value.length > 4096) {
    throw new AdapterError('invalid-param', `${name} must be 4096 characters or fewer`)
  }
  return value
}

export interface GitHubAdapterOptions {
  /** Overridable for tests against a local server. Production never sets this. */
  readonly baseUrl?: string
  readonly allowedHosts?: readonly string[]
}

export function createGitHubAdapter(options: GitHubAdapterOptions = {}): Adapter {
  const baseUrl = options.baseUrl ?? GITHUB_API_BASE
  const allowedHosts = options.allowedHosts ?? [GITHUB_API_HOST]

  const adapter: Adapter = {
    service: 'github',
    operations: GITHUB_OPERATIONS,
    allowedHosts,
    async execute(request: AdapterRequest, secret: Secret): Promise<unknown> {
      if (!GITHUB_OPERATIONS.includes(request.operation)) {
        throw new AdapterError('unknown-operation', `github does not implement ${request.operation}`)
      }

      const shape = RESPONSE_FIELDS[request.operation]
      if (shape === undefined) {
        // Unreachable given the membership check above, but failing loudly is better than
        // silently returning an empty object if the two tables ever drift apart.
        throw new AdapterError('unknown-operation', `no response shape for ${request.operation}`)
      }

      const built = buildRequest(request.operation, request.params)

      return await callApi(
        adapter,
        baseUrl,
        {
          operation: request.operation,
          path: built.path,
          method: built.method,
          ...(built.body === undefined ? {} : { body: built.body }),
          responseFields: shape.fields,
          responseIsList: shape.list,
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        },
        secret,
      )
    },
  }

  return adapter
}

/** Operations registered in the catalogue but deliberately not implemented. */
export const GITHUB_UNIMPLEMENTED: readonly Operation[] = [
  'github.release.create',
  'github.repo.delete',
  'github.billing.read',
  'github.member.admin',
]