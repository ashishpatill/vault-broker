/**
 * Diagnostic logging that cannot corrupt the protocol channel.
 *
 * Two hard rules, both learned the hard way:
 *
 *  1. **MCP stdio uses stdout for JSON-RPC.** A single stray `console.log` — including
 *     one from a dependency — corrupts the framing and the client disconnects with a
 *     parse error that points nowhere near the cause. All diagnostics go to stderr.
 *  2. **A logger must never be able to print a credential.** Rather than trusting every
 *     call site, `debug` runs its value through a redactor first, so passing a `Secret`
 *     or a raw token by mistake degrades to `[redacted]` instead of leaking.
 */

import { inspect } from 'node:util'

import { Secret } from './secret.ts'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
}

function configuredLevel(): LogLevel {
  const raw = process.env['VAULTBROKER_LOG']?.toLowerCase()
  if (raw === 'debug' || raw === 'info' || raw === 'warn' || raw === 'error') return raw
  return 'warn'
}

/**
 * Credential shapes to scrub from any diagnostic output.
 *
 * Deliberately conservative and pattern-based rather than tied to specific providers: a
 * credential we have never seen is still a credential. This is defence in depth behind
 * `Secret`, not a replacement for it.
 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /\b(?:gh[pousr]_[A-Za-z0-9]{16,})/gu, // GitHub tokens
  /\bsk-[A-Za-z0-9_-]{16,}/gu, // OpenAI-style
  /\bnapi_[A-Za-z0-9]{16,}/gu, // Neon
  /\bAKIA[0-9A-Z]{16}\b/gu, // AWS access key ids
  /\bASIA[0-9A-Z]{16}\b/gu, // AWS temporary credentials
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/gu, // Slack
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu, // JWT
]

/** Replace anything that looks like a credential with a marker. */
export function redact(text: string): string {
  let output = text
  for (const pattern of CREDENTIAL_PATTERNS) {
    output = output.replace(pattern, '[redacted:credential-pattern]')
  }
  return output
}

/**
 * Render any value for logging without leaking it.
 *
 * `Secret` instances are caught structurally (their own `describe()` returns a redacted
 * string), then the rendered text is swept for credential patterns as a second layer.
 */
export function safeRender(value: unknown): string {
  if (value instanceof Secret) return value.describe()
  if (typeof value === 'string') return redact(value)

  try {
    return redact(inspect(value, { depth: 4, breakLength: 120 }))
  } catch {
    return '[unrenderable]'
  }
}

/** Compose one log line. Always returns a single redacted line. */
export function format(level: LogLevel, scope: string, message: string, detail?: unknown): string {
  const base = `[vaultbroker:${scope}] ${message}`
  return detail === undefined ? redact(base) : `${redact(base)} ${safeRender(detail)}`
}

export interface Logger {
  debug(message: string, detail?: unknown): void
  info(message: string, detail?: unknown): void
  warn(message: string, detail?: unknown): void
  error(message: string, detail?: unknown): void
}

/**
 * Create a scoped logger writing to stderr.
 *
 * stderr, never stdout — see the module comment. This is not configurable, on purpose.
 */
export function createLogger(scope: string): Logger {
  const emit = (level: LogLevel, message: string, detail?: unknown): void => {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[configuredLevel()]) return
    process.stderr.write(`${format(level, scope, message, detail)}\n`)
  }

  return {
    debug: (m, d) => emit('debug', m, d),
    info: (m, d) => emit('info', m, d),
    warn: (m, d) => emit('warn', m, d),
    error: (m, d) => emit('error', m, d),
  }
}

/**
 * Capture writes to stdout for the duration of a test.
 *
 * Used to prove the protocol invariant: nothing but JSON-RPC may ever reach stdout.
 */
export function captureStdout(): { lines: string[]; restore: () => void } {
  const lines: string[] = []
  const original = process.stdout.write.bind(process.stdout)

  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    lines.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
    return true
  }) as typeof process.stdout.write

  return {
    lines,
    restore: () => {
      process.stdout.write = original
    },
  }
}