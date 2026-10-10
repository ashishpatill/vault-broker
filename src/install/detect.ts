/**
 * Known harnesses and where they live on this machine.
 *
 * Detection is a set of probes over known paths and binary names — there is no scanning
 * API to use, and enumerating a filesystem looking for "something that looks like an AI
 * harness" would be both slow and a privacy problem.
 *
 * The paths here were verified on macOS 26.2 / arm64. They are a starting point for
 * detection, not a contract: `probe()` reports what it actually found so a mismatch is
 * visible rather than silent.
 */

import { existsSync, lstatSync, readdirSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** Harness identifiers used across the daemon protocol and policy grants. */
export type KnownClient = 'cursor' | 'claude-code' | 'opencode' | 'codex'

export interface HarnessProbe {
  readonly client: KnownClient
  readonly label: string
  /** Candidate paths, in preference order. */
  readonly candidates: readonly string[]
}

const HOME = (): string => homedir()

/** Known install locations. App bundles are preferred over CLI shims. */
export const HARNESS_PROBES: readonly HarnessProbe[] = [
  {
    client: 'cursor',
    label: 'Cursor',
    candidates: [
      '/Applications/Cursor.app',
      join(HOME(), 'Applications/Cursor.app'),
      '/usr/local/bin/cursor',
      '/opt/homebrew/bin/cursor',
    ],
  },
  {
    client: 'claude-code',
    label: 'Claude Code',
    candidates: [
      join(HOME(), '.local/bin/claude'),
      '/usr/local/bin/claude',
      '/opt/homebrew/bin/claude',
    ],
  },
  {
    client: 'opencode',
    label: 'OpenCode',
    candidates: [
      '/Applications/OpenCode.app',
      join(HOME(), 'Applications/OpenCode.app'),
      join(HOME(), '.opencode/bin/opencode'),
      '/usr/local/bin/opencode',
      '/opt/homebrew/bin/opencode',
    ],
  },
  {
    client: 'codex',
    label: 'Codex',
    candidates: [
      '/Applications/ChatGPT.app',
      join(HOME(), 'Applications/ChatGPT.app'),
      join(HOME(), '.codex/bin/codex'),
      '/usr/local/bin/codex',
    ],
  },
]

/** Resolve a probe to a real path, or undefined if nothing is installed. */
export function probe(harness: HarnessProbe): string | undefined {
  for (const candidate of harness.candidates) {
    if (!existsSync(candidate)) continue
    try {
      // Resolve symlinks so the identity we record is the real target.
      return realpathSync(candidate)
    } catch {
      return candidate
    }
  }
  return undefined
}

export interface DetectedHarness {
  readonly client: KnownClient
  readonly label: string
  readonly path: string
}

/** Every harness currently installed, in probe order. */
export function detectHarnesses(): DetectedHarness[] {
  const found: DetectedHarness[] = []

  for (const harness of HARNESS_PROBES) {
    const path = probe(harness)
    if (path !== undefined) {
      found.push({ client: harness.client, label: harness.label, path })
    }
  }

  return found
}

/**
 * Inside an app bundle, the file that actually executes.
 *
 * Registration binds to this rather than to the bundle, because `Contents/MacOS/<Name>`
 * is the signed executable while the bundle directory contains variable content.
 */
export function mainExecutable(appPath: string): string {
  const stats = lstatSync(appPath)
  if (!stats.isDirectory()) return appPath

  const macosDir = join(appPath, 'Contents', 'MacOS')
  if (!existsSync(macosDir)) return appPath

  // Several entries can exist (helpers). The main executable matches the bundle's
  // Info.plist CFBundleExecutable, but reading and parsing plist is out of scope for v0;
  // the largest regular file is a good proxy and, unlike the first alphabetical entry, is
  // stable when helpers are added.
  const entries = readdirSync(macosDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .filter((entry) => !entry.name.endsWith('.lproj'))

  if (entries.length === 0) return appPath

  let best = macosDir
  let bestSize = -1

  for (const entry of entries) {
    const full = join(macosDir, entry.name)
    const size = lstatSync(full).size
    if (size > bestSize) {
      best = full
      bestSize = size
    }
  }

  return best
}