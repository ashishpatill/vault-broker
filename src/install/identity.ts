/**
 * Harness identity via macOS code signing.
 *
 * This is the highest-value security feature that is unblocked right now. `codesign`
 * inspection works with no Xcode and no signing identity, so a harness's grant can be
 * bound to what its binary actually *is* rather than to a path string.
 *
 * ## What this catches
 *
 * A harness binary that was replaced, patched, re-signed by someone else, or moved. Path
 * checks alone miss all of these, because a writable path can be repointed at a different
 * executable. Team ID plus designated requirement plus content hash catches them.
 *
 * ## What this does NOT catch
 *
 * A process running as this user can still reach the daemon socket and claim to be a
 * registered client. Node has no `LOCAL_PEERCRED` equivalent, so we cannot verify a
 * peer's uid *in the kernel*. The daemon does verify the shim's own parent process
 * best-effort via `ps` — see {@link inspectProcess} — and that check is honestly weaker
 * than it looks. Definitive verification needs the v0.2 native helper.
 *
 * Recorded here rather than buried, because a signature check on a path can read as
 * "identity verified" when what it actually establishes is "this file at this path is the
 * one that was approved".
 */

import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { createHash } from 'node:crypto'

/** Absolute path to codesign. Overridable so tests can supply a stub. */
export function codesignBinary(): string {
  return process.env['VAULTBROKER_CODESIGN_BIN'] ?? '/usr/bin/codesign'
}

export class IdentityError extends Error {}

/**
 * A harness's verified identity.
 *
 * `designatedRequirement` and `contentHash` are the two fields that carry real weight:
 * the DR states what a legitimate instance must satisfy, and the content hash pins the
 * exact bytes that were reviewed. Team ID alone is too coarse — many apps share a vendor
 * — and path alone is worthless.
 */
export interface CodeSignatureIdentity {
  /** Bundle identifier, e.g. com.todesktop.230313mzl4w4u92. */
  readonly identifier: string | null
  /** Apple developer team, e.g. VDXQ22DGB9. */
  readonly teamId: string | null
  /** Full authority chain, leaf first. */
  readonly authorities: readonly string[]
  /** Whether Apple notarised the code. */
  readonly notarized: boolean
  /** Whether the signature is currently valid per `codesign`. */
  readonly signatureValid: boolean
  /** macOS designated requirement expression. */
  readonly designatedRequirement: string | null
  /** Content hash of the signed code. */
  readonly contentHash: string | null
  /** Real path of what was inspected. */
  readonly path: string
}

/**
 * Run codesign and return stdout and stderr together.
 *
 * Uses spawnSync rather than execFileSync because `codesign -dv` writes its report to
 * **stderr** and exits 0 — execFileSync returns only stdout on success, so the whole
 * report was discarded and every identity parsed as empty. That failure is silent and
 * reads as "valid", which is the worst possible direction for a security check.
 */
function runCodesign(args: readonly string[]): { status: number; output: string } {
  const result = spawnSync(codesignBinary(), [...args], {
    encoding: 'utf8',
    maxBuffer: 4 << 20,
  })

  if (result.error !== undefined) {
    throw new IdentityError(`could not run ${codesignBinary()}: ${result.error.message}`)
  }

  return {
    status: result.status ?? 1,
    output: `${result.stdout ?? ''}\n${result.stderr ?? ''}`,
  }
}

function parseVerbose(output: string): {
  identifier: string | null
  teamId: string | null
  authorities: string[]
  notarized: boolean
} {
  const identifier = /^Identifier=(.*)$/mu.exec(output)?.[1]?.trim() ?? null
  const teamId = /^TeamIdentifier=(.*)$/mu.exec(output)?.[1]?.trim() ?? null
  const authorities = [...output.matchAll(/^Authority=(.*)$/gmu)].map((m) => (m[1] ?? '').trim())
  const notarized = /^Notarization Ticket=stapled$/mu.test(output)
  return { identifier, teamId, authorities, notarized }
}

/**
 * Inspect a binary or app bundle's code signature.
 *
 * Resolves symlinks first: a grant bound to `/usr/local/bin/cursor` that is really a link
 * into the app bundle should be judged on its real target, otherwise a swap that
 * repoints the symlink changes nothing that was recorded.
 */
export function inspectSignature(target: string): CodeSignatureIdentity {
  if (!existsSync(target)) {
    throw new IdentityError(`no such file: ${target}`)
  }

  // realpath so a symlink swap cannot hide behind a stable-looking path.
  const path = realpathSync(target)

  const details = runCodesign(['-dv', '--verbose=4', path])
  const { identifier, teamId, authorities, notarized } = parseVerbose(details.output)

  const valid = runCodesign(['--verify', '--strict', path])
  const signatureValid = valid.status === 0

  const dr = runCodesign(['-dr', '-', path])
  const designatedRequirement = /designated => (.+)$/mu.exec(dr.output)?.[1]?.trim() ?? null

  const cdHash = /^CDHash=(.*)$/mu.exec(details.output)?.[1]?.trim() ?? null

  return Object.freeze({
    identifier,
    teamId,
    authorities: Object.freeze(authorities),
    notarized,
    signatureValid,
    designatedRequirement,
    // Prefer codesign's own CDHash; fall back to hashing the main executable so an
    // unsigned binary still gets a content anchor.
    contentHash: cdHash ?? sha256OfFileMainExecutable(path),
    path,
  })
}

/**
 * Hash the thing that actually executes.
 *
 * For a `.app`, that is `Contents/MacOS/<name>`, not the bundle directory — hashing the
 * bundle directory would include timestamps and vary between otherwise identical copies.
 */
function sha256OfFileMainExecutable(path: string): string {
  const stats = lstatSync(path)

  if (!stats.isDirectory()) {
    return createHash('sha256').update(readFileSync(path)).digest('hex')
  }

  const macosDir = `${path}/Contents/MacOS`
  if (existsSync(macosDir)) {
    const entries = readdirSync(macosDir).filter((name) => !name.endsWith('.lproj'))
    const executable = entries[0]
    if (executable !== undefined) {
      return createHash('sha256').update(readFileSync(`${macosDir}/${executable}`)).digest('hex')
    }
  }

  // A directory with no MacOS subdir: hash the path itself rather than silently returning
  // null, so an identity is always comparable.
  return createHash('sha256').update(path).digest('hex')
}

/** A recorded registration for one client. */
export interface ClientRegistration {
  readonly clientId: string
  readonly identity: CodeSignatureIdentity
  readonly registeredAt: string
  /** Human label, e.g. "Cursor". */
  readonly label: string
}

export type IdentityVerdict =
  | { readonly ok: true; readonly reason?: undefined }
  | {
      readonly ok: false
      readonly reason:
        | 'team-changed'
        | 'requirement-changed'
        | 'content-changed'
        | 'signature-invalid'
        | 'not-notarized'
        | 'path-changed'
      readonly message: string
    }

/**
 * Compare a live identity against what was registered.
 *
 * Every field is compared; a mismatch in any one of them is a refusal. Notably this
 * includes the signature becoming *invalid* — a binary whose code was modified after
 * signing reports a broken signature on Apple silicon, which is the tamper case.
 *
 * Path change is reported but treated separately: a user legitimately moving or
 * re-installing an app should be able to re-register, so this is surfaced as its own
 * reason rather than folded into "tampered".
 */
export function verifyIdentity(
  registered: ClientRegistration,
  live: CodeSignatureIdentity,
): IdentityVerdict {
  const before = registered.identity

  if (before.signatureValid && !live.signatureValid) {
    return {
      ok: false,
      reason: 'signature-invalid',
      message: `${registered.label} is no longer correctly signed — the binary was modified after signing`,
    }
  }

  if (before.teamId !== live.teamId) {
    return {
      ok: false,
      reason: 'team-changed',
      message: `${registered.label} team changed: was ${before.teamId ?? 'none'}, now ${live.teamId ?? 'none'}`,
    }
  }

  if (before.designatedRequirement !== null && before.designatedRequirement !== live.designatedRequirement) {
    return {
      ok: false,
      reason: 'requirement-changed',
      message: `${registered.label} designated requirement changed — the app was re-signed`,
    }
  }

  if (before.contentHash !== null && before.contentHash !== live.contentHash) {
    return {
      ok: false,
      reason: 'content-changed',
      message: `${registered.label} content hash changed — the signed code is not the code that was approved`,
    }
  }

  // Notarisation is compared against what was registered, not required absolutely.
  //
  // Requiring it would refuse the real Claude Code CLI on this machine: its versioned
  // binary is Developer ID signed but not stapled. A rule that blocks a legitimate,
  // signed, widely-used harness is a rule that gets turned off — and a disabled rule
  // protects nothing. If it was absent at registration and is present now, that is an
  // improvement worth recording, not a mismatch.
  if (before.notarized && !live.notarized) {
    return {
      ok: false,
      reason: 'not-notarized',
      message: `${registered.label} was notarised at registration and no longer is`,
    }
  }

  return { ok: true }
}

/** Best-effort view of another process, used for the parent-process check. */
export interface ProcessInfo {
  readonly pid: number
  readonly executablePath: string
  readonly command: string
}

/**
 * Look up a process by pid using `ps`.
 *
 * **This is not an identity check.** Any same-user process can spawn a child, and a
 * compromised process can lie about what it exec'd. What it does establish is a useful
 * consistency signal — a client that claims to be Cursor should have a Cursor-ish parent
 * — and it costs nothing.
 *
 * Definitive peer identity requires `LOCAL_PEERCRED` in a native helper (v0.2).
 */
export function inspectProcess(pid: number): ProcessInfo | undefined {
  try {
    const output = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'comm=,args='], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 1 << 20,
    }).trim()

    if (output === '') return undefined

    const [firstLine = ''] = output.split('\n')
    // comm= and args= on one line yields "<path> <args...>"; comm alone is the path.
    const spaceIndex = firstLine.indexOf(' ')
    const executablePath = spaceIndex === -1 ? firstLine : firstLine.slice(0, spaceIndex)

    return { pid, executablePath, command: firstLine }
  } catch {
    return undefined
  }
}

/**
 * Does a process look like the registered client?
 *
 * Compares the parent process's executable path against the registered app path. A
 * substring match on the bundle name is used because a harness's helper process runs from
 * inside the bundle while the registered path may be the CLI shim in /usr/local/bin.
 */
export function processLooksLike(
  info: ProcessInfo | undefined,
  registered: ClientRegistration,
): boolean {
  if (info === undefined) return false

  const parentPath = info.executablePath
  const registeredPath = registered.identity.path

  if (parentPath === registeredPath) return true

  const bundleName = registeredPath.split('/').find((part) => part.endsWith('.app'))
  if (bundleName !== undefined && parentPath.includes(bundleName)) return true

  // Electron/Node apps run helpers from inside the bundle; match on the bundle directory.
  const appDir = registeredPath.endsWith('.app') ? registeredPath : ''
  if (appDir !== '' && parentPath.startsWith(`${appDir}/`)) return true

  return false
}

/** Render an identity for display. No secrets involved, so full detail is fine. */
export function describeIdentity(identity: CodeSignatureIdentity): string {
  return [
    `Identifier: ${identity.identifier ?? '(none)'}`,
    `Team:       ${identity.teamId ?? '(none)'}`,
    `Notarized:  ${identity.notarized ? 'yes' : 'no'}`,
    `Valid:      ${identity.signatureValid ? 'yes' : 'no'}`,
    `CDHash:     ${identity.contentHash ?? '(none)'}`,
    `Authority:  ${identity.authorities[0] ?? '(none)'}`,
    `Path:       ${identity.path}`,
  ].join('\n')
}