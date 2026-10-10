/**
 * Filesystem helpers with security-relevant defaults.
 *
 * Two rules encoded here rather than repeated (and eventually forgotten) at call sites:
 *
 *   1. Directories we create are `0700` and files are `0600`, regardless of the
 *      process umask. `mkdir` honours umask, so the mode argument alone is not enough —
 *      we chmod explicitly afterwards.
 *   2. Writes are atomic (temp file + fsync + rename), so a crash mid-write cannot leave
 *      a truncated vault that fails to parse on next launch.
 */

import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'

import { RUNTIME_DIR_MODE, RUNTIME_FILE_MODE } from './runtime-paths.ts'

/**
 * Create a directory (and parents) with mode 0700, overriding umask.
 * Safe to call when the directory already exists.
 */
export function ensureDir0700(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: RUNTIME_DIR_MODE })
  chmodSync(dir, RUNTIME_DIR_MODE)
}

/**
 * Atomically write `contents` to `filePath` with mode 0600.
 *
 * The temp file is created in the destination directory so the final `rename` stays on
 * the same filesystem and is therefore atomic.
 */
export function writeFileAtomic(filePath: string, contents: string | Buffer): void {
  const dir = dirname(filePath)
  ensureDir0700(dir)

  const tmp = resolve(dir, `.${process.pid}.${Date.now()}.tmp`)

  let fd: number | undefined
  try {
    fd = openSync(tmp, 'wx', RUNTIME_FILE_MODE)
    // writeFileSync accepts string | ArrayBufferView and loops until the whole buffer is
    // written; a bare writeSync can return a short count on a large payload.
    writeFileSync(fd, contents)
    // Durability before the rename: otherwise a crash can lose the rename's target data.
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined

    chmodSync(tmp, RUNTIME_FILE_MODE)
    renameSync(tmp, filePath)
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd)
      } catch {
        // Already closed or never opened; the unlink below is what matters.
      }
    }
    try {
      unlinkSync(tmp)
    } catch {
      // Temp file may not exist; nothing useful to do.
    }
    throw err
  }
}

/**
 * Copy a file into a timestamped backup, keeping the most recent `keep` copies.
 *
 * Called before every vault write. The point is not confidentiality — the backup is
 * encrypted exactly like the original — it is recoverability, so an interrupted write or a
 * bad migration cannot leave the user with no copy of their credentials.
 */
export function backupFile(filePath: string, keep = 5): void {
  if (!existsSync(filePath)) return

  const dir = join(dirname(filePath), 'backups')
  ensureDir0700(dir)

  const base = basename(filePath)
  const target = resolve(dir, nextBackupName(base))

  copyFileSync(filePath, target)
  chmodSync(target, RUNTIME_FILE_MODE)

  // Trim: keep the newest `keep`, delete the rest. Sorted by name, which is chronological
  // because the stamp is ISO-8601 with separators replaced.
  const existing = readdirSync(dir)
    .filter((name) => name.startsWith(`${base}.`))
    .sort()

  for (const stale of existing.slice(0, Math.max(0, existing.length - keep))) {
    rmSync(resolve(dir, stale), { force: true })
  }
}

/** Back up the vault file specifically, so the vault's backup policy stays in one place. */
export function backupVaultFile(filePath: string, keep = 5): void {
  backupFile(filePath, keep)
}

/**
 * Allocate a unique backup filename.
 *
 * The timestamp alone is not unique enough: two writes within the same millisecond
 * (which happens when a vault is created and then immediately written to) would collide
 * on the target path, and `copyFileSync` would silently overwrite the first backup. Adding
 * a counter and a pid makes collisions practically impossible.
 */
let backupSequence = 0

function nextBackupName(base: string): string {
  backupSequence += 1
  const stamp = new Date().toISOString().replaceAll(/[:.]/gu, '-')
  return `${base}.${stamp}.${String(process.pid)}.${String(backupSequence)}.bak`
}

/**
 * Read a JSON file, returning `undefined` when it does not exist.
 *
 * Used for optional metadata files. Callers must treat `undefined` as "not initialised",
 * not as "empty but valid".
 */
export function readJsonIfExists<T>(filePath: string): T | undefined {
  if (!existsSync(filePath)) return undefined

  const raw = readFileSync(filePath, 'utf8')
  return JSON.parse(raw) as T
}