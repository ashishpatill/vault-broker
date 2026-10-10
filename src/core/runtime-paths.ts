/**
 * Runtime path resolution.
 *
 * Every path is returned from a function rather than exported as a constant, so that a
 * test which changes `VAULTBROKER_HOME` is not silently reading the real runtime
 * directory. Exporting frozen path constants is a classic way for security tooling to
 * end up writing to `~/Library/Application Support` during a test run.
 */

import { homedir } from 'node:os'
import { resolve } from 'node:path'

/** Directory mode for the runtime directory and everything inside it. */
export const RUNTIME_DIR_MODE = 0o700

/** File mode for vault, state, audit log and client registration files. */
export const RUNTIME_FILE_MODE = 0o600

/** Environment variable that relocates the entire runtime directory. */
export const HOME_ENV_VAR = 'VAULTBROKER_HOME'

/**
 * Root of all broker state.
 *
 * Override with `VAULTBROKER_HOME` (used by the test suite, and by anyone who wants the
 * broker's data somewhere other than the standard macOS location).
 */
export function runtimeRoot(): string {
  const override = process.env[HOME_ENV_VAR]
  if (override !== undefined && override !== '') {
    return resolve(override)
  }
  return resolve(homedir(), 'Library', 'Application Support', 'VaultBroker')
}

/** Unix domain socket the daemon listens on. Deliberately never a TCP port. */
export function socketPath(): string {
  return resolve(runtimeRoot(), 'broker.sock')
}

/** Lock file enforcing a single daemon instance. */
export function daemonLockPath(): string {
  return resolve(runtimeRoot(), 'daemon.lock')
}

/** Encrypted vault. Contents are opaque; see src/core/vault.ts (iteration I1). */
export function vaultPath(): string {
  return resolve(runtimeRoot(), 'vault.json')
}

/** Broker metadata: schema version, install time, daemon state. Contains no secrets. */
export function statePath(): string {
  return resolve(runtimeRoot(), 'state.json')
}

/** Hash-linked audit log. Contains no secret values by construction. */
export function auditLogPath(): string {
  return resolve(runtimeRoot(), 'audit.log')
}

/** Per-client registration records (identity binding, grants). No secret values. */
export function clientsDir(): string {
  return resolve(runtimeRoot(), 'clients')
}

/**
 * Advisory file inside the runtime directory that asks git to ignore everything, so a
 * user who ever runs `git init` in a parent directory cannot accidentally commit the
 * vault. Defence in depth only — the directory mode is the real control.
 */
export function selfIgnorePath(): string {
  return resolve(runtimeRoot(), '.gitignore')
}

/** All known runtime paths, resolved once. */
export function runtimePaths() {
  return {
    root: runtimeRoot(),
    socket: socketPath(),
    daemonLock: daemonLockPath(),
    vault: vaultPath(),
    state: statePath(),
    auditLog: auditLogPath(),
    clients: clientsDir(),
  } as const
}