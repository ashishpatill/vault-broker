/**
 * `vaultbroker init` — create the runtime directory with correct permissions.
 *
 * Deliberately does NOT create the encrypted vault: that arrives in iteration I1 along
 * with the key hierarchy. Creating an empty placeholder here would risk shipping a file
 * that looks like a vault but contains no key material.
 */

import { existsSync, readFileSync } from 'node:fs'

import { ensureDir0700, writeFileAtomic } from '../../core/fsx.ts'
import { clientsDir, runtimeRoot, selfIgnorePath, statePath, RUNTIME_DIR_MODE } from '../../core/runtime-paths.ts'

/** Bumped when the on-disk metadata schema changes incompatibly. */
export const STATE_SCHEMA_VERSION = 1

export interface BrokerState {
  readonly schemaVersion: number
  readonly createdAt: string
  readonly product: 'vaultbroker'
}

export interface InitResult {
  readonly created: boolean
  readonly root: string
  readonly state: BrokerState
}

export function runInit(): InitResult {
  const root = runtimeRoot()
  const existed = existsSync(statePath())

  ensureDir0700(root)
  ensureDir0700(clientsDir())

  // Defence in depth. The 0700 mode is the real control; this only matters if someone
  // later runs `git init` in a parent directory and adds the app support folder.
  writeFileAtomic(selfIgnorePath(), '# VaultBroker runtime directory — never commit\n*\n')

  let state: BrokerState
  if (existed) {
    const existing = JSON.parse(readFileSync(statePath(), 'utf8')) as BrokerState
    if (existing.schemaVersion !== STATE_SCHEMA_VERSION) {
      throw new Error(
        `runtime state schema v${existing.schemaVersion} is not supported by this build ` +
          `(expected v${STATE_SCHEMA_VERSION}). Refusing to overwrite; back up and migrate manually.`,
      )
    }
    state = existing
  } else {
    state = {
      schemaVersion: STATE_SCHEMA_VERSION,
      createdAt: new Date().toISOString(),
      product: 'vaultbroker',
    }
    writeFileAtomic(statePath(), `${JSON.stringify(state, null, 2)}\n`)
  }

  // Re-assert the mode in case the directory pre-existed with looser permissions.
  ensureDir0700(root)

  return { created: !existed, root, state }
}

export function printInit(result: InitResult): void {
  const mode = RUNTIME_DIR_MODE.toString(8).padStart(4, '0')
  const verb = result.created ? 'Initialised' : 'Already initialised'
  process.stdout.write(
    `${verb} VaultBroker runtime at ${result.root}\n` +
      `  permissions: ${mode}\n` +
      `  schema: v${result.state.schemaVersion}\n` +
      (result.created ? '' : '  (existing state preserved)\n'),
  )
}