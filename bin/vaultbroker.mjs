#!/usr/bin/env node
// Thin launcher: Node needs the type-stripping flag to import .ts sources directly.
// A compiled build is not used in v0 — see iterations/PLAN.md for why.
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const entry = resolve(here, '..', 'src', 'cli', 'main.ts')

const result = spawnSync(
  process.execPath,
  ['--experimental-strip-types', '--disable-warning=ExperimentalWarning', entry, ...process.argv.slice(2)],
  { stdio: 'inherit' },
)

process.exit(result.status ?? 1)