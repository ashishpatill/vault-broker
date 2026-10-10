/**
 * A stub `security` binary that records how it was invoked.
 *
 * Its entire purpose is to let the test suite prove the `ps`-leak rule: that the
 * key-encryption key never appears in argv, only on stdin. The real `/usr/bin/security`
 * cannot be asked "what were your arguments", so we substitute a binary that answers.
 *
 * Invocation:
 *   security-stub.js <logPath> <mode> [args...]
 *
 * The stub appends a JSON line per invocation to `<logPath>`, then performs a trivial
 * in-file store so the vault tests can round-trip through it.
 */

import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const [logPath, mode, ...args] = process.argv.slice(2)

if (logPath === undefined || mode === undefined) {
  process.stderr.write('security-stub: usage: security-stub.js <logPath> <mode> [args...]\n')
  process.exit(64)
}

const argv = process.argv.slice(4)

/** Read the password `security` would have prompted for on stdin. */
function readStdin() {
  try {
    return readFileSync(0, 'utf8')
  } catch {
    return ''
  }
}

const stdin = readStdin()

// Record a *hash* of stdin rather than its contents. The test needs to prove the value
// arrived via stdin, and a digest proves that just as well without writing key material
// to disk — which would be a poor look in this project's own test suite.
appendFileSync(
  logPath,
  `${JSON.stringify({
    mode,
    argv,
    stdinLength: stdin.length,
    stdinSha256: createHash('sha256').update(stdin).digest('hex'),
  })}\n`,
  { mode: 0o600 },
)

const storePath = `${logPath}.store`

// Dispatch on argv, not on the caller's mode string. The wrapper passes an arbitrary
// label, and keying behaviour off a label means a mismatch silently degrades into a
// no-op that exits 0 — which looks exactly like success.
const subcommand = argv.find((a) => a.endsWith('generic-password')) ?? ''

if (subcommand.startsWith('add')) {
  // Mirror the real `security` binary's double prompt on create: it asks for the
  // password twice, and a single write yields "passwords don't match" while still
  // exiting 0. Modelling that here keeps the retry/verify path honest.
  const lines = stdin.split('\n').filter((l) => l !== '')
  const value = lines[0]

  if (lines.length >= 2 && lines[0] !== lines[1]) {
    process.stderr.write('security-stub: passwords don\'t match\n')
    // Real `security` exits 0 here despite storing an unusable item.
    writeFileSync(storePath, '', { mode: 0o600 })
    process.exit(0)
  }

  writeFileSync(storePath, value ?? '', { mode: 0o600 })
  process.exit(0)
}

if (subcommand.startsWith('find')) {
  if (!existsSync(storePath)) process.exit(44)
  process.stdout.write(readFileSync(storePath, 'utf8'))
  process.exit(0)
}

if (subcommand.startsWith('delete')) {
  process.exit(existsSync(storePath) ? 0 : 44)
}

process.exit(0)