# VaultBroker — Iteration & Loop Plan

**Date:** 2026-10-06
**Master plan:** `docs/planning/2026-10-06-vaultbroker-plan.md`
**Project:** `vaultbroker/`
**Mode:** one goal per iteration, self-guarding loop prompt, machine-checkable exit criterion

---

## How to run this

Nine iterations, I0 → I8, strictly sequential. For each one:

1. Switch to the **Build** agent.
2. Paste that iteration's loop prompt as `/loop <prompt>` (dynamic mode — no interval; the agent self-paces).
3. The prompt runs once immediately, then re-arms until the exit criterion passes.
4. When the exit criterion passes, the prompt **stops the loop and reports DONE**. Do not start the next iteration.
5. Move to the next iteration.

Every loop prompt is **self-guarding**: it checks the exit criterion *before* touching anything, so a re-run on a completed iteration exits immediately instead of churning. That makes them safe to leave armed.

Before I0, copy this file into the repo as `iterations/PLAN.md` so build mode can read it alongside the code.

---

## Verified toolchain constraints (bake these into every iteration)

| Fact | Impact |
|---|---|
| Node v22.23.2, npm 10.9.8, registry reachable | deps are fine; pin versions |
| `node --experimental-strip-types` works | **no build step** — run `.ts` directly |
| `node:test` built in | use the built-in runner, no jest/vitest |
| `@modelcontextprotocol/sdk@1.32.1` available | use the real SDK for the shim, not hand-rolled JSON-RPC |
| Unix domain sockets work | UDS transport as designed |
| **No Xcode / no CLT, 0 signing identities** | no native code, no signing, no notarization in any iteration |
| `codesign` inspection works | client identity binding is available now |
| `security` CLI works, login keychain present | KEK storage available now |
| macOS 26.2 arm64, FileVault On, SIP enabled | target platform only |

**Standing rules, present in every loop prompt:**

- Never print, log, echo, or return a credential value — not in a test fixture, not in an error
  message, not in a debug line, not in a commit message.
- Never pass a secret via argv (visible in `ps`); pipe over stdin only.
- No new native code, no code signing, no notarization.
- Stop at the iteration boundary.

---

## Repo layout to establish in I0

```
vaultbroker/
  package.json              scripts: typecheck, test, check, dev
  tsconfig.json             strict, noUncheckedIndexedAccess
  src/
    core/       crypto.ts  secret.ts  vault.ts  policy.ts  capability.ts  audit.ts
    daemon/     server.ts  session.ts  approval.ts
    shim/       main.ts    transport.ts
    adapters/   registry.ts  github.ts  neon.ts
    install/    detect.ts  clients/cursor.ts claude-code.ts opencode.ts codex.ts  diff.ts
    cli/        main.ts  commands/*.ts
  test/         *.test.ts
  iterations/   PLAN.md (this file) + per-iteration notes
```

---

# I0 — Foundation & invariant contract

**Goal:** The repo builds, tests run, and the credential-non-disclosure invariant is encoded as a type plus a test that *fails* when violated.

**Why first:** Everything else is scaffolding around this. Encoding the invariant before any code can leak a secret means every later iteration is written against a guardrail rather than retrofitted with a comment.

**Depends on:** nothing.

**Exit criterion**
```bash
npm run check
```
exits 0, and `test/secret.test.ts` proves `Secret<T>` cannot be JSON-serialised or stringified, and `vaultbroker init` creates a `0700` runtime dir.

### Tasks
1. `git init`, `package.json` (ESM, `"type": "module"`), strict `tsconfig.json`.
2. Scripts: `typecheck` (`tsc --noEmit`), `test` (`node --experimental-strip-types --test test/**/*.test.ts`), `check` = typecheck + test.
3. `src/core/secret.ts` — the `Secret<T>` type:
   - Private class, value in a private field, **no** `toJSON`, no `toString`, no `[Symbol.for('nodejs.util.inspect.custom')]` that reveals the value.
   - Only permitted operations: `injectIntoChildEnv()`, `useInFetch()`, `useInHeader()`. Each returns/consumes without ever surfacing the plaintext.
   - Add a `Symbol.dispose`-style wipe of the buffer on scope exit where practical.
4. `test/secret.test.ts` — the *negative* test: assert `JSON.stringify(new Secret('x'))` does not contain the value, no enumerable own properties leak it, and the type cannot be widened to `string`. **This test must fail if anyone later adds `toJSON`.**
5. `src/core/runtime-paths.ts` — resolve `~/Library/Application Support/VaultBroker` (override via `VAULTBROKER_HOME` for tests).
6. `src/cli/main.ts` + `commands/init.ts` — `vaultbroker init` creates runtime dir `0700`, an empty encrypted-vault placeholder, and writes a `.gitignore`. Idempotent.
7. `README.md` — security claims and **explicit non-goals** from master plan §10. Write the honest threat boundary now, so it can't drift.

### Failure modes
- Type stripping chokes on `enum` or parameter properties → use `const` objects and plain assignments.
- `node:test` glob expansion differs across shells → use an explicit test glob via `node --test test/` (directory mode), not a shell-expanded `**`.

### Loop prompt
```
/loop VaultBroker Iteration I0 (Foundation & invariant contract) in vaultbroker/. Read iterations/PLAN.md section I0 and ~/.opencode/plan/2026-10-06-vaultbroker-plan.md first. Run the exit criterion `npm run check` BEFORE editing anything: if it already exits 0 and the Secret<T> negative test and `vaultbroker init` both pass, stop the loop and report DONE — do not re-arm, do not start I1. Otherwise implement the I0 tasks in order, keep `npm run check` green after every change, never print or log a credential value and never pass a secret via argv, add no native code, and stop at the I0 boundary. Commit when the exit criterion passes.
```

---

# I1 — Vault core

**Goal:** Credentials are stored and retrieved with per-record authenticated encryption, and the vault file on disk reveals no account names or secret values.

**Depends on:** I0

**Exit criterion**
```bash
npm run check && npm run test:vault
```
`test:vault` = round-trip add/read/delete across services, tamper-detection (flip a ciphertext byte → read fails loudly), blind-index lookup works without decryption, and an assertion that the raw vault file contains neither the secret nor the account alias.

### Tasks
1. `src/core/crypto.ts` — AES-256-GCM via `node:crypto` (no third-party crypto dep). HKDF-SHA256 for per-record DEK. HMAC-SHA256 blind index.
2. Key hierarchy: random 32-byte KEK → stored in login keychain via `/usr/bin/security`, **secret piped over stdin, never `-w <value>`**. Vault file stores only wrapped DEKs.
3. `src/core/vault.ts` — records `{ service, accountAlias, secretType, ciphertext, nonce, tag, version, createdAt, rotatedAt }`. Blind index over `service + accountAlias` so lookup needs no decryption and no plaintext metadata.
4. Atomic writes: temp file → `fsync` → `rename`. `0600` perms. Back up on each successful write, keep last N.
5. Corruption recovery: on decrypt failure, refuse and surface a recoverable error — never return partial/garbage as if valid.
6. Tests: round-trip; tamper detection; blind index; **`security` invoked with stdin not argv** (assert argv never contains the key — this is the `ps` leak guard); file-permission assertion.

### Failure modes
- `security` prompting on a TTY during tests → always pipe stdin; never let it touch the terminal.
- Keychain access prompts when the key was created by a different binary → record the creating app path with `-T` and document the re-prompt.

### Loop prompt
```
/loop VaultBroker Iteration I1 (Vault core) in vaultbroker/. Read iterations/PLAN.md section I1 first. Run `npm run check && npm run test:vault` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I2. Otherwise implement the I1 tasks in order, keep both commands green after every change, never print or log a credential value, pipe the keychain secret over stdin and never argv, use only node:crypto (no third-party crypto deps), add no native code, and stop at the I1 boundary. Commit when the exit criterion passes.
```

---

# I2 — Daemon, stdio shim, MCP transport

**Goal:** One harness can call a broker tool over stdio MCP and get a real answer, with the daemon holding all state behind a Unix domain socket.

**Depends on:** I1

**Exit criterion**
```bash
npm run check && npm run test:mcp
```
`test:mcp` spawns the shim as a child process, performs a real MCP `initialize` + `tools/list` + `tools/call` round trip, and asserts the socket is a `0700` Unix domain socket with **no TCP listener** (verified by asserting the daemon opens no internet socket).

### Tasks
1. `src/daemon/server.ts` — UDS at `<runtime>/broker.sock` inside the `0700` runtime dir. Single-instance via an advisory lock file. Idempotent start/stop.
2. `src/shim/main.ts` — stdio MCP server via `@modelcontextprotocol/sdk`. The shim holds **no** secret material. It reads its client registration token from a `0600` file and forwards to the daemon.
3. `src/daemon/session.ts` — request envelope `{ clientId, tool, args, projectPath }`; the daemon resolves the project from the client's cwd, never from a model-supplied value.
4. `tools/list_accounts` — returns service + alias only. **First real tool, first proof of non-disclosure.**
5. Lifecycle: `vaultbroker daemon start|stop|status`; shim auto-starts the daemon on demand.
6. Tests: full stdio round trip; assert no TCP socket is ever created (instrument `net`/`tls`); assert two concurrent shims share one daemon and one unlocked vault.

### Failure modes
- MCP SDK stdio transport is newline-delimited JSON — keep diagnostics on **stderr only**, never stdout, or the handshake corrupts.
- Daemon auto-start races between two shims → lock file must be atomic (`O_EXCL`).

### Loop prompt
```
/loop VaultBroker Iteration I2 (Daemon, stdio shim, MCP transport) in vaultbroker/. Read iterations/PLAN.md section I2 first. Run `npm run check && npm run test:mcp` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I3. Otherwise implement the I2 tasks in order using @modelcontextprotocol/sdk, keep diagnostics strictly on stderr so stdout stays a clean JSON-RPC channel, guarantee no TCP listener exists, never print or log a credential value, add no native code, and stop at the I2 boundary. Commit when the exit criterion passes.
```

---

# I3 — Policy engine & audit log

**Goal:** Nothing is permitted unless explicitly granted, and every decision is recorded in a tamper-evident log that contains no secret values.

**Depends on:** I2

**Exit criterion**
```bash
npm run check && npm run test:policy
```
Proves: default-deny for an ungranted client; an unlisted operation on a granted service is denied; TTL expiry denies; a capability bound to project A is refused in project B; a replayed nonce is refused; a `deploy`/`billing`/`delete` operation without fresh interactive approval is denied; and the audit log survives a middle-line edit being detected (hash chain).

### Tasks
1. `src/core/capability.ts` — capability mint/redeem. Fields per master plan §7. Deny-by-default: any missing or changed attribute → refuse. No wildcard `*`.
2. Operation tiers: `read` / `write` / `deploy` / `delete` / `billing` / `admin`. The top four always require fresh approval, never a cached grant.
3. Short TTL (minutes→hours), request cap, rate limit, project-path binding.
4. Nonce + replay guard persisted in the vault-adjacent state file.
5. `src/core/audit.ts` — append-only hash-linked log. Fields: event id, monotonic seq, timestamp, client id, cdhash, service, operation, decision, destination host, adapter version. **Never** a secret, never an auth header, never a full request body. Signed checkpoint placeholder reserved for v0.2 (Secure Enclave) — record the chain now, sign later.
6. `src/daemon/approval.ts` — approval requests go to the broker's own channel, **never** to model text. In v0 this is an interactive CLI prompt plus a macOS notification; Touch ID arrives in v0.2.
7. `vaultbroker approve|deny|list|revoke` commands.

### Failure modes
- Clock skew breaks TTL → store both issued and expiry, fail closed on negative remaining time.
- Approval UI must be unreachable by model-generated content — assert no MCP tool can create, widen, or extend a grant.

### Loop prompt
```
/loop VaultBroker Iteration I3 (Policy engine & audit log) in vaultbroker/. Read iterations/PLAN.md section I3 first. Run `npm run check && npm run test:policy` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I4. Otherwise implement the I3 tasks in order with deny-by-default as the default and no wildcard scopes, never print or log a credential value, never let any MCP tool create or widen a grant, keep approval strictly outside model-reachable text, add no native code, and stop at the I3 boundary. Commit when the exit criterion passes.
```

---

# I4 — Client identity binding

**Goal:** A harness's grant is bound to its code signature, and swapping or tampering with the binary is detected on the next connection.

**Depends on:** I3

**Exit criterion**
```bash
npm run check && npm run test:identity
```
Binds to a real installed harness (OpenCode or Codex), then proves: (a) a valid connection is accepted; (b) a modified/tampered binary, or a changed TeamID/CDHash, is refused; (c) refusal locks the vault and emits an audit event.

### Tasks
1. `src/install/identity.ts` — capture via `codesign`: `TeamIdentifier`, authority chain, designated requirement (`codesign -dr -`), CDHash/binary hash, notarization ticket presence, install path. Verified working on this Mac against Cursor.app (TeamID `VDXQ22DGB9`).
2. Persist the binding at registration; **re-verify on every connection**.
3. Mismatch → refuse the connection, lock the vault, emit a high-severity audit event, surface a notification.
4. Best-effort parent-process check in the shim: `process.ppid` → executable path via `ps` → compare against the registration. Document loudly that this is **not** kernel peer-credential verification (`LOCAL_PEERCRED`) — that needs the v0.2 Swift helper.
5. Tests: accept-valid, reject-tampered, reject-changed-team, reject-moved-binary; assert the v0.2 gap is documented in code, not silently assumed away.

### Failure modes
- `codesign -dv` writes to stderr, not stdout → capture both.
- Cursor is an Electron app with helper binaries; bind the **main** executable only, and note the child-process caveat.

### Loop prompt
```
/loop VaultBroker Iteration I4 (Client identity binding) in vaultbroker/. Read iterations/PLAN.md section I4 first. Run `npm run check && npm run test:identity` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I5. Otherwise implement the I4 tasks in order using codesign inspection only, re-verify identity on every connection, treat a signature mismatch as refuse-and-lock, document in code that the ppid check is best-effort and not kernel peer-credential verification, never print or log a credential value, add no native code, and stop at the I4 boundary. Commit when the exit criterion passes.
```

---

# I5 — Adapter framework & GitHub

**Goal:** A real GitHub API call is brokered end-to-end, and the token is proven absent from every observable output.

**Depends on:** I4

**Exit criterion**
```bash
npm run check && npm run test:adapter
```
Live GitHub call succeeds **and** a captured stdio transcript, the audit log, and the child process environment all assert zero occurrences of the token or any secret-shaped string.

### Tasks
1. `src/adapters/registry.ts` — allowlisted adapters only. Each declares fixed operations, fixed permitted hosts, fixed credential scope. No model-supplied URL escapes the host allowlist.
2. `call_api` — the daemon performs the request itself. `Secret<T>.useInHeader()` injects the credential; the plaintext never leaves daemon memory.
3. Response handling — **allowlist** the returned fields (not a blocklist). An outbound denylist additionally scans for credential patterns (`ghp_`, `sk-`, `napi_`, `AKIA`, JWT) and fails the request closed if one appears in a response body — defence against a provider echoing a token back.
4. `src/adapters/github.ts` — operations: `repo.read`, `repo.list`, `pr.list`, `pr.create`, `issue.list`. Host fixed to `api.github.com`.
5. Tests: live call; **captured stdio contains no secret**; allowlist strips unexpected fields; a mock returning a token-shaped body fails closed; a non-allowlisted host is refused.

### Failure modes
- The biggest risk this iteration exists to catch: any adapter path that returns raw response text to the model. Keep responses allowlist-shaped from day one.
- `run_adapter` for third-party MCP servers is **out of scope for this iteration**; defer until I8 at the earliest, and only with a one-shot fd launcher — never env vars.

### Loop prompt
```
/loop VaultBroker Iteration I5 (Adapter framework & GitHub) in vaultbroker/. Read iterations/PLAN.md section I5 first. Run `npm run check && npm run test:adapter` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I6. Otherwise implement the I5 tasks in order with an allowlisted host set and allowlisted response fields, inject credentials only through Secret<T>, fail closed on any secret-shaped value appearing in an outbound response, never print or log a credential value, do not implement run_adapter or any env-var credential injection in this iteration, add no native code, and stop at the I5 boundary. Commit when the exit criterion passes.
```

---

# I6 — Neon adapter & plaintext-token migration

**Goal:** The real plaintext Neon token is moved out of `~/.cursor/mcp.json` into the vault, and a live Neon call is brokered through it.

**Depends on:** I5

**Exit criterion**
```bash
npm run check && npm run test:neon
```
A live Neon call succeeds via the broker, **and** `grep -c 'napi_' ~/.cursor/mcp.json` returns `0` (the token is gone from the config file), with a verified backup of the original file retained.

### Tasks
1. `src/adapters/neon.ts` — Neon HTTP API, host fixed to the Neon endpoint. Operations: `branch.list`, `project.list`, `query.execute`.
2. `vaultbroker import --from-config` — read a token out of an existing harness config, write it straight into the vault, and never echo it (read → `Secret<T>` → vault, with no intermediate string in any log).
3. Rewrite `~/.cursor/mcp.json` to reference the broker instead of carrying the token. **Back up first; verify the backup; require explicit confirmation; provide `vaultbroker rollback`.**
4. Confirm `Neon` is not left behind as a live plaintext entry in Cursor's other config surfaces (`~/.cursor/mcp-servers.json`, workspace configs) — sweep for residual occurrences and report them.
5. Tests: import path never logs the token; config rewrite is atomic and reversible; live call succeeds; residual-token sweep returns clean.

### Failure modes
- **Do not delete the user's token without a verified backup.** If the backup can't be read back, abort and say so.
- Cursor may cache MCP config — note that a restart is required and report it, don't paper over it.

### Loop prompt
```
/loop VaultBroker Iteration I6 (Neon adapter & plaintext-token migration) in vaultbroker/. Read iterations/PLAN.md section I6 first. Run `npm run check && npm run test:neon` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I7. Otherwise implement the I6 tasks in order, back up and verify the backup BEFORE rewriting ~/.cursor/mcp.json, never print or log the imported token, sweep for any residual plaintext occurrence and report them, keep the config rewrite atomic and reversible, add no native code, and stop at the I6 boundary. Commit when the exit criterion passes.
```

---

# I7 — Installer for all four harnesses

**Goal:** All four installed harnesses can be registered with a shown diff, a verified backup, and a working rollback — and three of them via their supported CLI.

**Depends on:** I6

**Exit criterion**
```bash
npm run check && npm run test:install
```
`test:install` asserts a correct diff is generated for Cursor, Claude Code, OpenCode and Codex; that applying it produces the exact shown diff; that rollback restores byte-identical originals; and that the per-client config entry contains **no secret**.

### Tasks
1. `src/install/detect.ts` — probe the verified locations: `/Applications/Cursor.app` + `/usr/local/bin/cursor`; `~/.local/bin/claude`; `~/.opencode/bin/opencode`; `/Applications/ChatGPT.app/Contents/Resources/codex`.
2. `src/install/diff.ts` — render an exact, human-readable proposed diff. `vaultbroker install <client> --dry-run` prints it and exits without writing. **Never write without explicit confirmation.**
3. Prefer the supported CLI: `claude mcp add`, `opencode mcp add --global`, `codex mcp add`. **File-edit only for Cursor** (`~/.cursor/mcp.json` `mcpServers` map), with backup + rollback.
4. Codex writes TOML (`[mcp_servers.<name>]` in `~/.codex/config.toml`); OpenCode writes the `mcp` map (`type: "local"`, `command: [...]` array) in `~/.config/opencode/opencode.json`. Handle both formats correctly and preserve unrelated entries byte-for-byte.
5. Absolute signed-path entry, fixed args, no secrets, no env blocks carrying credentials.
6. `vaultbroker install|uninstall|status|revoke --client <name>` with rollback wired to I6's mechanism.
7. Tests: diff generation for all four; apply matches diff; rollback is byte-identical; no secret in any written entry; idempotent re-install.

### Failure modes
- Config formats drift between harness versions → isolate per-client writers, version-pin what is known, and always offer `--dry-run`.
- Writing JSON via naive string manipulation corrupts unrelated keys → parse, mutate, re-serialise preserving key order.

### Loop prompt
```
/loop VaultBroker Iteration I7 (Installer for all four harnesses) in vaultbroker/. Read iterations/PLAN.md section I7 first. Run `npm run check && npm run test:install` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, do not start I8. Otherwise implement the I7 tasks in order, prefer the supported CLI for claude-code, opencode and codex, file-edit only for cursor, always print the exact diff and require explicit confirmation before writing, back up before every write, preserve unrelated config keys byte-for-byte, never write a secret into any config file, add no native code, and stop at the I7 boundary. Commit when the exit criterion passes.
```

---

# I8 — Dogfood & conformance gate

**Goal:** The locked v0 target is proven: a credential drives real calls from all four harnesses and not one byte of it reaches model context, config files, transcripts, `ps` output, or the audit log.

**Depends on:** I7. **This is the ship gate. Nothing else counts.**

**Exit criterion**
```bash
npm run check && npm run test:conformance
```
The conformance suite is the release gate and must pass on every subsequent change.

### Tasks
1. **Static check** — CI/lint fails if any tool handler, adapter, or type is capable of returning a `Secret<T>` or a decrypted field. Enforce via a lint rule plus a type boundary that cannot be widened.
2. **Runtime denylist** — every outbound MCP response scanned for credential patterns; fail closed. (Built in I5; wire it as a hard gate here.)
3. **Full conformance test** — a fake harness drives *every* tool with adversarial arguments and asserts no secret-shaped byte crosses the stdio boundary, across all four client registrations.
4. **Live dogfood** — register all four harnesses (Cursor, Claude Code, OpenCode, Codex), approve, and drive a real `call_api` from each. Capture stdio traffic, harness transcripts, all four config files, `ps -E`, and the audit log; assert zero secret occurrences in all five.
5. **Negative tests** — ungranted op denied; expired TTL denied; wrong project denied; replayed nonce denied; `deploy` without approval denied; tampered binary denied; repeated denials trigger the anomaly response (halt leases → revoke → lock → notify).
6. **`vaultbroker status`** — a single honest control panel: registered clients, live capabilities, expiry, adapter versions, recent audit events, and any residual plaintext-token findings.
7. Final README pass: security claims, honest threat boundary, and the v0.2 gap list (Secure Enclave, Touch ID, notarization, kernel peer creds) stated plainly.

### Failure modes
- A provider echoing a token in a response body — this is exactly what the runtime denylist exists for; don't weaken it to a warning.
- Residual plaintext tokens elsewhere on disk. Sweep and **report**, don't silently fix files outside the project's own scope.

### Loop prompt
```
/loop VaultBroker Iteration I8 (Dogfood & conformance gate) in vaultbroker/. Read iterations/PLAN.md section I8 first. Run `npm run check && npm run test:conformance` BEFORE editing: if it exits 0, stop the loop and report DONE — do not re-arm, this is the ship gate. Otherwise implement the I8 tasks in order, treat the conformance suite as a hard release gate rather than a warning, drive real calls from all four harnesses and assert zero secret occurrences in stdio traffic, harness transcripts, all four config files, ps -E output and the audit log, keep the README honest about what v0 does NOT protect against, add no native code, and stop at the I8 boundary. Commit when the exit criterion passes.
```

---

## Critical path & risks

| Iteration | Risk if rushed | What must never slip |
|---|---|---|
| I0 | Guardrail defined late → retrofitted, weasel-worded comments | The negative `Secret<T>` test |
| I1 | Keychain secret leaks via `ps` argv | stdin-only key delivery + a test that asserts it |
| I2 | Diagnostics on stdout corrupt the MCP channel | stderr-only logging |
| I3 | A wildcard or cacheable approval sneaks in | deny-by-default; fresh approval for deploy/delete/billing |
| I4 | Identity check becomes decorative | re-verify **every** connection; refuse-and-lock on mismatch |
| I5 | Raw response text leaks a token to the model | allowlist response fields; fail closed |
| I6 | User's only Neon token lost | verified backup before rewrite; rollback |
| I7 | Silent config corruption across harnesses | diff shown; confirmation required; byte-identical rollback |
| I8 | Ship gate weakened to "passes mostly" | zero secret occurrences, or it doesn't ship |

## After I8

`I8` passing means the product's central claim is **true**. Everything after is scope:
v0.2 (Xcode install → Secure Enclave identity, Touch ID, biometric keychain ACLs, signed +
notarized app, `LOCAL_PEERCRED` peer verification) and v0.3 (sandboxed adapters, dynamic
credentials, App Attest, licensing, Endpoint Security for an enterprise tier). Do not start
either until the conformance gate has stayed green.