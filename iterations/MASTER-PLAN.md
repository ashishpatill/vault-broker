# VaultBroker — macOS-native, model-blind credential broker

**Status:** planning
**Date:** 2026-10-06
**Project folder:** `vaultbroker/` (created, empty)
**CLI name:** `vaultbroker`

---

## 1. Goal

One locally-installed credential broker. Every AI harness on the Mac connects to it over
local stdio MCP, uses shared account aliases, and **never receives a credential value**.

The product is **credential non-disclosure + centralized least-privilege policy**, not
"a password manager with an MCP interface."

### The single invariant (everything else is negotiable, this is not)

> The model may request an authorized action, but it never receives the credential
> that authorizes that action.

Enforcement must be **architectural**, not policy-based. There is no `get_secret` tool,
no "redact before returning" filter, no trust in adapter code. A credential exists only
inside: (a) the vault process memory while a brokered request is in flight, or (b) the
environment/fd of a broker-launched, allowlisted child process.

---

## 2. Verified environment findings

All checked on this machine, not assumed.

| Finding | Value | Consequence |
|---|---|---|
| OS | macOS 26.2 (26.2 / build 25C56), arm64 | Apple silicon — Secure Enclave available |
| FileVault | **On** | Vault on disk is encrypted at rest by OS too |
| SIP | **enabled** | Blocks some injection/debugging paths |
| Xcode / Command Line Tools | **NOT INSTALLED** (`xcode-select -p` fails; `/Library/Developer/CommandLineTools` absent; CLT receipt is stale/orphaned) | **Cannot compile Swift or any native code. Cannot build .app, cannot sign, cannot notarize.** |
| Codesigning identities | **0 valid identities** | Cannot sign/notarize any artifact yet |
| `codesign` (inspection) | **Works** — verified on Cursor.app (TeamID `VDXQ22DGB9`, DR extracted, Notarization Ticket stapled) | **Client identity binding is achievable TODAY with no Xcode.** |
| `security` (Keychain CLI) | `/usr/bin/security`, login keychain present | Keychain read/write achievable via CLI |
| Node | v22.23.2 | Primary implementation language for v0 |
| Bun / Cargo / Python | 1.4.0 / 1.96 / 3.13.7 | Fallbacks / packaging |

### The hard blocker, stated plainly

Everything in the "Apple hardware" story — **Secure Enclave key generation, Touch ID via
LocalAuthentication, keychain biometric ACLs (`kSecAccessControlBiometryCurrentSet`),
Hardened Runtime, notarization, Endpoint Security system extension** — requires a native
build toolchain and a Developer ID identity.

`security` CLI cannot create a Secure Enclave key and cannot set a biometry ACL on a
keychain item. There is no workaround; this is an API-surface limit, not a packaging one.

**Therefore the plan is explicitly two-phase.** v0 proves the security invariant with what
works today. v0.2 adds the Apple hardware layer once Xcode is installed. Do not fake the
hardware claims in v0 — that would be the exact "marketing over substance" failure this
product is positioned against.

---

## 3. Verified integration surface

Four harnesses are installed on this machine right now, and **all four support local stdio
MCP servers**. Three of four expose a supported CLI for registration; Cursor is file-only.

| Harness | Present as | Registration | Config location |
|---|---|---|---|
| **Cursor** | `/Applications/Cursor.app` + `/usr/local/bin/cursor` | JSON file only (no CLI) | `~/.cursor/mcp.json` → `mcpServers` map |
| **Claude Code** | `~/.local/bin/claude` | `claude mcp add <name> <cmd> -- <args>` | `~/.claude.json` |
| **OpenCode** | `/Applications/OpenCode.app` + `~/.opencode/bin/opencode` | `opencode mcp add --global <name> -- <cmd...>` | `~/.config/opencode/opencode.json` → `mcp` map (`type: "local"`, `command: [...]` array) |
| **Codex** | `/Applications/ChatGPT.app/.../codex` | `codex mcp add` | `~/.codex/config.toml` → `[mcp_servers.<name>]` |

Detection is therefore a matter of probing known paths + binary names. No scanning API needed.

### Live demonstration opportunity — already on disk

Two real findings that make this project immediately demonstrable rather than theoretical:

1. **`~/.cursor/mcp.json` currently contains a plaintext Neon bearer token**
   (a partially-redacted live token, under `mcpServers.Neon.headers.Authorization`). This is exactly the
   leak class VaultBroker exists to eliminate. It is the ideal v0 migration demo: import the
   token into the vault, install the broker entry, show the token gone from the config file.
2. **`~/.codex/config.toml` is set to `sandbox_mode = "danger-full-access"` with
   `approval_policy = "never"`** — i.e. a harness with no approval gate and full filesystem
   access. This is the threat model made concrete, and a good justification for policy defaults.

Also from prior sessions (ICM memory): repeatedly burning hours hunting for API keys scattered
across `.env`, `mcp.json`, `process.env`, 1Password and the macOS keychain — the SuperLearn
Dodo test-key search is a documented example. That is the recurring pain this product removes.

---

## 4. Architecture

### Why a daemon + shim, not a single stdio process

MCP stdio means **the harness launches the broker**. If every harness launched its own broker
process, then "authenticate once, use everywhere" is impossible — you'd have four unlocked
vaults, four approval authorities, four audit logs, and four chances for a race.

So split the two responsibilities:

```
Cursor ──┐                    ┌─────────────────────────────┐
Claude ──┤ stdio MCP          │  vaultbroker daemon         │
OpenCode ┼───────────────────►│  - encrypted vault          │
Codex  ──┘ (shim, no secrets) │  - policy + capability engine│
                            │  - approval authority       │
   (shim reads token from     │  - service adapters          │
    0600 file owned by user,  │  - tamper-evident audit log │
    verifies OWN signature)   │  - Secret material stays here│
                               └───────────┬─────────────────┘
                              Unix domain socket (0700 dir)
                                    NO TCP. NO LISTENING PORT.
```

- **No network listener at all.** The only socket is a filesystem Unix domain socket inside a
  `0700` directory under `~/Library/Application Support/VaultBroker/`. This is the structural
  answer to "not vulnerable to man-in-the-middle": there is no network path to intercept.
- Each harness gets its own `shim` process; the shim holds **no** secret material and is
  disposable. Killing all shims does not lose state (daemon owns it).
- CLI use case is the same surface:
  `vaultbroker exec --project ~/src/app -- opencode`

### Client identity binding — works today, no Xcode

This is the highest-value security feature that is *unblocked*. At registration, capture via
`codesign`:

- `TeamIdentifier`, full authority chain
- designated requirement (`codesign -dr -`)
- `CDHash` / binary content hash
- notarization ticket presence
- installation path

Re-verify on **every** connection. If the signature, team, or content hash changes after
approval → refuse, lock the vault, alert. This directly detects the "approved harness got
replaced/tampered" attack, which is otherwise invisible.

Note explicitly: for the stdio shim, `process.ppid` + `/proc`-equivalent path inspection gives a
*best-effort* parent identity check. Definitive kernel peer credentials (`LOCAL_PEERCRED`)
require a native helper → v0.2. The v0 gap is written down in §7 rather than papered over.

---

## 5. Vault & crypto design

```
record: { service, accountAlias, secretType, ciphertext, nonce, tag, createdAt, rotatedAt }
key hierarchy:
   KEK  → macOS Keychain (login keychain, via /usr/bin/security, secret piped via STDIN
                                — never argv, because argv is visible in `ps`)
   DEK  → per-record data key, HKDF-SHA256(KEK, recordId || version)
   AEAD → AES-256-GCM (node:crypto, no third-party dep)
   IDX  → HMAC-SHA256(separate index key) blind index over service+alias,
           so account lookup works without decrypting and without plaintext metadata
```

Design points:
- **Per-record encryption** + key versioning, so rotation is per-record and cheap.
- **Blind index** for service/account lookup — a stolen vault file reveals no account names.
  (Metadata leak matters: account aliases and project paths are themselves sensitive.)
- `security` CLI secret must be delivered via stdin, never `-w <value>`. `ps` exposure is a
  real and commonly-missed leak.
- Atomic writes (temp + `rename`), encrypted backups, `0600` perms, recovery on corruption.
- Memory hygiene: zeroize buffers where practical; drop decrypted key from daemon state on
  idle timeout / lock event.

**Known v0 limitation, stated up front:** with only the `security` CLI available, the KEK cannot
carry a biometric ACL, so vault unlock is a single keychain-unlock event rather than a Touch ID
gate. The keychain itself is protected by FileVault + the login password, which is a real
boundary — just not the one in the marketing copy. Biometric ACL arrives with the native helper.

---

## 6. MCP tool surface (the important part)

### Tools that exist

| Tool | Purpose | Returns secrets? |
|---|---|---|
| `list_accounts` | service + alias only | No |
| `list_grants` | this client's own capabilities + expiry | No |
| `request_access` | ask for a capability (approval happens in broker UI, **never** from model text) | No |
| `call_api` | broker performs the provider call, returns filtered business result | No |
| `run_adapter` | broker launches a **registered, allowlisted** adapter; credential injected into child's fd/env | No |
| `audit_recent` | this client's own recent events | No |

### Tools that must never exist

- `get_secret`, `read_secret`, `export`, `copy_to_clipboard`, `list_all_secrets` — any tool
  whose return value is the credential.
- A generic `run_shell(command, with_credential: true)`. That is unrestricted secret
  delegation and it destroys the entire security model. The spec should fail review if this
  appears.

### Enforcement, not documentation

The invariant gets a real test suite, not a comment:

1. **Static check** — no adapter or tool handler returns a field derived from decrypted secret
   material; enforced by a wrapper type (`Secret<T>`) whose only permitted operations are
   `injectInto(child)` / `useInFetch()`. It cannot be serialized, logged, or returned.
2. **Runtime denylist** — outbound MCP responses are scanned for known credential patterns
   (`ghp_`, `sk-`, `napi_`, `AKIA`, JWT, provider-specific) and the request fails closed.
   This is defence-in-depth against a *provider* echoing a token back in a response body.
3. **Conformance test** — a fake harness drives every tool and asserts no secret-shaped byte
   ever crosses the stdio boundary. Run in CI and as a release gate.

Adapter responses are additionally filtered by allowlist of returned fields, not by blocklist.

---

## 7. Capability & policy model

```
Capability {
  id, clientId, service, accountRef,
  operations[],            // github.pr.create, github.repo.read, neon.query ...
  projectPath,             // bound to a specific project dir
  issuedAt, expiresAt,     // short TTL: minutes to hours, not days
  maxRequests, requestCount,
  rateLimit,
  binding { cdhash, teamId, installPath }
}
```

- **Deny-by-default.** Any attribute missing or changed → refuse. No wildcard `*`.
- Operation tiers are explicit and separate: `read` / `write` / `deploy` / `delete` /
  `billing` / `admin`. Production, billing, admin and delete require interactive approval
  *every time*, never a cached grant.
- Leases are short-lived and bound to client + project + operation set.
- Nonces + replay protection on capability redemption.
- **The model can never write policy.** No tool creates, widens, or extends a grant. Policy
  changes only via `vaultbroker` CLI or the broker UI.
- Rate limits and request-size limits per capability.

### Honest threat-boundary statement (must appear in the README, not just this doc)

Can guarantee: no credentials in model context; no credentials in MCP tool results; no
credentials in harness config files; no network listener; per-client revocable grants;
tamper-evident audit; detection of harness binary tampering.

Cannot guarantee: protection from a fully compromised macOS kernel; a malicious harness from
*misusing* a permission the user already granted (we bound blast radius + make it attributable);
detection of every malware/supply-chain attack; secrecy after a credential is deliberately
injected into an authorized third-party process.

---

## 8. Adapters (v0)

Two, chosen because they prove the model end-to-end and because real credentials for them are
already present on this machine:

1. **GitHub** — REST API via `call_api`. Fixed operation allowlist, fixed host
   (`api.github.com`), token never leaves the daemon.
2. **Neon / Postgres HTTP API** — direct migration target for the plaintext token currently
   in `~/.cursor/mcp.json`.

Rule for every adapter: fixed operations, fixed destinations (host allowlist, no model-supplied
URL without allowlist match), fixed credential scope, no arbitrary path/command parameters.
Adapters are broker-side by default. `run_adapter` exists only for third-party MCP servers that
must receive the credential — and even then, only for pinned signed packages with a verified
hash, never a model-chosen command.

### The known weak point, named honestly

If a third-party MCP server must be launched with the credential, the strongest channel available
is a one-shot anonymous pipe (inherited fd), not an environment variable — env vars leak via
crash reports, child processes, accidental logging, and `ps -E` to any same-user process. A tiny
launcher reads the fd and sets the child's env. This is materially better than env, not perfect.
Preferred path remains broker-side adapters where the credential never leaves the daemon.

---

## 9. Installer (the "integrates automatically" feature)

`vaultbroker install <client>` must:

1. Detect installed harnesses (probe known paths + binary names — all four found above).
2. **Print the exact proposed diff** and require interactive confirmation. Never silently edit.
3. Back up the existing config file first.
4. Write the minimal entry — absolute signed path, fixed args, **no secrets** in the config.
5. Record the per-client grant + codesign identity.
6. Provide `vaultbroker uninstall <client>` / `revoke --client <client>` that restores the backup.

Ordering for each client: prefer the **supported CLI** (`claude mcp add`, `opencode mcp add`,
`codex mcp add`); fall back to file editing only for Cursor, with backup + rollback.

Config diff rendering is a real deliverable — "here is exactly what changes, approve or not"
is the trust primitive for the whole auto-install story.

---

## 10. v0 scope

### Deliver
- Vault with per-record AES-256-GCM, HKDF key hierarchy, blind indexes, Keychain-held KEK
- Policy engine: deny-by-default capabilities, operation tiers, short TTL, project binding
- Codesign-based client identity binding + tamper detection
- Daemon (UDS, 0700) + per-harness stdio MCP shim
- MCP tool surface per §6, with the `Secret<T>` type and conformance tests
- GitHub + Neon adapters
- Hash-linked, tamper-evident audit log (no secret values, ever)
- `vaultbroker` CLI: `init`, `add`, `install`, `uninstall`, `list`, `status`, `revoke`,
  `approve`, `lock`, `exec`
- Installer adapters for all four harnesses with diff + backup + rollback

### Explicitly NOT in v0 (do not claim, do not stub-and-call-it-done)
- Secure Enclave device identity, Touch ID approval, biometric keychain ACL
- Code signing / notarization / Hardened Runtime
- Endpoint Security system extension
- App Attest, Sign in with Apple, licensing, monetization
- Kernel peer-credential (`LOCAL_PEERCRED`) client authentication
- Adapter sandboxing via seatbelt profiles

---

## 11. Milestones (build order)

- **M0 — Skeleton.** Repo layout, CLI arg parsing, `init` creates 0700 runtime dir + vault file.
- **M1 — Vault core.** Crypto, key hierarchy, blind index, CRUD, atomic writes, unit tests.
- **M2 — Daemon + shim.** UDS transport, MCP handshake, tool registry. First end-to-end
  `list_accounts` from one harness.
- **M3 — Policy.** Capability mint/redeem, operation tiers, TTL, project binding, replay guard.
- **M4 — Identity.** Codesign capture + per-connection re-verification + tamper response.
- **M5 — Adapters.** GitHub, then Neon.
- **M6 — Installer.** Detection, diff, backup, apply, rollback for all four harnesses.
- **M7 — Audit + invariants.** Hash-linked log, `Secret<T>`, conformance suite, CI gate.
- **M8 — Dogfood.** Import the plaintext Neon token out of `~/.cursor/mcp.json`; run a real
  request from each of the four harnesses; confirm no credential appears in any transcript,
  config file, or `ps` output.

M8 is the actual deliverable that matters. Everything before it is scaffolding.

---

## 12. Validation plan

The product ships on one measurable claim, so test exactly that:

1. Populate vault with GitHub + Neon credentials.
2. Register all four harnesses; complete approvals.
3. Drive a real request from each harness (`call_api`).
4. **Assert zero secret-shaped strings** in: MCP stdio traffic (captured), each harness's
   transcript/session history, all four config files, `ps -E` output, the audit log, and any
   crash/error output.
5. Assert `~/.cursor/mcp.json` no longer contains the plaintext Neon token.
6. Tamper test: modify a copy of a harness binary signature → registration refuses.
7. Expiry test: wait out TTL → request denied.
8. Negative test: model attempts a `deploy`/`billing` op without approval → denied + prompt shown.

---

## 13. v0.2 — Apple hardware layer (requires Xcode install + Developer ID)

- Install Xcode (~10–15 GB, Apple ID required) — **prerequisite**, currently missing.
- Register Developer ID, enable App Store Connect / notarization credentials.
- Native `vaultbroker-helper` (Swift):
  - Secure Enclave P-256 device identity key; non-exportable private key.
  - Bind vault to device; sign broker sessions, approvals, and audit checkpoints.
  - `LocalAuthentication` Touch ID gate for production/billing/delete and for vault unlock.
  - Keychain item with `kSecAccessControlBiometryCurrentSet` — invalidates on new biometric
    enrolment, which is a genuinely strong property worth claiming *only* once true.
  - `LOCAL_PEERCRED` peer verification → definitive client authentication (closes the v0 gap).
- Signed + notarized `.app` with Hardened Runtime and a minimal entitlement set.
  No library-validation disable, no JIT entitlement, no Accessibility/FDA/Screen Recording.
- Refuse to run if the broker binary's own signature fails self-verification.
- Gate all updates behind signature + notarization check; rollback-resistant.

## v0.3 — Hardening & monetisation
- Sandboxed adapters (seatbelt profiles with fixed network + filesystem rules)
- Dynamic/short-lived credentials: OAuth refresh, GitHub installation tokens, WIF for cloud
- App Attest for device attestation + enrolment/recovery approval (with the honest caveat that
  Apple states it cannot prove the OS is clean — do not overclaim)
- Optional encrypted telemetry, privacy-preserving, opt-in only
- Sign in with Apple for identity + licensing; Secure Enclave key for device binding (distinct roles)
- Endpoint Security system extension for an enterprise tier — **last**, it is privileged,
  raises operational risk and expands the attack surface
- MDM / managed policy support

---

## 14. Decisions — RESOLVED 2026-10-06

| # | Decision | Rationale |
|---|---|---|
| 1 | **Stack: TypeScript/Node now, Swift helper in v0.2** | Node 22 already installed; v0 ships the full non-disclosure invariant immediately. Best MCP SDK maturity, so protocol iteration is fastest. Apple hardware layer deferred, not faked. |
| 2 | **v0 adapters: GitHub + Neon** | Both have real credentials present on this machine. Neon doubles as the migration demo (plaintext token in `~/.cursor/mcp.json`). Minimum adapter surface to prove the invariant end-to-end. |
| 3 | **Monetisation: excluded from v0** | v0 carries one measurable claim. Licensing adds Sign in with Apple + App Attest surface competing with the security core. Revisit at v0.3. |
| 4 | **Name: `vaultbroker`** (placeholder, freely renameable) | Directory + CLI name. |

### Locked v0 target

> Prove end-to-end that a credential stored in `vaultbroker` can drive a real GitHub and a real
> Neon request from all four installed harnesses (Cursor, Claude Code, OpenCode, Codex), and
> that not one byte of it reaches model context, harness config files, transcripts, `ps` output,
> or the audit log.

If that holds, the product's central claim is true and the rest is engineering.

## 15. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| "Secure Enclave / Touch ID" implied in v0 but not delivered | **High — credibility** | §10 non-goals are explicit; README states limits up front |
| Env-var injection to third-party MCP servers | Medium | Prefer broker-side adapters; one-shot fd launcher; document residual gap |
| `security` CLI secret lands in `ps` argv | Medium | Pipe via stdin only; CI test greps for it |
| Same-user malware reads vault/keychain | Medium | Out of scope for v0; documented; FileVault + SIP already help |
| Four harness config formats drift | Medium | Adapters isolated per client; version-pinned; `--dry-run` always available |
| Scope creep into "secure everything" | High | v0 = one invariant, four harnesses, two adapters. Full stop. |
| Codex at `danger-full-access` + `approval_policy=never` | High | Flag it; per-client policy profile caps blast radius regardless of harness sandboxing |