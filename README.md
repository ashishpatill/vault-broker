# VaultBroker

A local credential broker for AI coding harnesses. Harnesses ask the broker to *do*
something with an account; they never receive the credential that authorises it.

**Status: iteration I5 — adapter framework and GitHub.** Provider calls are brokered with
fixed operations, fixed hosts and allowlisted response fields, with a fail-closed scan on
every response body. Nothing is installed into a real harness yet — that is I7.
See [iterations/PLAN.md](iterations/PLAN.md) for the roadmap
and [iterations/MASTER-PLAN.md](iterations/MASTER-PLAN.md) for the design.

---

## The invariant

> The model may request an authorized action, but it never receives the credential that
> authorizes that action.

This is enforced structurally, not by policy:

- There is no `get_secret` tool, and none will be added. A generic
  `run_shell(command, with_credential)` is written into the spec as an automatic failure —
  it is unrestricted secret delegation.
- Credentials are held in `Secret<T>` ([src/core/secret.ts](src/core/secret.ts)), which
  stores them in an ES private field and exposes only *callback-scoped* sinks
  (`withHeaders`, `withEnvVar`). The plaintext is unreachable outside the callback, so a
  careless caller cannot re-open the leak.
- `test/secret.test.ts` asserts the negative: `JSON.stringify`, string coercion,
  `util.inspect`, property enumeration, spread, and `structuredClone` must all fail to
  produce the credential. A `Secret` is also not assignable to `string`, enforced by
  `@ts-expect-error` under `tsc`.

## What this does not protect against

Stated up front, because a security product that oversells is worse than none:

| Threat | Status |
|---|---|
| Credential reaching model context via tool output | **Prevented** by design + tested |
| Credential sitting in a harness config file | **Prevented** (arrives with iteration I7) |
| A malicious *other* MCP server reading the vault | **Prevented** — adapters are allowlisted, no generic exec |
| Man-in-the-middle between broker and harness | **Structurally avoided** — Unix domain socket in a `0700` directory, no TCP listener |
| Compromised harness **misusing a permission you granted** | **Not prevented.** We narrow scope, shorten TTLs, require fresh approval for sensitive operations and make it attributable. That is all. |
| A client **claiming to be** a different harness | **Partially prevented.** A registered harness's binary is verified by code signature on every connection (I4). But any same-user process can still *reach* the socket and claim a registered client id, because Node cannot read kernel peer credentials. v0.2's native helper closes that. |
| Malware running as the same user | **Not prevented.** It can read broker memory. FileVault and SIP help at rest; they do not help a live process. |
| Compromised macOS kernel / malicious hypervisor / altered boot chain | **Not prevented.** A user-space vault cannot defend against this. |

## Where this design is still weak

- **Third-party MCP servers.** If a provider must be launched with the credential in its
  environment, `ps -E` can read it for any same-user process. The default is now
  broker-side adapters (I5), which keep the credential inside the daemon entirely. A
  one-shot-fd launcher path exists conceptually for providers that cannot be modelled as
  fixed operations, and is deliberately **not built yet**: adding it before the rest of the
  system is proven would weaken the model for a case that may never arise.
- **JavaScript cannot zeroize strings.** `Secret` stores credential bytes in a `Buffer` so
  `dispose()` can scrub them, but any copy a `Headers` object or child environment makes
  is GC-bound, not wiped.
- **Client identity verification is signature-based only in v0.** Matching a harness's
  code signature (Team ID, designated requirement, CDHash) detects a swapped or tampered
  binary, but definitive kernel peer-credential checks (`LOCAL_PEERCRED`) need a native
  helper — iteration v0.2, which requires Xcode.
- **Not in v0 at all:** Secure Enclave device identity, Touch ID approval, biometric
  keychain ACLs, code signing, notarisation, sandboxed adapters, App Attest.

## Storage model (v0.1)

```
KEK  32 random bytes in the macOS Keychain (service vaultbroker:kek, account vault:v1)
     │  HKDF-SHA256
     ├── indexKey   → HMAC blind index over (service, accountAlias)
     └── per record → AES-256-GCM DEK, bound to recordId + kdfVersion via AAD
```

Consequences worth knowing:

- **The vault file contains no key material.** Per-record keys are *derived*, not stored,
  so `vault.json` holds only ciphertext, nonces, tags and blind indexes.
- **The vault file contains no plaintext metadata either.** Service names and account
  aliases live inside the ciphertext; lookup uses an HMAC. Someone who copies the file
  learns how many credentials exist and nothing about which services they are for.
- **Random bytes cannot pass through a text CLI.** 32 random bytes are frequently invalid
  UTF-8; decoding them would expand the value (32 → 49-60 bytes) and make every stored
  vault permanently undecryptable. The KEK is therefore hex-encoded for keychain
  transport. There is a regression test for this.
- **Tampering is loud.** A modified ciphertext, a swapped record, a wrong key, or an
  unknown schema version all fail closed. A vault that cannot be authenticated is treated
  as compromised, never as empty.
- **Backups are encrypted too**, taken before each write, pruned to the newest five.

Known limitation: `security` cannot set a biometry ACL, so unlock is gated on the login
Keychain password rather than Touch ID. The native helper in v0.2 replaces this.

## Process architecture (v0.2)

```
Cursor ──┐                    ┌──────────────────────────────┐
Claude ──┤ stdio MCP          │  vaultbroker daemon          │
OpenCode ┼───────────────────►│  - vault + keychain          │
Codex  ──┘ shim (no secrets)  │  - policy (I3)               │
                              │  - audit log (I3)            │
   shim reads no secret,      │  credential material stays   │
   owns no vault              │  inside this process         │
                              └──────────────┬───────────────┘
                                Unix domain socket, 0700 dir
                                     NO TCP. NO PORT.
```

One daemon serves every harness. That is the reason for the split: a separate broker
process per harness would mean four unlocked vaults, four approval authorities and four
audit logs, and "authenticate once" would be impossible. The shim is disposable — kill
every shim and no state is lost.

There are two protocols, deliberately:

- **MCP**, spoken by the harness to the shim over stdio. stdout is the JSON-RPC channel.
- **VaultBroker's own frame protocol**, spoken by the shim to the daemon. Keeping it
  separate means a compromised harness sees only the tool surface, and a change to MCP
  tooling cannot silently alter the internal trust boundary.

Verified on a live daemon:

```
lsof -p <daemon> -a -i    → nothing (no network sockets at all)
lsof -p <daemon> -a -U    → broker.sock only
daemon stdout             → 0 bytes
shim stdout               → pure JSON-RPC, every line parses
credentials in either     → none
```

### Tool surface

Two tools, both metadata-only:

- `list_accounts` — service, account alias, type, timestamps. No secret values.
- `broker_status` — daemon state and connected clients.

The forbidden set (`get_secret`, `export`, `copy_to_clipboard`, `run_shell`) is asserted
by name in the test suite rather than left to review discipline, and no tool accepts any
arguments — free-form input is a disclosure risk. `list_accounts` builds its response from
an explicit field list rather than a spread, so a field added to `VaultEntry` later cannot
leak into a response by accident.

### What the socket does not yet prove

Any process running as this user can reach the socket. I4 binds each client to its code
signature; definitive kernel peer-credential checks (`LOCAL_PEERCRED`) need a native helper
and land in v0.2. `peerCredentials()` in `src/daemon/server.ts` is the seam where that
check goes, and it currently returns `undefined` honestly rather than pretending.

## Adapters (v0.5)

An adapter is the only component allowed to spend a credential on a provider call, and it
is constrained on four axes:

| Constraint | Why |
|---|---|
| **Fixed operations** | An operation the adapter does not declare cannot be called at all. |
| **Fixed hosts** | Requests go only to an adapter-chosen base URL. A caller cannot supply a URL — `callApi` takes a *path*, never a URL. |
| **Validated parameters** | Path segments match `^[A-Za-z0-9._-]{1,128}$`; refs allow slashes (real branches are `fix/flux`) but reject `..`. |
| **Allowlisted response fields** | An explicit per-operation field list. Not a blocklist — a blocklist only knows about fields someone already thought of, and providers add fields freely. |

Every response then goes through a **fail-closed credential scan** before parsing, because
a provider echoing a token back is the case the whole design has to survive. Upstream
error bodies are reported as a status code only — never included in the error message,
since error bodies can reflect the request.

Order matters: the host is checked **before** the credential is spent, so there is no
reason to hand a credential to a request that is about to be refused.

```ts
const result = await adapter.execute(
  { operation: 'github.repo.read', params: { owner: 'octocat', repo: 'Hello-World' } },
  vault.getSecret('github', 'work'),   // a Secret<T>, disposable by the caller
)
```

Verified end to end against a local server standing in for the API:

```
server saw Authorization: Bearer ghp_REALPATHTOKEN…   ← credential spent, correctly
result: {"id":1296269,"name":"Hello-World","full_name":"octocat/Hello-World","private":false}
result contains token? false
```

A repository payload carries `permissions`, `owner`, `subscribers_count` and internal refs.
None of it is relayed.

### Operations deliberately not implemented

`github.repo.delete`, `github.release.create`, `github.billing.read` and
`github.member.admin` are in the catalogue but **not** implemented. An unimplemented
operation is refused by the registry; a half-implemented one invites a mistake at the worst
possible moment. `github.repo.list` is scoped to `/user/repos` rather than accepting a
login, so a grant cannot be redirected at somebody else's private repositories.

### Verification status, stated precisely

The full path — credential injection, host checking, response scan, field projection,
non-disclosure — is exercised against a **local HTTP server**. A live `api.github.com`
test exists but is **skipped**, because there is no GitHub token on this machine. "Verified
against a stub that behaves like the API" and "verified against the real API" are different
claims, and only the first one is true today.

## Client identity binding (v0.4)

A grant is bound to **what a harness's binary actually is**, not to a path string. A
writable path can be repointed at a different executable, so path checks catch nothing.
Registration captures, via `codesign`:

| Field | Catches |
|---|---|
| `TeamIdentifier` | a binary signed by a different developer |
| designated requirement | a re-signed app (`identifier "com.attacker.tool"`) |
| `CDHash` | the signed code being swapped for different bytes |
| signature validity | code modified after signing — invalid on Apple silicon |
| notarisation ticket | losing notarisation after registration |
| realpath | a symlink swap pointing elsewhere |

Identity is **re-verified on every connection**, not once at registration. A one-time check
is worthless against a binary swapped afterwards, which is the entire attack.

On mismatch the broker **contains** rather than merely refusing:

1. the request is refused;
2. **every** grant for that client is revoked, regardless of TTL;
3. a `critical` audit event records the specific reason;
4. the vault is locked, releasing key material from memory;
5. the user is notified — a silent refusal would leave a compromised client free to keep
   probing with no indication anything happened.

Steps are ordered so the important effects happen first: if locking fails, grants are
already revoked and the notification says so explicitly.

```bash
vaultbroker client detect      # what is installed, and each signature
vaultbroker client register --client cursor
vaultbroker client list
vaultbroker client verify --client cursor
vaultbroker client unregister --client cursor   # also revokes its grants
```

Verified against the harnesses installed on this machine:

```
cursor       com.todesktop.230313mzl4w4u92  VDXQ22DGB9  notarized
claude-code  com.anthropic.claude-code       Q6L2SF6YDW  (signed, not stapled)
opencode     ai.opencode.desktop             5NZ4Q7NXJ4  notarized
codex        com.openai.codex                2DC432GLL2  notarized
```

### What binding does *not* prove

Any process running as this user can still reach the socket and claim a registered client
id. Node exposes no `LOCAL_PEERCRED`, so the peer's uid cannot be checked in the kernel.
`peerCredentials()` in `src/daemon/server.ts` is the seam where that lands in v0.2, and it
returns `undefined` today — asserted by a test, so a stub claiming to verify would fail
rather than quietly satisfy. The `ps`-based parent-process check is a consistency signal,
not identity, and is labelled as such in the code.

Registration also refuses binaries whose signature does not validate, and notarisation is
compared against registration rather than required absolutely — the real Claude Code CLI is
Developer ID signed but not stapled, and a rule that blocks a legitimate harness is a rule
that eventually gets disabled.

## Policy model (v0.3)

Every request goes through `PolicyEngine.authorise`. There is no second path — no tool
handler that checks its own scope, no adapter that trusts its caller. A policy engine
with an escape hatch is not a policy engine.

**Defaults are deny.** A request is refused when any attribute is missing, unknown,
expired, mismatched, or when the evidence needed to allow it is absent. Absence of
information is a reason to refuse, never permission.

| Tier | Operations | Approval |
|---|---|---|
| `read` | `github.repo.read`, `neon.project.list`, … | grantable for hours |
| `write` | `github.pr.create`, `neon.query.execute`, … | grantable for hours |
| `deploy` | `github.release.create`, … | **fresh approval every time** |
| `delete` | `github.repo.delete`, `neon.branch.delete`, … | **fresh approval every time** |
| `billing` | `github.billing.read`, … | **fresh approval every time** |
| `admin` | `github.member.admin`, … | **fresh approval every time** |

A capability names its operations explicitly. **Wildcards are rejected at construction**,
because `'*'` is the shape every privilege-escalation bug eventually takes. Grants are
also bound to one client, one account, one project directory, and expire (TTL clamped to
1–480 minutes), with a request cap, a rate limit, and a one-time nonce so a replayed
frame cannot spend the same permission twice.

`deploy`, `delete`, `billing` and `admin` are **never** satisfied by a cached grant. They
need a `policy approve` at the moment of use, inside a two-minute window, consumed on
first redemption whether or not the request then succeeds.

```bash
vaultbroker policy grant --client cursor --service github --account work \
  --project ~/src/acme --operations github.repo.read,github.pr.create --ttl 60

vaultbroker policy approve --client cursor --service github --account work \
  --project ~/src/acme --operation github.release.create

vaultbroker policy list
vaultbroker policy revoke --client cursor
vaultbroker policy audit
vaultbroker policy verify
```

`approve` is deliberately a CLI command and **not** an MCP tool. An approval a model
could request would not be an approval.

## Audit log

Hash-linked: each record commits to the previous record's hash, so altering or removing
any historical entry invalidates every hash after it. Editing the middle of a chain is
detected, and deleting a record surfaces as a gap at the following one.

The chain is **not a signature.** Anyone who can write the file can recompute the whole
chain. What it does give you is detection of corruption, partial writes and naive edits,
and a stable anchor for the signed checkpoints that v0.2 will add.

What is never recorded, by construction rather than by convention:

- no credential values, in any encoding — every string field is passed through the
  credential redactor, so a token smuggled in as `service` or `clientId` is redacted too;
- no `Authorization` headers or cookies;
- no full request or response bodies;
- no model prompts or tool results.

`AuditEvent` is a closed field set, and free-form detail is length-capped so an entry
cannot smuggle a payload. Read commands do not append events — an earlier version rebuilt
persisted grants inside `policy list`, which meant *reading the audit log grew it*.

## Commands

```bash
vaultbroker init
vaultbroker secret list
vaultbroker secret add --service github --account work --from-file ./token
pbpaste | vaultbroker secret add --service github --account work --from-stdin
vaultbroker secret show   --service github --account work
vaultbroker secret rotate --service github --account work --from-file ./token
vaultbroker secret remove --service github --account work
```

`--value` is deliberately **not** supported. Credentials are accepted only via
`--from-file` or `--from-stdin`, because argv is visible in `ps` and persists in shell
history.

## Manual verification

Some checks cannot be automated in-tree because they involve the real Keychain and real
process state — that the KEK lands in the Keychain, that no credential appears in
`ps -A -o args=`, that the vault file is `0600`. These are written out as runnable steps
in [test/manual/vault-manual.md](test/manual/vault-manual.md).

## Development

```bash
npm install
npm run check       # typecheck + tests  ← the gate for every iteration
npm run typecheck
npm test
npm run daemon      # run the daemon in the foreground
npm run shim        # run a shim on stdio (what a harness launches)
```

TypeScript runs directly via Node 22's type stripper — there is no build step, and
`erasableSyntaxOnly` in `tsconfig.json` keeps the source compatible with that.

Two known runtime constraints, both worked around in-tree:

- Node 22's type stripper does not support `using` declarations, so disposal is tested by
  calling `[Symbol.dispose]()` directly.
- `node --test` takes no directory argument in this version; the test script passes a quoted
  glob so the shell does not expand it.

A third, worth knowing if you move the repo: `import.meta.url` percent-encodes spaces, so an
entry-point check comparing it to `process.argv[1]` by suffix silently never matches under a
path containing a space. Both entry points resolve both sides with `fileURLToPath`/`resolve`.

```bash
node bin/vaultbroker.mjs init   # creates ~/Library/Application Support/VaultBroker (0700)
VAULTBROKER_HOME=/tmp/vb npm test
```

## Layout

```
src/core/      secret.ts (the invariant), runtime-paths.ts, fsx.ts
src/cli/       thin dispatcher; handlers never touch plaintext
src/daemon/    I2 — vault owner behind a Unix domain socket
src/shim/      I2 — disposable stdio MCP server, holds no secret material
src/adapters/  I5 — allowlisted service adapters
src/install/   I4, I7 — code-signature binding and harness installers
test/          negative-first test suites
iterations/    PLAN.md (roadmap) and MASTER-PLAN.md (design)
```