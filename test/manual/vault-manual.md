# Manual verification — iteration I1 (vault core)

These are the checks that cannot be automated in-tree, because they involve the real
macOS Keychain and real process state. Run them by hand after `npm run check`.

## Setup

```bash
export VAULTBROKER_HOME=$(mktemp -d)
node bin/vaultbroker.mjs init
printf 'ghp_realistic_token_ABC123' > /tmp/vb-token.txt
```

## 1. Full command lifecycle

```bash
node bin/vaultbroker.mjs secret add --service github --account work --from-file /tmp/vb-token.txt
node bin/vaultbroker.mjs secret add --service neon --account proj-alpha --from-file /tmp/vb-token.txt --type bearer
node bin/vaultbroker.mjs secret list
node bin/vaultbroker.mjs secret show --service github --account work
```

Expect: two stored credentials, an aligned table, and JSON metadata containing no token.

## 2. Nothing readable leaked to disk

```bash
grep -c 'ghp_realistic_token_ABC123' "$VAULTBROKER_HOME/vault.json"   # expect 0
grep -c 'github' "$VAULTBROKER_HOME/vault.json"                       # expect 0
grep -rc 'ghp_realistic_token_ABC123' "$VAULTBROKER_HOME/backups/"    # expect 0 everywhere
stat -f '%Sp %N' "$VAULTBROKER_HOME/vault.json" "$VAULTBROKER_HOME/backups/"*
```

Expect: `0`, `0`, all zeros, and `-rw-------` on every file. Service and account names are
inside the ciphertext; only HMAC blind indexes are in the clear.

## 3. The keychain holds the KEK, hex-encoded — not the credential

```bash
/usr/bin/security find-generic-password -s vaultbroker:kek -a vault:v1 -w
```

Expect 64 hex characters. It must **not** be the GitHub token. Anyone reading this item
gets the key-encryption key, not any stored credential.

## 4. No credential in the process table

```bash
ps -A -o args= | grep -c 'ghp_realistic_token_ABC123'
```

Expect `0`. Note that a bare `grep` can match its own command line; use a distinctive
canary and read the result with that caveat in mind. The point is that
`vaultbroker secret add` never places the credential in argv or in an exported
environment variable.

## 5. `--value` is refused

```bash
node bin/vaultbroker.mjs secret add --service x --account y --value LEAKED
```

Expect a refusal explaining that argv is visible in `ps` and shell history. The flag is
rejected rather than supported, because a flag that exists will eventually be used.

## 6. Rotation and removal

```bash
printf 'rotated_value_XYZ789' > /tmp/vb-token2.txt
node bin/vaultbroker.mjs secret rotate --service github --account work --from-file /tmp/vb-token2.txt
grep -c 'ghp_realistic_token_ABC123' "$VAULTBROKER_HOME/vault.json"   # still 0
node bin/vaultbroker.mjs secret remove --service github --account work
node bin/vaultbroker.mjs secret list
```

## 7. Tamper detection

```bash
node bin/vaultbroker.mjs secret add --service github --account work --from-file /tmp/vb-token.txt
python3 - <<'PY'
import json, os, base64
p = os.path.join(os.environ['VAULTBROKER_HOME'], 'vault.json')
d = json.load(open(p))
raw = bytearray(base64.b64decode(d['records'][0]['aead']['ciphertext']))
raw[0] ^= 0x01
d['records'][0]['aead']['ciphertext'] = base64.b64encode(bytes(raw)).decode()
json.dump(d, open(p, 'w'))
PY
node bin/vaultbroker.mjs secret list
```

Expect a loud failure naming an authentication problem. It must not print a plausible
credential or silently show an empty vault — a vault that cannot be authenticated is a
vault that must be treated as compromised.

## Cleanup

```bash
rm -rf "$VAULTBROKER_HOME"
/usr/bin/security delete-generic-password -s vaultbroker:kek -a vault:v1
rm -f /tmp/vb-token.txt /tmp/vb-token2.txt
```