# with-secrets

Local development secrets, encrypted at rest behind **two required factors**:

1. **What you know** — a passphrase, stretched with Argon2id.
2. **What you have** — a YubiKey FIDO2 `hmac-secret` touch.

Nothing on disk is decryptable until you type the passphrase *and* touch the key.
A dormant or automated compromise sees only ciphertext; a leaked passphrase is
useless without the physical key present and pressed.

## How it works

```
passKey   = Argon2id(passphrase, salt)                 # what you know
hmacOut   = YubiKey hmac-secret(credID, hmacSalt)      # what you have (touch)
masterKey = HKDF-SHA256(ikm = hmacOut, salt = passKey) # both required
ciphertext = XChaCha20-Poly1305(masterKey, secrets-json)
```

The store is a single encrypted file. Its header (Argon2 params, salt,
credential id, hmac salt, nonce) is authenticated as AEAD additional data, so it
can't be altered without failing decryption. The header carries a `version` byte
so a future hardware-only or multi-recipient format can be added without
migrating existing stores.

The FIDO2 credential is **non-resident**: the key stores nothing, using zero
on-key slots and leaving your passkey list untouched. The credential id (not
secret) lives in the store header.

## Threat model

Defends against: stolen disk/backup, offline brute force (Argon2id + a real
passphrase), and automated/remote malware that lacks the physical key.

Does **not** defend against: an attacker already running as you who is actively
listening at the moment you type the passphrase and touch the key. No local
software scheme does once code executes as you.

Secret and scope **names** are stored in cleartext (only values are encrypted),
so anyone with the store file can enumerate them. This is deliberate — it lets
`list`/`scopes` work without a touch — and leaks nothing beyond what the
committed `.secrets` manifests already show.

## Usage

```sh
ws init                 # create the store (passphrase + 2 touches)
ws set  AWS_SECRET      # store a secret in the current project scope
ws -g set GITHUB_TOKEN  # store a global secret
ws list                 # list current scope + global names (no touch; alias: ls)
ws -g list              # list global names only (no touch)
ws scopes               # list all scope names (no touch)
ws rm   AWS_SECRET      # remove a secret from the current scope
ws -g rm GITHUB_TOKEN   # remove a global secret
ws request              # mint a one-time key to receive secrets from a coworker
ws send --to TOKEN      # encrypt this repo's secrets to a coworker's token
ws receive blob.wsx     # decrypt a received blob into your own store
ws session              # unlock once, then set/rm/list many
ws run -- pnpm run dev  # inject the nearest .secrets, then run the command
ws pnpm run dev         # shorthand for the above
```

The binary is `ws`; the module and project are named `with-secrets`.

### Listing without decryption

`list` and `scopes` read a **cleartext name index** stored in the envelope, so
they need no passphrase or touch — only secret *values* are encrypted. Listing
inside a scope shows that scope's names plus the global names that still apply
there (a global name shadowed by a scoped one of the same name is omitted, since
the scoped value wins). The index is authenticated alongside the header, so it
can't be silently altered without failing the next decrypt.

### Scopes

Secrets are either **global** or **scoped to a project**. A project's scope is
declared in its `.secrets` manifest; walking up from the working directory finds
the nearest one. A scoped lookup falls back to global, so shared secrets live in
one place while project-specific ones stay tied to the project.

`set NAME` (no `-g`) stores under the current scope. If no `.secrets` exists in
the working directory or any parent, it offers — **before** asking for the
passphrase or a touch — to create one, prompting for a scope name (default: the
directory name). On success it also records the `NAME` → store-key mapping in
that `.secrets`, so the very next `with-secrets run` already knows to inject it.

`-g` targets global for `set`, `rm`, and `list`.

### Importing from `.env`

`ws import [DIR]` migrates existing plaintext `.env` files into the store:

1. Recursively finds `.env` / `.env.*` files under `DIR` (default CWD), skipping
   `node_modules`, `.git`, `vendor`, template files (`*.example`, `*.sample`, …),
   and its own `.bak` backups.
2. If the results span several files/directories it warns first — they'll all land
   in one scope, so you may prefer running `ws import` inside each project.
3. Shows an interactive checklist of every variable (secret-looking ones
   pre-checked). Toggle with space, `a` for all, Enter to confirm, `q` to cancel.
4. Imports the selected values into the current scope (creating a `.secrets` if
   needed) with one passphrase + one touch, and records the env-var mappings.
5. Rewrites each `.env` with the imported lines removed (other lines kept
   verbatim), writing a `.env.bak` first and offering to delete a now-empty file.

> The `.env.bak` backups still contain the plaintext secrets. `ws` prints their
> paths and leaves them in place as a brief safety net — delete them once you've
> confirmed the store works.

### Handing secrets to a coworker

When a coworker needs a repo's secrets, `ws` moves them across an insecure
channel (Slack, email) without either party ever handling a plaintext file, and
with **forward secrecy**: the exchange keypair is thrown away after a single use,
so a blob that leaks later can't be opened by anyone — not even the recipient.

```
# Receiver, on their machine:
ws request
#  -> prints a one-time token (wsx1-…) and a fingerprint like ABLE-QK
#     (valid 15 minutes)

# Sender, in the repo whose .secrets they want to share:
ws send --to wsx1-…
#  -> shows the token's fingerprint (confirm it matches what the receiver reads
#     aloud) and prints your own sender fingerprint, then writes <scope>.wsx

# Receiver, in the target repo:
ws receive <scope>.wsx
#  -> shows the sender's fingerprint (confirm it's really them), then lands the
#     secrets into their own store and destroys the one-time key
```

How it works and why it's safe:

- **Two throwaway keys (confidentiality + forward secrecy).** The sender encrypts
  with a fresh ephemeral key per blob (standard sealed-box); the *receiver's* key
  is also one-time — `ws request` mints it, `ws receive` uses it once and deletes
  it. Once the exchange is done the private key is gone, so the blob is
  permanently undecryptable.
- **15-minute window.** A pending key expires 15 minutes after `ws request`
  (you're meant to be doing this together). `receive` refuses an expired key.
- **Receiver fingerprint check.** The token is the receiver's public key; both
  sides derive the same short fingerprint from it. Comparing it aloud ("does yours
  start with ABLE?") catches a *token* swapped in transit — an attacker who
  substitutes their own token would otherwise get the secrets encrypted to them.
- **Sender signature (authenticity + non-repudiation).** Each blob is signed with
  the sender's *persistent* Ed25519 identity (generated at `ws init`, stored
  encrypted). `receive` verifies the signature and shows the sender's fingerprint
  for the receiver to confirm — because anyone who sees the public token can craft
  a blob to it, this reverse-direction check is what proves the blob really came
  from your coworker and not an impostor on the channel who poisoned the values.
  The signing key is persistent but confidentiality doesn't depend on it: it
  can't decrypt anything, so forward secrecy is unaffected.
- **`send` shares the repo's full `.secrets` set.** Secrets that only resolve via
  the global fallback are offered in a checklist (opt-in); local ones are always
  included. The `.secrets` name→store-key mappings ride along, so the receiver's
  `ws run` works immediately.
- **`receive` lands secrets in the receiver's own two-factor store** (one
  passphrase + one touch). Local-origin secrets go to the current scope
  (creating a `.secrets` if needed); global-origin ones go to their global bucket
  after a checklist. If an incoming name collides with one they already have, a
  checklist lets them pick which to overwrite, showing `abc…z`-style previews of
  each value so they can tell them apart.

Both parties need an initialized store (`ws init`). Only `ws request` works
without one — it's just a key, not a secret.

> During the 15-minute window the receiver's throwaway **private** key sits on
> their disk (mode 0600) so `receive` can find it. That's the one exposure: an
> attacker who reads that file *and* intercepts the blob within the window could
> open it. It's a deliberate trade for a zero-setup receiver, kept small by the
> short window and the key's destruction on first `receive`. Run `ws request`
> only when you're about to do the handoff, not ahead of time.

### Sessions

Setting many secrets one-by-one means re-typing the passphrase each time. A
session caches only the passphrase-derived key in memory for the life of the
process; the passphrase is entered once, but **every change still requires a
YubiKey touch**:

```
$ ws session
Passphrase: ********************
Unlocking…
Unlocked. Passphrase cached until you exit; each change needs a touch.
Commands: set NAME | rm NAME | list | help | quit  (Ctrl-D to exit)
ws> set AWS_SECRET
Value for AWS_SECRET: ******            # touch YubiKey
Stored AWS_SECRET
ws> quit
```

No master key or plaintext is held between commands — each operation
re-derives from the cached passphrase key plus a fresh touch, so the only thing
lingering in memory is one of the two factors, useless on its own. The cache
dies when the process exits; there is no background daemon or socket.

### The `.secrets` manifest

A per-project file naming which secrets to inject and which scope they belong to.
It names secrets, never values, so it's safe to commit.

```
# .secrets
# @scope acme-api                       # scope name (defaults to the file's dir)
AWS_SECRET_ACCESS_KEY=aws/prod/secret   # ENV_VAR=store-key
DATABASE_URL                            # shorthand: env var == store key
```

`ws run` walks up for the nearest `.secrets`, reads its scope, and resolves each
entry against that scope with global fallback.

Store location: `$WITH_SECRETS_STORE`, else
`$XDG_DATA_HOME/with-secrets/store.wsec` (default `~/.local/share/...`), mode 0600.

## Build

Requires Go 1.25+ and `libfido2` (`brew install libfido2`). cgo is used to talk
to the audited libfido2 directly — no third-party FIDO binding.

```sh
go test ./...
go build -o bin/ws ./cmd/ws     # or: go install ./cmd/ws
```
