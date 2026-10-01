# with-secrets

A CLI (`ws`) that stores local-development secrets encrypted at rest behind **two
required factors**: a passphrase (Argon2id) and a YubiKey FIDO2 `hmac-secret`
touch. Nothing on disk decrypts without both.

`README.md` is the authoritative spec — threat model, crypto construction,
envelope formats, and full command reference. Read it before changing behavior.
This file is the orientation for working in the code.

## Key derivation (the core invariant)

```
passKey   = Argon2id(passphrase, salt)                 # what you know
hmacOut   = YubiKey hmac-secret(credID, hmacSalt)      # what you have (touch)
masterKey = HKDF-SHA256(ikm=hmacOut, salt=passKey)     # both required
ciphertext = XChaCha20-Poly1305(masterKey, secrets-json)
```

Both factors are needed to derive `masterKey`; neither alone reveals anything.
Every write re-derives from scratch — no master key or plaintext is cached
between operations (a session caches only `passKey`, still requiring a touch per
change). Preserve this: don't add caching of the master key or plaintext, and
don't add a code path that decrypts values with only one factor.

`ws rotate` changes the passphrase: fresh Argon2id `salt` + current default
params, same `credID`/`hmacSalt` (so one touch both opens the old envelope and
seals the new one). `store.Rotate` takes the old envelope and first opens it
with the given factors (so a wrong hmac output can't seal an unopenable store),
then verifies the new envelope reopens before returning it. `ParseHeader`
range-checks Argon2id params, since they're used before the AEAD can reject a
tampered header.

## Layout

- `cmd/ws/` — CLI entry point and all command handlers (`main.go` is large: flag
  parsing, `init`/`set`/`rm`/`list`/`scopes`/`run`/`session`, TTY prompts, atomic
  writes). Subcommands split into `import.go`, `exchange.go`, `checklist.go`,
  `rotate.go`. `storefile.go` owns reading, unlocking and saving the store:
  **always save through `storeFile.save` / `commitStore`**, never
  `writeFileAtomic` on the store directly. Saving is compare-and-swap under a
  `store.wsec.lock` flock — the file must still match the bytes the command
  read — so concurrent writers (or a write racing `rotate`) can't clobber each
  other. The lock is held only around the compare + rename, never across prompts.
- `internal/store/` — on-disk encrypted envelope (`WSEC`). Header + cleartext
  name index are AEAD additional data, so tampering fails decryption. Header has
  a `version` byte for future formats. Only **values** are encrypted; scope and
  secret **names** live in a cleartext index so `list`/`scopes` need no touch.
- `internal/fido/` — cgo wrapper over `libfido2` for the `hmac-secret` extension.
  Non-resident credential (uses zero on-key slots); credID stored in the header.
- `internal/manifest/` — parses/maintains the committable `.secrets` file
  (`ENV_VAR=store-key` mappings + `# @scope NAME`). Names, never values.
- `internal/exchange/` — one-time, forward-secret secret handoff between users
  (`WSBX` blob). Ephemeral X25519 sealed-box for confidentiality + forward
  secrecy; persistent Ed25519 signature for authenticity.
- `internal/dotenv/` — minimal `.env` parser for `ws import`; keeps original
  lines verbatim so rewrites touch only imported keys.

## Scopes

Secrets are **global** or **scoped to a project**. A project's scope comes from
the nearest `.secrets` manifest (walk up from CWD). Scoped lookups fall back to
global. `-g` targets global for `set`/`rm`/`list`.

A manifest can **explicitly** inherit a parent scope with a `# @extends <ref>`
directive (`<ref>` = the parent manifest's directory, relative to the child).
`manifest.Chain` walks the nearest manifest → its `@extends` parents (cycle/
depth/missing-parent guarded); `MergedEntries` unions their entries child-first,
and `store.ResolveChain` resolves each value nearest scope → parent scopes →
global. Reads only (`run`/`get`/`list`): `set`/`rm` still target the nearest
scope. Inheritance is opt-in by design — no ancestor `.secrets` is picked up
implicitly.

## Build & test

Requires **Go 1.25+** and **libfido2** (`brew install libfido2`). cgo talks to
libfido2 directly — no third-party FIDO binding.

```sh
go test ./...
go build -o bin/ws ./cmd/ws     # or: go install ./cmd/ws
```

Every package has table-driven `_test.go` tests. Run `go test ./...` after
changes. Note: `bin/` and `*.wsec`/`*.wsx` are gitignored — never commit a real
store or exchange blob.

## Release & install

Releases are automated with [just-release](https://github.com/serialexp/just-release)
(conventional-commit driven), across two workflows:

- `release.yml` (push to `main`): runs `just-release`, which opens/updates a
  release PR bumping the version and `CHANGELOG.md`. Merging it lands a
  `release: X.Y.Z` commit.
- `publish.yml` (on the `release:` commit): the `build-macos` job builds `ws` on
  a native Apple Silicon runner (`macos-14`, libfido2 from brew), derives the
  version from the release commit, and `upload-artifact`s `ws-darwin-arm64` +
  `.sha256`. The `publish` job then runs `just-release`, which creates the
  `vX.Y.Z` Release and attaches this run's artifacts as assets (needs
  `actions: read`). cgo means each target must build on its own native runner —
  macOS arm64 is the only one wired up so far; add a job per new platform.
- The build injects the version via `-ldflags "-X main.version=v<X.Y.Z>"`;
  `ws version` prints it (`main.version` defaults to `"dev"` for local builds).
- `install.sh` downloads the release asset, verifies its checksum, and installs
  libfido2 via brew (prompting, unless `WS_ASSUME_YES=1`). The binary dynamically
  links libfido2, so that runtime dependency is mandatory.
- Asset attachment requires a just-release version with the artifact-upload
  feature (≥ the release that added `src/artifacts.ts`); older versions create
  the release but attach nothing.

## Conventions

- No backwards-compatibility shims unless asked. The envelope `version` byte is
  the intended mechanism for format evolution; bump it rather than silently
  changing layout.
- Envelope/blob formats are documented in the package doc comments of
  `store.go` and `exchange.go` — keep those comments in sync with any change.
- `TODO.md` tracks known follow-ups (e.g. `rm` leaving manifest entries, a
  `prune` command, import `.bak` cleanup). Consult it before adding a new TODO.
