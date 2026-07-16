# with-secrets — follow-ups

- **`rm` leaves the manifest mapping.** `set` auto-appends the `NAME` entry to
  `.secrets`, but `rm` only deletes the stored value; the `.secrets` line stays,
  so a later `run` reports the secret as missing. Decide whether `rm` should
  offer to drop the manifest entry too.
- **`prune` command.** No way to clean up orphan scopes (a `.secrets` deleted
  from disk leaves its bucket in the store). Add `ws prune`.
- **PATH install.** Decide on `~/.local/bin` symlink vs `go install ./cmd/ws` vs
  a brew formula so `ws` is on PATH.
- **Import `.bak` cleanup.** `ws import` leaves `.env.bak` files (plaintext) as a
  safety net. Consider a `--shred-backups` flag or a follow-up prompt to remove
  them once the store is verified.
- **Exchange: manage pending keys.** Add `ws request --list` (show open exchanges
  + time left) and a way to cancel one, beyond the automatic 15-minute GC.
