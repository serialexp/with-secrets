package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"with-secrets/internal/store"
)

// cmdRotate changes the store's passphrase. It needs the current passphrase and
// one YubiKey touch: the touch's hmac-secret output both opens the store and
// (unchanged, since the credential and hmac salt are kept) seals the new
// envelope, which gets a fresh Argon2id salt and the current default params.
// The new envelope is verified to reopen before it replaces the old one, and it
// is only written if no other ws command saved in the meantime.
//
// Only the live store changes: backups or copies of the old file still open
// with the old passphrase (and the YubiKey).
func cmdRotate(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: with-secrets rotate")
	}

	f, err := readStore()
	if err != nil {
		return err
	}

	current, err := readSecret("Current passphrase: ")
	if err != nil {
		return err
	}
	passKey := store.DerivePassKey(current, f.h)
	store.Zero(current)
	defer store.Zero(passKey)

	hmacOut, err := touchHMAC(f.h)
	if err != nil {
		return err
	}
	defer store.Zero(hmacOut)

	// Catch a mistyped current passphrase before asking for the new one.
	if err := checkStore(passKey, hmacOut, f); err != nil {
		return err
	}

	next, err := promptNewPassphrase()
	if err != nil {
		return err
	}
	defer store.Zero(next)
	if err := refuseSamePassphrase(next, passKey, f.h); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Re-encrypting…")
	data, err := store.Rotate(f.raw, passKey, hmacOut, next, store.DefaultParams())
	if err != nil {
		return err
	}
	if err := commitStore(f.path, f.raw, data); err != nil {
		return err
	}
	fmt.Println("Passphrase changed. Any open `ws session` must be restarted.")
	return nil
}

// errSamePassphrase is returned when the new passphrase equals the current one.
var errSamePassphrase = errors.New("the new passphrase is the same as the current one; nothing changed")

// refuseSamePassphrase compares next against the current passphrase by
// stretching it under the current header and comparing with the current
// passKey, so the current passphrase itself needn't be kept in memory.
func refuseSamePassphrase(next, currentPassKey []byte, h store.Header) error {
	k := store.DerivePassKey(next, h)
	defer store.Zero(k)
	if subtle.ConstantTimeCompare(k, currentPassKey) == 1 {
		return errSamePassphrase
	}
	return nil
}
