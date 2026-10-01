package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"

	"with-secrets/internal/fido"
	"with-secrets/internal/store"
)

// Every command that changes the store follows read → decrypt → modify → save.
// Two commands doing that at once would silently lose whichever saved first —
// and a `set` racing a `rotate` could put the old passphrase back. So saving is
// compare-and-swap: under an exclusive lock, the file must still be byte-for-byte
// what this command read, or nothing is written. The lock is held only for that
// check and the atomic rename (milliseconds), never across prompts or touches, so
// a command left waiting at a prompt can't block anyone else.

// errStoreChanged is returned when the store on disk no longer matches what this
// command read, i.e. another ws command saved in the meantime.
var errStoreChanged = errors.New("the store changed on disk while this command ran (another ws command saved first); nothing was saved — re-run it")

// storeFile is the store as read from disk: its parsed parts, plus the raw bytes
// a later save compares against to detect a concurrent writer.
type storeFile struct {
	path    string
	raw     []byte
	h       store.Header
	idx     store.Index
	ct, aad []byte
}

// readStore loads and parses the store at the configured location.
func readStore() (*storeFile, error) {
	path, err := storePath()
	if err != nil {
		return nil, err
	}
	return readStoreAt(path)
}

func readStoreAt(path string) (*storeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no store found at %s — run `with-secrets init` first", path)
		}
		return nil, err
	}
	h, idx, ct, aad, err := store.ParseHeader(data)
	if err != nil {
		return nil, err
	}
	return &storeFile{path: path, raw: data, h: h, idx: idx, ct: ct, aad: aad}, nil
}

// save seals st under key with f's header and commits it over f. On success f
// tracks the new bytes, so a second save by the same command also passes.
func (f *storeFile) save(key []byte, st *store.Store) error {
	data, err := store.Encrypt(key, f.h, st)
	if err != nil {
		return err
	}
	if err := commitStore(f.path, f.raw, data); err != nil {
		return err
	}
	f.raw = data
	return nil
}

// lockStore takes an exclusive advisory lock on a sidecar file next to the store
// (the store itself is replaced by rename, so it can't carry the lock). The lock
// file is never deleted — removing it would let two processes lock different
// inodes. Blocks until the lock is free; holders keep it only for milliseconds.
func lockStore(path string) (release func(), err error) {
	// O_NOFOLLOW: never lock (or create) whatever a planted symlink points at.
	lf, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock store: %w", err)
	}
	fd := int(lf.Fd())
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		lf.Close()
		return nil, fmt.Errorf("lock store: %w", err)
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		lf.Close()
	}, nil
}

// commitStore atomically replaces the store at path with data, but only if the
// file still holds exactly expected. A nil expected means the store must not
// exist yet (creation). Otherwise it returns errStoreChanged and writes nothing.
func commitStore(path string, expected, data []byte) error {
	release, err := lockStore(path)
	if err != nil {
		return err
	}
	defer release()

	cur, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if expected != nil {
			return errStoreChanged
		}
	case err != nil:
		return err
	default:
		if expected == nil || !bytes.Equal(cur, expected) {
			return errStoreChanged
		}
	}
	return writeFileAtomic(path, data, 0o600)
}

// touchHMAC performs the YubiKey touch for f's credential and returns the
// hmac-secret output. The caller owns (and must Zero) it.
func touchHMAC(h store.Header) ([]byte, error) {
	cdh, err := randCDH()
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Touch your YubiKey…")
	return touchWithRetry(func() ([]byte, error) {
		return fido.HMACSecret(h.CredID, h.HMACSalt, cdh)
	}, promptReconnectKey)
}

// openStore folds hmacOut into passKey and decrypts f. The caller owns (and must
// Zero) the returned key.
func openStore(passKey, hmacOut []byte, f *storeFile) (*store.Store, []byte, error) {
	key, err := store.CombineKey(passKey, hmacOut)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Decrypt(key, f.h, f.ct, f.aad)
	if err != nil {
		store.Zero(key)
		return nil, nil, err
	}
	return st, key, nil
}

// checkStore folds hmacOut into passKey and confirms the result opens f, without
// decoding the secrets. Use it to validate the factors up front.
func checkStore(passKey, hmacOut []byte, f *storeFile) error {
	key, err := store.CombineKey(passKey, hmacOut)
	if err != nil {
		return err
	}
	defer store.Zero(key)
	return store.Check(key, f.h, f.ct, f.aad)
}

// touchDeriveDecrypt performs the YubiKey touch, folds the result into the given
// passKey, and decrypts. The caller owns (and must Zero) the returned key.
func touchDeriveDecrypt(passKey []byte, f *storeFile) (*store.Store, []byte, error) {
	hmacOut, err := touchHMAC(f.h)
	if err != nil {
		return nil, nil, err
	}
	defer store.Zero(hmacOut)
	return openStore(passKey, hmacOut, f)
}

// unlock reads the store, prompts for the passphrase, performs the YubiKey
// touch, and returns the decrypted store plus the file it came from (to save
// back through). The caller owns (and must Zero) the returned key.
func unlock() (st *store.Store, key []byte, f *storeFile, err error) {
	f, err = readStore()
	if err != nil {
		return nil, nil, nil, err
	}
	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return nil, nil, nil, err
	}
	passKey := store.DerivePassKey(pass, f.h)
	store.Zero(pass)
	defer store.Zero(passKey)

	st, key, err = touchDeriveDecrypt(passKey, f)
	if err != nil {
		return nil, nil, nil, err
	}
	return st, key, f, nil
}

// shortPassphrase is the length below which a new passphrase draws a warning.
const shortPassphrase = 12

// checkNewPassphrase validates a newly chosen passphrase against its
// confirmation. short reports whether it is below the recommended length (a
// warning, not an error).
func checkNewPassphrase(pass, confirm []byte) (short bool, err error) {
	if len(pass) == 0 {
		return false, errors.New("passphrase must not be empty")
	}
	if !bytes.Equal(pass, confirm) {
		return false, errors.New("passphrases do not match")
	}
	return len(pass) < shortPassphrase, nil
}

// promptNewPassphrase asks for a new passphrase twice and validates it. The
// caller owns (and must Zero) the result.
func promptNewPassphrase() ([]byte, error) {
	pass, err := readSecret("New passphrase: ")
	if err != nil {
		return nil, err
	}
	confirm, err := readSecret("Confirm passphrase: ")
	if err != nil {
		store.Zero(pass)
		return nil, err
	}
	defer store.Zero(confirm)
	short, err := checkNewPassphrase(pass, confirm)
	if err != nil {
		store.Zero(pass)
		return nil, err
	}
	if short {
		fmt.Fprintln(os.Stderr, "warning: short passphrase; the on-disk store is only as strong as this.")
	}
	return pass, nil
}

// errSessionRotated is returned when a session's cached passphrase key no longer
// applies because the passphrase was rotated after the session started.
var errSessionRotated = errors.New("the store's passphrase was rotated after this session started; quit and start a new session")

// sessionKey is a session's cached passphrase factor: the Argon2id output plus
// the header it was derived for, so a later rotation is reported clearly instead
// of as a generic decryption failure.
type sessionKey struct {
	passKey []byte
	kdf     store.Header
}

// check reports errSessionRotated if h no longer stretches the passphrase the
// way the session's cached key was derived.
func (sk sessionKey) check(h store.Header) error {
	if !store.SamePassKDF(sk.kdf, h) {
		return errSessionRotated
	}
	return nil
}

// verify touches and confirms the cached passphrase key opens f, without
// decoding the secrets — used to catch a mistyped passphrase up front.
func (sk sessionKey) verify(f *storeFile) error {
	if err := sk.check(f.h); err != nil {
		return err
	}
	hmacOut, err := touchHMAC(f.h)
	if err != nil {
		return err
	}
	defer store.Zero(hmacOut)
	return checkStore(sk.passKey, hmacOut, f)
}

// open touches and decrypts f with the cached passphrase key.
func (sk sessionKey) open(f *storeFile) (*store.Store, []byte, error) {
	if err := sk.check(f.h); err != nil {
		return nil, nil, err
	}
	return touchDeriveDecrypt(sk.passKey, f)
}
