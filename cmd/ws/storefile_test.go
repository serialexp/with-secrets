package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"with-secrets/internal/store"
)

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCommitStoreWritesWhenUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	writeTestFile(t, path, []byte("old"))

	if err := commitStore(path, []byte("old"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, path); string(got) != "new" {
		t.Errorf("store = %q, want %q", got, "new")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("store mode = %o, want 600", perm)
	}
}

func TestCommitStoreRefusesWhenChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	// We read "old", but another command has since saved "theirs".
	writeTestFile(t, path, []byte("theirs"))

	err := commitStore(path, []byte("old"), []byte("ours"))
	if !errors.Is(err, errStoreChanged) {
		t.Fatalf("got %v, want errStoreChanged", err)
	}
	if got := readTestFile(t, path); string(got) != "theirs" {
		t.Errorf("store was overwritten: %q", got)
	}
}

func TestCommitStoreRefusesWhenDeleted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	err := commitStore(path, []byte("old"), []byte("ours"))
	if !errors.Is(err, errStoreChanged) {
		t.Fatalf("got %v, want errStoreChanged", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("store should not have been recreated (stat err = %v)", err)
	}
}

func TestCommitStoreCreatesWhenExpectedAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	if err := commitStore(path, nil, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, path); string(got) != "fresh" {
		t.Errorf("store = %q, want %q", got, "fresh")
	}
}

func TestCommitStoreRefusesToOverwriteOnCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	writeTestFile(t, path, []byte("existing"))

	if err := commitStore(path, nil, []byte("fresh")); !errors.Is(err, errStoreChanged) {
		t.Fatalf("got %v, want errStoreChanged", err)
	}
	if got := readTestFile(t, path); string(got) != "existing" {
		t.Errorf("existing store was overwritten: %q", got)
	}
}

func TestLockStoreExcludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")

	release, err := lockStore(path)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan func(), 1)
	go func() {
		r, err := lockStore(path)
		if err != nil {
			t.Error(err)
			close(acquired)
			return
		}
		acquired <- r
	}()

	select {
	case <-acquired:
		t.Fatal("second lock acquired while the first was held")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case r, ok := <-acquired:
		if ok {
			r()
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second lock not acquired after the first was released")
	}

	info, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("lock file mode = %o, want 600", perm)
	}
}

func TestStoreFileSaveThenSaveAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	h, err := store.NewHeader(store.Params{Time: 1, Memory: 8 * 1024, Threads: 1}, []byte("cred"))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	st := store.NewStore()
	data, err := store.Encrypt(key, h, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitStore(path, nil, data); err != nil {
		t.Fatal(err)
	}

	f, err := readStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.raw, data) {
		t.Fatal("raw bytes differ from what was written")
	}

	// Two saves from the same command must both pass the unchanged check.
	st.SetGlobal("A", "1")
	if err := f.save(key, st); err != nil {
		t.Fatal(err)
	}
	st.SetGlobal("B", "2")
	if err := f.save(key, st); err != nil {
		t.Fatalf("second save by the same command: %v", err)
	}

	again, err := readStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Decrypt(key, again.h, again.ct, again.aad)
	if err != nil {
		t.Fatal(err)
	}
	if got.Global["A"] != "1" || got.Global["B"] != "2" {
		t.Errorf("saved store = %v", got.Global)
	}
}

func TestReadStoreAtMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.wsec")
	if _, err := readStoreAt(path); err == nil {
		t.Fatal("expected an error for a missing store")
	}
}

func TestCheckNewPassphrase(t *testing.T) {
	cases := []struct {
		name          string
		pass, confirm string
		wantShort     bool
		wantErr       bool
	}{
		{"empty", "", "", false, true},
		{"mismatch", "correct horse battery", "correct horse batterY", false, true},
		{"short but matching", "hunter2", "hunter2", true, false},
		{"long and matching", "correct horse battery staple", "correct horse battery staple", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			short, err := checkNewPassphrase([]byte(c.pass), []byte(c.confirm))
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err == nil && short != c.wantShort {
				t.Errorf("short = %v, want %v", short, c.wantShort)
			}
		})
	}
}

func TestSessionKeyDetectsRotation(t *testing.T) {
	h, err := store.NewHeader(store.Params{Time: 1, Memory: 8 * 1024, Threads: 1}, []byte("cred"))
	if err != nil {
		t.Fatal(err)
	}
	sk := sessionKey{kdf: h}

	written := h
	written.Nonce = bytes.Repeat([]byte{1}, len(h.Nonce))
	if err := sk.check(written); err != nil {
		t.Errorf("an ordinary write should not invalidate the session: %v", err)
	}

	rotated, err := store.NewHeader(h.Params, h.CredID)
	if err != nil {
		t.Fatal(err)
	}
	if err := sk.check(rotated); !errors.Is(err, errSessionRotated) {
		t.Errorf("got %v, want errSessionRotated", err)
	}
}

func TestCommitStoreConcurrentWritersOneWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.wsec")
	writeTestFile(t, path, []byte("base"))

	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			errs <- commitStore(path, []byte("base"), []byte{byte('a' + i)})
		}(i)
	}
	wins := 0
	for i := 0; i < n; i++ {
		err := <-errs
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, errStoreChanged):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d writers won, want exactly 1", wins)
	}
	if got := readTestFile(t, path); len(got) != 1 {
		t.Errorf("store = %q, want a single winner's bytes", got)
	}
}

func TestCommitStoreMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone", "store.wsec")
	if err := commitStore(path, nil, []byte("x")); err == nil {
		t.Fatal("expected an error when the store directory is missing")
	}
}

func TestLockStoreRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.wsec")
	target := filepath.Join(dir, "elsewhere")
	writeTestFile(t, target, []byte("not a lock"))
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if release, err := lockStore(path); err == nil {
		release()
		t.Fatal("lockStore followed a symlinked lock file")
	}
}

// rotationFixture writes a real envelope (cheap Argon2 params, fake hmac output
// standing in for the touch) and returns what a set and a rotate each need.
func rotationFixture(t *testing.T) (path string, passKey, hmacOut, key []byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "store.wsec")
	h, err := store.NewHeader(store.Params{Time: 1, Memory: 8 * 1024, Threads: 1}, []byte("cred"))
	if err != nil {
		t.Fatal(err)
	}
	hmacOut = bytes.Repeat([]byte{9}, 32)
	passKey = store.DerivePassKey([]byte("old"), h)
	key, err = store.CombineKey(passKey, hmacOut)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Encrypt(key, h, store.NewStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := commitStore(path, nil, data); err != nil {
		t.Fatal(err)
	}
	return path, passKey, hmacOut, key
}

// A `set` that read the store before a `rotate` saved must not write its
// old-passphrase envelope back over the rotated one.
func TestSetRacingRotateCannotRevertIt(t *testing.T) {
	path, passKey, hmacOut, key := rotationFixture(t)

	setView, err := readStoreAt(path) // `ws set` reads…
	if err != nil {
		t.Fatal(err)
	}
	rotView, err := readStoreAt(path) // …and so does `ws rotate`.
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := store.Rotate(rotView.raw, passKey, hmacOut, []byte("new"), rotView.h.Params)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitStore(path, rotView.raw, rotated); err != nil {
		t.Fatal(err)
	}

	st := store.NewStore()
	st.SetGlobal("LATE", "value")
	if err := setView.save(key, st); !errors.Is(err, errStoreChanged) {
		t.Fatalf("set after rotate: got %v, want errStoreChanged", err)
	}
	if got := readTestFile(t, path); !bytes.Equal(got, rotated) {
		t.Error("the rotated store was overwritten")
	}
}

// And the other order: a rotate that read the store before a `set` saved must
// not drop that set's change.
func TestRotateRacingSetCannotDropIt(t *testing.T) {
	path, passKey, hmacOut, key := rotationFixture(t)

	rotView, err := readStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}
	setView, err := readStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}

	st := store.NewStore()
	st.SetGlobal("EARLY", "value")
	if err := setView.save(key, st); err != nil {
		t.Fatal(err)
	}
	saved := readTestFile(t, path)

	rotated, err := store.Rotate(rotView.raw, passKey, hmacOut, []byte("new"), rotView.h.Params)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitStore(path, rotView.raw, rotated); !errors.Is(err, errStoreChanged) {
		t.Fatalf("rotate after set: got %v, want errStoreChanged", err)
	}
	if got := readTestFile(t, path); !bytes.Equal(got, saved) {
		t.Error("the set's change was overwritten")
	}
}

func TestRefuseSamePassphrase(t *testing.T) {
	h, err := store.NewHeader(store.Params{Time: 1, Memory: 8 * 1024, Threads: 1}, []byte("cred"))
	if err != nil {
		t.Fatal(err)
	}
	current := store.DerivePassKey([]byte("summer-2026"), h)
	if err := refuseSamePassphrase([]byte("summer-2026"), current, h); !errors.Is(err, errSamePassphrase) {
		t.Errorf("same passphrase: got %v, want errSamePassphrase", err)
	}
	if err := refuseSamePassphrase([]byte("autumn-2026"), current, h); err != nil {
		t.Errorf("different passphrase: %v", err)
	}
}
