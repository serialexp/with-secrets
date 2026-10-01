package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"testing"
)

// testHeader builds a header with random salts and a fake credential id, and a
// fake hmac-secret output standing in for the YubiKey (so tests need no
// hardware). Returns the header and the derived key for the given passphrase.
func testHeader(t *testing.T, passphrase string) (Header, []byte, []byte) {
	t.Helper()
	// Cheap Argon2 params keep the test fast.
	params := Params{Time: 1, Memory: 8 * 1024, Threads: 1}
	credID := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, credID); err != nil {
		t.Fatal(err)
	}
	h, err := NewHeader(params, credID)
	if err != nil {
		t.Fatal(err)
	}
	hmacOut := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, hmacOut); err != nil {
		t.Fatal(err)
	}
	key, err := DeriveKey([]byte(passphrase), hmacOut, h)
	if err != nil {
		t.Fatal(err)
	}
	return h, key, hmacOut
}

func sampleStore() *Store {
	s := NewStore()
	s.SetGlobal("GITHUB_TOKEN", "ghtok")
	s.Set("acme", "DATABASE_URL", "postgres://acme")
	s.Set("beta", "DATABASE_URL", "postgres://beta")
	return s
}

func TestRoundTrip(t *testing.T) {
	h, key, _ := testHeader(t, "correct horse battery staple")
	in := sampleStore()

	data, err := Encrypt(key, h, in)
	if err != nil {
		t.Fatal(err)
	}
	h2, idx, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	// The cleartext index must describe the structure without decryption.
	if len(idx.Global) != 1 || idx.Global[0] != "GITHUB_TOKEN" {
		t.Errorf("index.Global = %v, want [GITHUB_TOKEN]", idx.Global)
	}
	if got := idx.Scopes["acme"]; len(got) != 1 || got[0] != "DATABASE_URL" {
		t.Errorf("index.Scopes[acme] = %v, want [DATABASE_URL]", got)
	}
	if _, ok := idx.Scopes["beta"]; !ok {
		t.Errorf("index missing scope beta: %v", idx.Scopes)
	}

	got, err := Decrypt(key, h2, ct, aad)
	if err != nil {
		t.Fatal(err)
	}

	if v, _ := got.Resolve("acme", "DATABASE_URL"); v != "postgres://acme" {
		t.Errorf("acme DATABASE_URL = %q", v)
	}
	if v, _ := got.Resolve("beta", "DATABASE_URL"); v != "postgres://beta" {
		t.Errorf("beta DATABASE_URL = %q", v)
	}
	// Global fallback: a scope that lacks the key sees the global value.
	if v, ok := got.Resolve("acme", "GITHUB_TOKEN"); !ok || v != "ghtok" {
		t.Errorf("fallback GITHUB_TOKEN = %q ok=%v", v, ok)
	}
}

func TestEnsureIdentity(t *testing.T) {
	s := NewStore()
	if _, ok := s.Identity(); ok {
		t.Fatal("fresh store should have no identity")
	}
	created, err := s.EnsureIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first EnsureIdentity should report created")
	}
	priv, ok := s.Identity()
	if !ok || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("Identity after EnsureIdentity: ok=%v len=%d", ok, len(priv))
	}
	// Idempotent: a second call keeps the same key and reports not-created.
	first := append([]byte(nil), s.SenderPriv...)
	created2, err := s.EnsureIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Error("second EnsureIdentity should report not created")
	}
	if !bytes.Equal(first, s.SenderPriv) {
		t.Error("EnsureIdentity must not replace an existing key")
	}
}

func TestIdentitySurvivesRoundTrip(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	in := sampleStore()
	if _, err := in.EnsureIdentity(); err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt(key, h, in)
	if err != nil {
		t.Fatal(err)
	}
	h2, idx, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	// The signing key is encrypted payload, never the cleartext name index.
	for _, n := range idx.Global {
		if n == "sender_priv" || n == "SenderPriv" {
			t.Fatal("identity leaked into cleartext index")
		}
	}
	got, err := Decrypt(key, h2, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.SenderPriv, in.SenderPriv) {
		t.Fatal("identity not preserved across encrypt/decrypt")
	}
}

func TestResolveFallbackAndMiss(t *testing.T) {
	s := sampleStore()
	if _, ok := s.Resolve("nonexistent-scope", "GITHUB_TOKEN"); !ok {
		t.Error("expected global fallback for unknown scope")
	}
	if _, ok := s.Resolve("acme", "NOPE"); ok {
		t.Error("expected miss for unknown key")
	}
	// A scoped key must not leak into another scope (no cross-scope fallback).
	if v, _ := s.Resolve("beta", "DATABASE_URL"); v == "postgres://acme" {
		t.Error("beta must not see acme's scoped value")
	}
}

func TestResolveChain(t *testing.T) {
	s := NewStore()
	s.SetGlobal("SHARED", "global-val")
	s.SetGlobal("ONLY_GLOBAL", "g")
	s.Set("parent", "SHARED", "parent-val")
	s.Set("parent", "FROM_PARENT", "p")
	s.Set("kid", "SHARED", "kid-val")

	// Most specific wins: kid > parent > global.
	if v, ok := s.ResolveChain([]string{"kid", "parent"}, "SHARED"); !ok || v != "kid-val" {
		t.Errorf("SHARED = %q,%v; want kid-val", v, ok)
	}
	// Falls through to the parent scope when the nearest lacks it.
	if v, ok := s.ResolveChain([]string{"kid", "parent"}, "FROM_PARENT"); !ok || v != "p" {
		t.Errorf("FROM_PARENT = %q,%v; want p", v, ok)
	}
	// Falls through the whole chain to global.
	if v, ok := s.ResolveChain([]string{"kid", "parent"}, "ONLY_GLOBAL"); !ok || v != "g" {
		t.Errorf("ONLY_GLOBAL = %q,%v; want g", v, ok)
	}
	// Total miss.
	if _, ok := s.ResolveChain([]string{"kid", "parent"}, "NOPE"); ok {
		t.Error("expected miss for unknown key")
	}
	// Empty scopes are skipped; resolves against global only.
	if v, ok := s.ResolveChain([]string{""}, "SHARED"); !ok || v != "global-val" {
		t.Errorf("empty-scope SHARED = %q,%v; want global-val", v, ok)
	}
	// A parent-only scope order does not see kid's value.
	if v, ok := s.ResolveChain([]string{"parent"}, "SHARED"); !ok || v != "parent-val" {
		t.Errorf("parent-only SHARED = %q,%v; want parent-val", v, ok)
	}
}

func TestRemovePrunesEmptyScope(t *testing.T) {
	s := NewStore()
	s.Set("solo", "ONLY", "x")
	if !s.Remove("solo", "ONLY") {
		t.Fatal("expected Remove to report existence")
	}
	if _, ok := s.Scopes["solo"]; ok {
		t.Error("empty scope should be pruned after removing its last key")
	}
	if s.Remove("solo", "ONLY") {
		t.Error("second Remove should report non-existence")
	}
}

func TestHeaderRoundTripPreservesFields(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	h2, _, _, _, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if h2.Params != h.Params {
		t.Errorf("params = %+v, want %+v", h2.Params, h.Params)
	}
	if !bytes.Equal(h2.Salt, h.Salt) {
		t.Error("salt not preserved")
	}
	if !bytes.Equal(h2.CredID, h.CredID) {
		t.Error("credID not preserved")
	}
	if !bytes.Equal(h2.HMACSalt, h.HMACSalt) {
		t.Error("hmacSalt not preserved")
	}
	if bytes.Equal(h2.Nonce, make([]byte, nonceLen)) {
		t.Error("nonce should be non-zero after Encrypt")
	}
}

func TestNonceChangesPerEncrypt(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	d1, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d1, d2) {
		t.Error("two encryptions produced identical output; nonce not randomised")
	}
}

func TestTamperCiphertextFails(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xFF
	h2, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(key, h2, ct, aad); err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}

func TestTamperHeaderFails(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	// Last byte of the Argon2 Time param: 1 -> 3, still in range, so only the
	// AEAD (header as additional data) can catch it.
	data[8] ^= 0x02
	h2, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(key, h2, ct, aad); err == nil {
		t.Fatal("expected decryption to fail on tampered header (AAD)")
	}
}

func TestTamperIndexFails(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the cleartext index (a scope/name character). The index
	// is authenticated as AAD, so decryption must fail.
	i := bytes.IndexByte(data, 'G') // 'G' from "GITHUB_TOKEN" in the JSON index
	if i < 0 {
		t.Fatal("could not locate index bytes to tamper")
	}
	data[i] ^= 0xFF
	h2, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(key, h2, ct, aad); err == nil {
		t.Fatal("expected decryption to fail on tampered index (AAD)")
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	h, key, hmacOut := testHeader(t, "right")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	h2, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := DeriveKey([]byte("wrong"), hmacOut, h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(wrongKey, h2, ct, aad); err == nil {
		t.Fatal("expected decryption to fail with wrong passphrase")
	}
}

func TestWrongHMACFails(t *testing.T) {
	h, key, _ := testHeader(t, "pw")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	h2, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	otherHMAC := make([]byte, 32)
	otherHMAC[0] = 1
	wrongKey, err := DeriveKey([]byte("pw"), otherHMAC, h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(wrongKey, h2, ct, aad); err == nil {
		t.Fatal("expected decryption to fail with wrong hmac-secret output")
	}
}

func TestDeriveKeySplitMatches(t *testing.T) {
	params := Params{Time: 1, Memory: 8 * 1024, Threads: 1}
	h, err := NewHeader(params, []byte("cred"))
	if err != nil {
		t.Fatal(err)
	}
	hmacOut := make([]byte, 32)
	hmacOut[3] = 9

	whole, err := DeriveKey([]byte("pw"), hmacOut, h)
	if err != nil {
		t.Fatal(err)
	}
	passKey := DerivePassKey([]byte("pw"), h)
	split, err := CombineKey(passKey, hmacOut)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, split) {
		t.Error("DeriveKey and CombineKey(DerivePassKey(...)) disagree")
	}
}

func TestParseErrors(t *testing.T) {
	if _, _, _, _, err := ParseHeader([]byte("XXXX....")); err != ErrBadMagic {
		t.Errorf("bad magic: got %v, want ErrBadMagic", err)
	}
	if _, _, _, _, err := ParseHeader([]byte("WS")); err != ErrTruncated {
		t.Errorf("short: got %v, want ErrTruncated", err)
	}
	bad := append(append([]byte{}, magic[:]...), 0xFF) // unsupported version
	if _, _, _, _, err := ParseHeader(bad); !errors.Is(err, ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

// rotateFixture seals a sample store (with a signing identity) under oldPass and
// returns the envelope, the old passphrase key, the fake hmac-secret output
// standing in for the touch, and the plaintext store for comparison.
func rotateFixture(t *testing.T, oldPass string) (data, oldPassKey, hmacOut []byte, want *Store) {
	t.Helper()
	h, key, hmacOut := testHeader(t, oldPass)
	want = sampleStore()
	if _, err := want.EnsureIdentity(); err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt(key, h, want)
	if err != nil {
		t.Fatal(err)
	}
	return data, DerivePassKey([]byte(oldPass), h), hmacOut, want
}

// openWith parses an envelope and decrypts it with the given passphrase and
// hmac-secret output.
func openWith(t *testing.T, data []byte, pass string, hmacOut []byte) (*Store, error) {
	t.Helper()
	h, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveKey([]byte(pass), hmacOut, h)
	if err != nil {
		t.Fatal(err)
	}
	return Decrypt(key, h, ct, aad)
}

var rotateParams = Params{Time: 1, Memory: 8 * 1024, Threads: 1}

func TestRotateNewPassphraseOpensWithSameContents(t *testing.T) {
	data, oldPassKey, hmacOut, want := rotateFixture(t, "old passphrase")

	rotated, err := Rotate(data, oldPassKey, hmacOut, []byte("new passphrase"), rotateParams)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openWith(t, rotated, "new passphrase", hmacOut)
	if err != nil {
		t.Fatalf("new passphrase should open the rotated store: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("contents changed across rotation:\n got  %+v\n want %+v", got, want)
	}

	_, oldIdx, _, _, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	_, newIdx, _, _, err := ParseHeader(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldIdx, newIdx) {
		t.Errorf("name index changed: %+v -> %+v", oldIdx, newIdx)
	}
}

func TestRotateOldPassphraseNoLongerOpens(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")
	rotated, err := Rotate(data, oldPassKey, hmacOut, []byte("new passphrase"), rotateParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWith(t, rotated, "old passphrase", hmacOut); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("old passphrase: got %v, want ErrDecrypt", err)
	}
}

func TestRotateStillNeedsTheYubiKey(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")
	rotated, err := Rotate(data, oldPassKey, hmacOut, []byte("new passphrase"), rotateParams)
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Clone(hmacOut)
	other[0] ^= 0xFF
	if _, err := openWith(t, rotated, "new passphrase", other); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("new passphrase with wrong hmac output: got %v, want ErrDecrypt", err)
	}
}

// Rotate must prove the factors it was handed open the current envelope before
// sealing a new one: a wrong (or zeroed) hmac output would otherwise produce a
// store no YubiKey can ever open again.
func TestRotateRefusesFactorsThatDoNotOpenTheOldStore(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")

	wrongHMAC := make([]byte, len(hmacOut)) // e.g. zeroed by a refactor
	if _, err := Rotate(data, oldPassKey, wrongHMAC, []byte("new passphrase"), rotateParams); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong hmac output: got %v, want ErrDecrypt", err)
	}

	wrongPassKey := bytes.Clone(oldPassKey)
	wrongPassKey[0] ^= 0xFF
	if _, err := Rotate(data, wrongPassKey, hmacOut, []byte("new passphrase"), rotateParams); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong passphrase key: got %v, want ErrDecrypt", err)
	}
}

func TestRotateKeepsHardwareFactorAndRefreshesSalt(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")
	oh, _, _, _, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	params := Params{Time: 2, Memory: 16 * 1024, Threads: 2}

	rotated, err := Rotate(data, oldPassKey, hmacOut, []byte("new passphrase"), params)
	if err != nil {
		t.Fatal(err)
	}
	nh, _, _, _, err := ParseHeader(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nh.CredID, oh.CredID) {
		t.Error("credential id changed; the same YubiKey credential must keep working")
	}
	if !bytes.Equal(nh.HMACSalt, oh.HMACSalt) {
		t.Error("hmac salt changed; a password rotation must not change the touch")
	}
	if bytes.Equal(nh.Salt, oh.Salt) {
		t.Error("Argon2id salt was reused; rotation must pick a fresh one")
	}
	if bytes.Equal(nh.Nonce, oh.Nonce) {
		t.Error("nonce was reused")
	}
	if nh.Params != params {
		t.Errorf("params = %+v, want %+v", nh.Params, params)
	}
}

func TestRotateDoesNotMutateInput(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")
	orig := bytes.Clone(data)
	if _, err := Rotate(data, oldPassKey, hmacOut, []byte("new passphrase"), rotateParams); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, orig) {
		t.Error("Rotate mutated the old envelope")
	}
}

func TestRotateRejectsEmptyPassphrase(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")
	if _, err := Rotate(data, oldPassKey, hmacOut, nil, rotateParams); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("got %v, want ErrEmptyPassphrase", err)
	}
}

func TestSamePassKDF(t *testing.T) {
	data, oldPassKey, hmacOut, _ := rotateFixture(t, "old passphrase")
	h, _, _, _, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}

	// A normal write only changes the nonce: the cached passKey still applies.
	same := h
	same.Nonce = make([]byte, len(h.Nonce))
	if !SamePassKDF(h, same) {
		t.Error("headers differing only by nonce should share a passphrase KDF")
	}

	rotated, err := Rotate(data, oldPassKey, hmacOut, []byte("new passphrase"), h.Params)
	if err != nil {
		t.Fatal(err)
	}
	rh, _, _, _, err := ParseHeader(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if SamePassKDF(h, rh) {
		t.Error("a rotated header must not share the old passphrase KDF")
	}

	stronger := h
	stronger.Params.Time++
	if SamePassKDF(h, stronger) {
		t.Error("different Argon2id params must not count as the same KDF")
	}
}

// Argon2id params come from the file and are used before the AEAD can reject a
// tampered header, so ParseHeader must refuse values that would panic or
// exhaust memory in argon2.IDKey.
func TestParseHeaderRejectsBadParams(t *testing.T) {
	cases := []struct {
		name   string
		params Params
	}{
		{"zero time", Params{Time: 0, Memory: 64 * 1024, Threads: 4}},
		{"zero threads", Params{Time: 3, Memory: 64 * 1024, Threads: 0}},
		{"memory below 8 KiB per thread", Params{Time: 3, Memory: 8*4 - 1, Threads: 4}},
		{"memory above cap", Params{Time: 3, Memory: maxArgonMemory + 1, Threads: 4}},
		{"time above cap", Params{Time: maxArgonTime + 1, Memory: 64 * 1024, Threads: 4}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := NewHeader(c.params, []byte("cred"))
			if err != nil {
				t.Fatal(err)
			}
			data, err := Encrypt(bytes.Repeat([]byte{1}, 32), h, NewStore())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, err := ParseHeader(data); !errors.Is(err, ErrBadParams) {
				t.Fatalf("got %v, want ErrBadParams", err)
			}
		})
	}

	// The defaults, and the cheap params the tests use, stay valid.
	for _, p := range []Params{DefaultParams(), rotateParams} {
		h, err := NewHeader(p, []byte("cred"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := Encrypt(bytes.Repeat([]byte{1}, 32), h, NewStore())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := ParseHeader(data); err != nil {
			t.Errorf("params %+v rejected: %v", p, err)
		}
	}
}

func TestCheck(t *testing.T) {
	h, key, hmacOut := testHeader(t, "pw")
	data, err := Encrypt(key, h, sampleStore())
	if err != nil {
		t.Fatal(err)
	}
	ph, _, ct, aad, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(key, ph, ct, aad); err != nil {
		t.Errorf("right key: %v", err)
	}
	wrong, err := DeriveKey([]byte("not pw"), hmacOut, ph)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(wrong, ph, ct, aad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: got %v, want ErrDecrypt", err)
	}
}
