package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
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
	data[5] ^= 0xFF // first byte of Argon2 Time param
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
