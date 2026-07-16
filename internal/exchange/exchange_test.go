package exchange

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"with-secrets/internal/manifest"
)

// sampleSigner returns a throwaway Ed25519 identity for signing test blobs.
func sampleSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func sampleBundle() *Bundle {
	return &Bundle{
		Scope:   "acme-api",
		Entries: []manifest.Entry{{EnvVar: "AWS_SECRET", StoreKey: "AWS_SECRET"}},
		Secrets: []Secret{
			{Name: "AWS_SECRET", Value: "shh-local", Origin: OriginLocal},
			{Name: "GITHUB_TOKEN", Value: "shh-global", Origin: OriginGlobal},
		},
	}
}

func TestTokenRoundTrip(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	tok := EncodeToken(id.Pub)
	got, err := DecodeToken(tok)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	if !bytes.Equal(got, id.Pub) {
		t.Fatalf("round-trip mismatch: %x != %x", got, id.Pub)
	}
	// Surrounding whitespace (pasted from chat) is tolerated.
	if _, err := DecodeToken("  " + tok + "\n"); err != nil {
		t.Errorf("whitespace token rejected: %v", err)
	}
}

func TestDecodeTokenRejectsMalformed(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"no prefix":    base32Nope(),
		"bad base64":   tokenPrefix + "!!!!not-base64!!!!",
		"wrong length": tokenPrefix + "AAAA", // decodes but too short
		"empty":        "",
	}
	for name, tok := range cases {
		if _, err := DecodeToken(tok); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
	// Sanity: the good one still passes.
	if _, err := DecodeToken(EncodeToken(id.Pub)); err != nil {
		t.Errorf("valid token rejected: %v", err)
	}
}

func base32Nope() string { return "definitely-not-a-token" }

func TestFingerprintDeterministicAndFormatted(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := Fingerprint(id.Pub)
	b := Fingerprint(id.Pub)
	if a != b {
		t.Fatalf("fingerprint not deterministic: %q != %q", a, b)
	}
	if len(a) != 7 || a[4] != '-' {
		t.Fatalf("fingerprint format = %q, want XXXX-XX", a)
	}
	// Different keys should (essentially always) differ.
	id2, _ := Generate()
	if Fingerprint(id2.Pub) == a {
		t.Errorf("distinct keys produced identical fingerprint %q", a)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer := sampleSigner(t)
	blob, err := Seal(id.Pub, signer, sampleBundle())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, senderPub, err := Open(id.Priv, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Scope != "acme-api" || len(got.Secrets) != 2 || len(got.Entries) != 1 {
		t.Fatalf("bundle not preserved: %+v", got)
	}
	if got.Secrets[0].Value != "shh-local" || got.Secrets[1].Origin != OriginGlobal {
		t.Fatalf("secret contents wrong: %+v", got.Secrets)
	}
	// Open surfaces the signer's public key so the caller can show its fingerprint.
	if !bytes.Equal(senderPub, signer.Public().(ed25519.PublicKey)) {
		t.Fatalf("senderPub %x != signer pub %x", senderPub, signer.Public())
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	id, _ := Generate()
	other, _ := Generate()
	blob, err := Seal(id.Pub, sampleSigner(t), sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(other.Priv, blob); err == nil {
		t.Fatal("Open with wrong key should fail")
	}
}

func TestTamperFails(t *testing.T) {
	id, _ := Generate()
	blob, err := Seal(id.Pub, sampleSigner(t), sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in each region: header (senderPub area), ciphertext, signature.
	// The signature covers header+ciphertext, so header/ciphertext tampering is
	// caught as ErrBadSignature before decryption is even attempted.
	headerLen := 4 + 1 + fpLen + pubLen + pubLen + nonceLen
	positions := map[string]int{
		"header":     5 + fpLen + 1, // inside senderPub
		"ciphertext": headerLen + 1, // inside the AEAD ciphertext
		"signature":  len(blob) - 1, // last signature byte
	}
	for name, pos := range positions {
		bad := append([]byte(nil), blob...)
		bad[pos] ^= 0x01
		if _, _, err := Open(id.Priv, bad); err == nil {
			t.Errorf("tamper in %s (pos %d) should fail to open", name, pos)
		}
	}
}

func TestWrongSignerDetectable(t *testing.T) {
	id, _ := Generate()
	alice := sampleSigner(t)
	blob, err := Seal(id.Pub, alice, sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	// A blob signed by Alice opens fine and surfaces Alice's fingerprint — which
	// differs from anyone else's, so the receiver's aloud check can catch an
	// impostor who crafted their own blob to the same token.
	_, senderPub, err := Open(id.Priv, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if Fingerprint(senderPub) != Fingerprint(alice.Public().(ed25519.PublicKey)) {
		t.Fatal("surfaced sender fingerprint does not match the true signer")
	}
	mallory := sampleSigner(t)
	if Fingerprint(mallory.Public().(ed25519.PublicKey)) == Fingerprint(senderPub) {
		t.Fatal("distinct signers produced identical fingerprints")
	}
}

func TestSwappedSenderPubFails(t *testing.T) {
	id, _ := Generate()
	alice := sampleSigner(t)
	mallory := sampleSigner(t)
	blob, err := Seal(id.Pub, alice, sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	// Swapping in Mallory's public key without re-signing must fail verification
	// (the signature is over the header, which includes senderPub).
	bad := append([]byte(nil), blob...)
	copy(bad[5+fpLen:5+fpLen+pubLen], mallory.Public().(ed25519.PublicKey))
	if _, _, err := Open(id.Priv, bad); err != ErrBadSignature {
		t.Fatalf("swapped senderPub: got %v, want ErrBadSignature", err)
	}
}

func TestRecipientFPMatches(t *testing.T) {
	id, _ := Generate()
	blob, err := Seal(id.Pub, sampleSigner(t), sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	fp, err := RecipientFP(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fp, FPBytes(id.Pub)) {
		t.Fatalf("RecipientFP %x != FPBytes %x", fp, FPBytes(id.Pub))
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := RecipientFP([]byte("short")); err != ErrTruncated {
		t.Errorf("short blob: got %v, want ErrTruncated", err)
	}
	id, _ := Generate()
	blob, _ := Seal(id.Pub, sampleSigner(t), sampleBundle())

	badMagic := append([]byte(nil), blob...)
	badMagic[0] ^= 0xFF
	if _, err := RecipientFP(badMagic); err != ErrBadMagic {
		t.Errorf("bad magic: got %v, want ErrBadMagic", err)
	}

	badVer := append([]byte(nil), blob...)
	badVer[4] = 0xFF
	if _, err := RecipientFP(badVer); err == nil {
		t.Error("bad version should error")
	}
}
