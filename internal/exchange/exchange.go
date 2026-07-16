// Package exchange implements a one-time, forward-secret handoff of secrets from
// one with-secrets user to another.
//
// The receiver mints a throwaway X25519 identity and shares its public half as a
// token. The sender encrypts a bundle of secrets to that token, producing a blob
// that travels over any insecure channel. The receiver opens the blob with the
// throwaway private key and then destroys it.
//
// Because the sender uses a fresh ephemeral key per blob (standard sealed-box)
// and the receiver's key is itself throwaway (destroyed after a single open), a
// blob that leaks after the exchange is undecryptable by anyone — the private
// key needed to open it no longer exists.
//
// The blob is also signed with the sender's persistent Ed25519 identity, so the
// receiver can confirm who sent it (a short fingerprint of the sender key, read
// aloud) and gets non-repudiation. Confidentiality comes from the recipient key;
// authenticity from the signature — orthogonal layers.
//
// Blob envelope (all integers big-endian):
//
//	magic         [4]byte   "WSBX"
//	version       uint8     currently 2
//	recipientFP   [8]byte   SHA256(recipientPub)[:8] — picks the pending key
//	senderPub     [32]byte  sender's persistent Ed25519 public key
//	ephemeralPub  [32]byte  sender's per-blob X25519 public key
//	nonce         [24]byte  XChaCha20-Poly1305 nonce
//	ciphertext    [...]byte AEAD(json(Bundle))
//	signature     [64]byte  Ed25519(header ‖ ciphertext)
//
// The header (everything up to the ciphertext) is authenticated as AEAD
// additional data; the trailing signature covers the header and ciphertext.
//
// Key schedule:
//
//	shared = ECDH(ephemeralPriv, recipientPub)              // == ECDH(recipientPriv, ephemeralPub)
//	key    = HKDF-SHA256(ikm=shared, salt=ephemeralPub‖recipientPub, info)
package exchange

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"with-secrets/internal/manifest"
)

const (
	// Version is the current blob envelope version.
	Version = 2

	pubLen   = 32
	fpLen    = 8
	nonceLen = chacha20poly1305.NonceSizeX // 24
	keyLen   = 32
	sigLen   = ed25519.SignatureSize // 64

	tokenPrefix = "wsx1-"
	hkdfInfo    = "with-secrets/exchange/v1"
)

var magic = [4]byte{'W', 'S', 'B', 'X'}

// Errors returned by the package.
var (
	ErrBadMagic     = errors.New("exchange: not a with-secrets blob (bad magic)")
	ErrBadVersion   = errors.New("exchange: unsupported blob version")
	ErrTruncated    = errors.New("exchange: blob is truncated or malformed")
	ErrOpen         = errors.New("exchange: decryption failed (wrong key or tampered blob)")
	ErrBadSignature = errors.New("exchange: sender signature invalid (wrong signer or tampered blob)")
)

// Origin records where a secret lived in the sender's store, so the receiver can
// land it in the corresponding place in theirs.
type Origin string

const (
	OriginLocal  Origin = "local"
	OriginGlobal Origin = "global"
)

// Secret is one name/value pair carried in a bundle.
type Secret struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Origin Origin `json:"origin"`
}

// Bundle is the decrypted payload of a blob: the secrets plus the manifest
// mappings needed for the receiver's `run` to work immediately.
type Bundle struct {
	Scope   string           `json:"scope"` // sender's scope name (informational)
	Entries []manifest.Entry `json:"entries"`
	Secrets []Secret         `json:"secrets"`
}

// Identity is a throwaway X25519 keypair (raw 32-byte values).
type Identity struct {
	Priv []byte
	Pub  []byte
}

// Generate mints a fresh throwaway identity.
func Generate() (Identity, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Priv: priv.Bytes(), Pub: priv.PublicKey().Bytes()}, nil
}

// EncodeToken renders a public key as the shareable token string.
func EncodeToken(pub []byte) string {
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

// DecodeToken parses a token back into a validated X25519 public key.
func DecodeToken(tok string) ([]byte, error) {
	tok = strings.TrimSpace(tok)
	rest, ok := strings.CutPrefix(tok, tokenPrefix)
	if !ok {
		return nil, fmt.Errorf("exchange: not a %s token", strings.TrimSuffix(tokenPrefix, "-"))
	}
	pub, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("exchange: malformed token: %w", err)
	}
	if len(pub) != pubLen {
		return nil, fmt.Errorf("exchange: token key wrong length (%d, want %d)", len(pub), pubLen)
	}
	if _, err := ecdh.X25519().NewPublicKey(pub); err != nil {
		return nil, fmt.Errorf("exchange: invalid public key: %w", err)
	}
	return pub, nil
}

// FPBytes is the raw fingerprint of a public key (SHA256(pub)[:8]). It is what
// the blob carries so the receiver can pick the matching pending key.
func FPBytes(pub []byte) []byte {
	sum := sha256.Sum256(pub)
	out := make([]byte, fpLen)
	copy(out, sum[:fpLen])
	return out
}

// Fingerprint is the short human-comparable form of a public key's fingerprint,
// e.g. "ABLE-QK". Both sides compute the same value from the same public key.
//
// It is intentionally short (30 bits of a base32 encoding): a presence check for
// two co-located people to read aloud and confirm they hold the same key, not a
// collision-resistant identifier.
func Fingerprint(pub []byte) string {
	// base32 std alphabet is already uppercase (A-Z2-7).
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(FPBytes(pub))[:6]
	return s[:4] + "-" + s[4:]
}

func deriveKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	r := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts a bundle to recipientPub and signs it with the sender's
// persistent Ed25519 identity (signerPriv), returning a complete blob. A fresh
// ephemeral X25519 keypair is generated per call for the encryption layer.
func Seal(recipientPub, signerPriv []byte, b *Bundle) ([]byte, error) {
	if len(signerPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("exchange: invalid signer key length (%d, want %d)", len(signerPriv), ed25519.PrivateKeySize)
	}
	signKey := ed25519.PrivateKey(signerPriv)
	senderPub := signKey.Public().(ed25519.PublicKey)

	curve := ecdh.X25519()
	rpub, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("exchange: invalid recipient key: %w", err)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(rpub)
	if err != nil {
		return nil, err
	}
	defer zero(shared)

	ephPub := eph.PublicKey().Bytes()
	key, err := deriveKey(shared, ephPub, recipientPub)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	plaintext, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	header := marshalHeader(FPBytes(recipientPub), senderPub, ephPub, nonce)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, header)

	signed := make([]byte, 0, len(header)+len(sealed))
	signed = append(signed, header...)
	signed = append(signed, sealed...)
	sig := ed25519.Sign(signKey, signed)

	return append(signed, sig...), nil
}

// Open verifies a blob's sender signature, then decrypts it with the recipient's
// private key. It returns the decrypted bundle and the verified sender public
// key (an Ed25519 key) so the caller can show its fingerprint for confirmation.
func Open(recipientPriv, blob []byte) (*Bundle, []byte, error) {
	_, senderPub, ephPub, nonce, ciphertext, signed, sig, aad, err := parseHeader(blob)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(senderPub), signed, sig) {
		return nil, nil, ErrBadSignature
	}

	curve := ecdh.X25519()
	rpriv, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("exchange: invalid private key: %w", err)
	}
	epub, err := curve.NewPublicKey(ephPub)
	if err != nil {
		return nil, nil, ErrTruncated
	}
	shared, err := rpriv.ECDH(epub)
	if err != nil {
		return nil, nil, err
	}
	defer zero(shared)

	key, err := deriveKey(shared, ephPub, rpriv.PublicKey().Bytes())
	if err != nil {
		return nil, nil, err
	}
	defer zero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, nil, ErrOpen
	}
	defer zero(plaintext)

	var bundle Bundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return nil, nil, err
	}
	// Return a copy of senderPub; it aliases the caller's blob otherwise.
	sp := make([]byte, len(senderPub))
	copy(sp, senderPub)
	return &bundle, sp, nil
}

// RecipientFP returns the recipient fingerprint embedded in a blob, without any
// private key — used to select the matching pending exchange.
func RecipientFP(blob []byte) ([]byte, error) {
	fp, _, _, _, _, _, _, _, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}
	return fp, nil
}

func marshalHeader(fp, senderPub, ephPub, nonce []byte) []byte {
	var b bytes.Buffer
	b.Write(magic[:])
	b.WriteByte(Version)
	b.Write(fp)
	b.Write(senderPub)
	b.Write(ephPub)
	b.Write(nonce)
	return b.Bytes()
}

// parseHeader splits a blob into its fields. It returns the authenticated header
// (AEAD additional data), the ciphertext, the signed region (header‖ciphertext),
// and the trailing signature.
func parseHeader(data []byte) (fp, senderPub, ephPub, nonce, ciphertext, signed, sig, aad []byte, err error) {
	const headerLen = 4 + 1 + fpLen + pubLen + pubLen + nonceLen
	if len(data) < headerLen+sigLen {
		return nil, nil, nil, nil, nil, nil, nil, nil, ErrTruncated
	}
	if !bytes.Equal(data[:4], magic[:]) {
		return nil, nil, nil, nil, nil, nil, nil, nil, ErrBadMagic
	}
	if data[4] != Version {
		return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("%w: %d", ErrBadVersion, data[4])
	}
	off := 5
	fp = data[off : off+fpLen]
	off += fpLen
	senderPub = data[off : off+pubLen]
	off += pubLen
	ephPub = data[off : off+pubLen]
	off += pubLen
	nonce = data[off : off+nonceLen]
	off += nonceLen
	ciphertext = data[off : len(data)-sigLen]
	signed = data[:len(data)-sigLen]
	sig = data[len(data)-sigLen:]
	aad = data[:headerLen]
	return fp, senderPub, ephPub, nonce, ciphertext, signed, sig, aad, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
