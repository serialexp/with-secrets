// Package store defines the on-disk encrypted secrets store.
//
// Envelope format (all integers big-endian):
//
//	magic        [4]byte   "WSEC"
//	version      uint8     currently 1
//	argonTime    uint32    Argon2id iterations
//	argonMemory  uint32    Argon2id memory in KiB
//	argonThreads uint8     Argon2id parallelism
//	salt         [16]byte  Argon2id salt (fixed for the life of the store)
//	credIDLen    uint16
//	credID       [credIDLen]byte   FIDO2 non-resident credential id
//	hmacSalt     [32]byte  salt fed to the YubiKey hmac-secret extension
//	nonce        [24]byte  XChaCha20-Poly1305 nonce (fresh per seal)
//	indexLen     uint32
//	index        [indexLen]byte    cleartext JSON: scope + secret NAMES (no values)
//	ciphertext   [...]byte         AEAD(secrets-json)
//
// The index is cleartext by design: it lets `list` and `scopes` enumerate scope
// and secret names without a passphrase or a touch. Only values are encrypted.
// Names are already visible in committed .secrets manifests, so this leaks
// nothing new.
//
// Key derivation combines two required factors:
//
//	passKey   = Argon2id(passphrase, salt, params)          // what you know
//	hmacOut   = YubiKey hmac-secret(credID, hmacSalt)       // what you have (touch)
//	masterKey = HKDF-SHA256(ikm=hmacOut, salt=passKey, info)
//
// Everything preceding the ciphertext — header and index — is authenticated as
// AEAD additional data, so params, credential id, salts, and the name index
// cannot be altered without failing the next decryption.
package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"crypto/sha256"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// Version is the current envelope version.
	Version = 1

	saltLen     = 16
	hmacSaltLen = 32
	keyLen      = 32
	nonceLen    = chacha20poly1305.NonceSizeX // 24

	hkdfInfo = "with-secrets/v1/masterkey"
)

var magic = [4]byte{'W', 'S', 'E', 'C'}

// Errors returned by the package.
var (
	ErrBadMagic    = errors.New("store: not a with-secrets file (bad magic)")
	ErrBadVersion  = errors.New("store: unsupported envelope version")
	ErrTruncated   = errors.New("store: file is truncated or malformed")
	ErrDecrypt     = errors.New("store: decryption failed (wrong passphrase, wrong key, or tampered file)")
	ErrCredTooLong = errors.New("store: credential id exceeds 65535 bytes")
)

// Params holds the Argon2id cost parameters.
type Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultParams returns sensible Argon2id parameters (~64 MiB, 3 passes).
func DefaultParams() Params {
	return Params{Time: 3, Memory: 64 * 1024, Threads: 4}
}

// Store is the decrypted secret store: a set of global secrets plus per-scope
// buckets. A scope lookup falls back to global.
type Store struct {
	Global map[string]string            `json:"global"`
	Scopes map[string]map[string]string `json:"scopes"`
	// SenderPriv is the owner's persistent Ed25519 identity, used to sign secret
	// handoff blobs (`ws send`). It is part of the encrypted payload, so it is
	// protected by the same two factors as the secrets and never appears in the
	// cleartext name index. Absent on stores created before the feature; filled
	// lazily on first send.
	SenderPriv []byte `json:"sender_priv,omitempty"`
}

// NewStore returns an empty store with initialised maps.
func NewStore() *Store {
	return &Store{Global: map[string]string{}, Scopes: map[string]map[string]string{}}
}

// EnsureIdentity generates a persistent Ed25519 signing identity into the store
// if one is not already present. It reports whether a new key was created (so the
// caller knows it must reseal to persist it). Idempotent.
func (s *Store) EnsureIdentity() (created bool, err error) {
	if len(s.SenderPriv) == ed25519.PrivateKeySize {
		return false, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	s.SenderPriv = priv
	return true, nil
}

// Identity returns the store's Ed25519 signing key, or ok=false if none is set.
func (s *Store) Identity() (ed25519.PrivateKey, bool) {
	if len(s.SenderPriv) != ed25519.PrivateKeySize {
		return nil, false
	}
	return ed25519.PrivateKey(s.SenderPriv), true
}

func (s *Store) ensure() {
	if s.Global == nil {
		s.Global = map[string]string{}
	}
	if s.Scopes == nil {
		s.Scopes = map[string]map[string]string{}
	}
}

// SetGlobal stores a global secret.
func (s *Store) SetGlobal(name, value string) {
	s.ensure()
	s.Global[name] = value
}

// Set stores a secret in the given scope (creating the scope if needed). An
// empty scope targets the global bucket.
func (s *Store) Set(scope, name, value string) {
	s.ensure()
	if scope == "" {
		s.Global[name] = value
		return
	}
	if s.Scopes[scope] == nil {
		s.Scopes[scope] = map[string]string{}
	}
	s.Scopes[scope][name] = value
}

// Resolve looks up name in scope, then falls back to global.
func (s *Store) Resolve(scope, name string) (string, bool) {
	return s.ResolveChain([]string{scope}, name)
}

// ResolveChain looks up name across the given scopes in order (most specific
// first), then falls back to global. The first hit wins. Empty scope names are
// skipped, so a single "" scope resolves against global alone.
func (s *Store) ResolveChain(scopes []string, name string) (string, bool) {
	for _, scope := range scopes {
		if scope == "" {
			continue
		}
		if m, ok := s.Scopes[scope]; ok {
			if v, ok := m[name]; ok {
				return v, true
			}
		}
	}
	v, ok := s.Global[name]
	return v, ok
}

// Remove deletes name from scope (empty scope = global). Returns whether it
// existed. Empty scopes are pruned.
func (s *Store) Remove(scope, name string) bool {
	if scope == "" {
		if _, ok := s.Global[name]; ok {
			delete(s.Global, name)
			return true
		}
		return false
	}
	m, ok := s.Scopes[scope]
	if !ok {
		return false
	}
	if _, ok := m[name]; !ok {
		return false
	}
	delete(m, name)
	if len(m) == 0 {
		delete(s.Scopes, scope)
	}
	return true
}

// GlobalNames returns the sorted names of global secrets.
func (s *Store) GlobalNames() []string { return sortedKeys(s.Global) }

// ScopeNames returns the sorted names of secrets in the given scope.
func (s *Store) ScopeNames(scope string) []string { return sortedKeys(s.Scopes[scope]) }

// Index is the cleartext projection of the store's structure: which secret names
// exist globally and per scope, with no values. It is embedded in the envelope
// so names can be listed without decrypting.
type Index struct {
	Global []string            `json:"global"`
	Scopes map[string][]string `json:"scopes"`
}

// Index builds the name index from the current store contents.
func (s *Store) Index() Index {
	idx := Index{Global: s.GlobalNames(), Scopes: map[string][]string{}}
	for scope := range s.Scopes {
		idx.Scopes[scope] = s.ScopeNames(scope)
	}
	return idx
}

// ScopeNames returns the sorted scope names present in the index.
func (i Index) ScopeNames() []string {
	out := make([]string, 0, len(i.Scopes))
	for k := range i.Scopes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Header is the non-ciphertext portion of the envelope. Salt, CredID and
// HMACSalt are fixed for the life of a store so that both factors reproduce the
// same masterKey; Nonce is regenerated on every Encrypt.
type Header struct {
	Params   Params
	Salt     []byte
	CredID   []byte
	HMACSalt []byte
	Nonce    []byte
}

// NewHeader builds a header with fresh random salts and nonce for a new store.
func NewHeader(params Params, credID []byte) (Header, error) {
	h := Header{
		Params:   params,
		Salt:     make([]byte, saltLen),
		CredID:   append([]byte(nil), credID...),
		HMACSalt: make([]byte, hmacSaltLen),
		Nonce:    make([]byte, nonceLen),
	}
	if _, err := io.ReadFull(rand.Reader, h.Salt); err != nil {
		return Header{}, err
	}
	if _, err := io.ReadFull(rand.Reader, h.HMACSalt); err != nil {
		return Header{}, err
	}
	return h, nil
}

// DerivePassKey stretches the passphrase with Argon2id into a 32-byte key. This
// is the "what you know" half of the master key and the expensive step; it can
// be computed once and cached (e.g. for an interactive session) since on its own
// it cannot decrypt anything without the YubiKey factor.
func DerivePassKey(passphrase []byte, h Header) []byte {
	return argon2.IDKey(passphrase, h.Salt, h.Params.Time, h.Params.Memory, h.Params.Threads, keyLen)
}

// CombineKey folds the YubiKey hmac-secret output into the cached passKey to
// produce the 32-byte master key. Both factors are required.
func CombineKey(passKey, hmacOut []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, hmacOut, passKey, []byte(hkdfInfo))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeriveKey combines the passphrase and the YubiKey hmac-secret output into the
// 32-byte master key. hmacOut is the raw output of the hmac-secret extension
// obtained with h.CredID and h.HMACSalt.
func DeriveKey(passphrase, hmacOut []byte, h Header) ([]byte, error) {
	passKey := DerivePassKey(passphrase, h)
	defer Zero(passKey)
	return CombineKey(passKey, hmacOut)
}

// marshalHeader serialises the fixed header prefix (magic through nonce). Encrypt
// appends the length-prefixed index to this to form the AEAD additional data.
func marshalHeader(h Header) ([]byte, error) {
	if len(h.CredID) > 0xFFFF {
		return nil, ErrCredTooLong
	}
	var b bytes.Buffer
	b.Write(magic[:])
	b.WriteByte(Version)
	_ = binary.Write(&b, binary.BigEndian, h.Params.Time)
	_ = binary.Write(&b, binary.BigEndian, h.Params.Memory)
	b.WriteByte(h.Params.Threads)
	b.Write(h.Salt)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(h.CredID)))
	b.Write(h.CredID)
	b.Write(h.HMACSalt)
	b.Write(h.Nonce)
	return b.Bytes(), nil
}

// ParseHeader reads the header and cleartext index from data and returns them
// along with the ciphertext and the authenticated prefix (AEAD additional data,
// which spans the header and index).
func ParseHeader(data []byte) (h Header, idx Index, ciphertext, aad []byte, err error) {
	r := bytes.NewReader(data)

	var gotMagic [4]byte
	if _, err = io.ReadFull(r, gotMagic[:]); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	if gotMagic != magic {
		return Header{}, Index{}, nil, nil, ErrBadMagic
	}

	ver, err := r.ReadByte()
	if err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	if ver != Version {
		return Header{}, Index{}, nil, nil, fmt.Errorf("%w: %d", ErrBadVersion, ver)
	}

	if err = binary.Read(r, binary.BigEndian, &h.Params.Time); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	if err = binary.Read(r, binary.BigEndian, &h.Params.Memory); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	if h.Params.Threads, err = r.ReadByte(); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}

	h.Salt = make([]byte, saltLen)
	if _, err = io.ReadFull(r, h.Salt); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}

	var credLen uint16
	if err = binary.Read(r, binary.BigEndian, &credLen); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	h.CredID = make([]byte, credLen)
	if _, err = io.ReadFull(r, h.CredID); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}

	h.HMACSalt = make([]byte, hmacSaltLen)
	if _, err = io.ReadFull(r, h.HMACSalt); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}

	h.Nonce = make([]byte, nonceLen)
	if _, err = io.ReadFull(r, h.Nonce); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}

	var idxLen uint32
	if err = binary.Read(r, binary.BigEndian, &idxLen); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	idxBytes := make([]byte, idxLen)
	if _, err = io.ReadFull(r, idxBytes); err != nil {
		return Header{}, Index{}, nil, nil, ErrTruncated
	}
	if err = json.Unmarshal(idxBytes, &idx); err != nil {
		return Header{}, Index{}, nil, nil, fmt.Errorf("store: malformed index: %w", err)
	}
	if idx.Scopes == nil {
		idx.Scopes = map[string][]string{}
	}

	headerLen := len(data) - r.Len()
	aad = data[:headerLen]
	ciphertext = data[headerLen:]
	return h, idx, ciphertext, aad, nil
}

// Encrypt seals the store under key, generating a fresh nonce. The returned
// bytes are a complete envelope. h is copied; the caller's header is not mutated.
func Encrypt(key []byte, h Header, s *Store) ([]byte, error) {
	plaintext, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	defer Zero(plaintext)

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	h.Nonce = nonce

	prefix, err := marshalHeader(h)
	if err != nil {
		return nil, err
	}
	idxBytes, err := json.Marshal(s.Index())
	if err != nil {
		return nil, err
	}
	// AAD spans the header and the cleartext index.
	aad := make([]byte, 0, len(prefix)+4+len(idxBytes))
	aad = append(aad, prefix...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(idxBytes)))
	aad = append(aad, idxBytes...)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext to aad's backing array copy; build explicitly.
	sealed := aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, len(aad)+len(sealed))
	out = append(out, aad...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt opens the ciphertext with key and returns the store.
func Decrypt(key []byte, h Header, ciphertext, aad []byte) (*Store, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, h.Nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer Zero(plaintext)

	s := NewStore()
	if err := json.Unmarshal(plaintext, s); err != nil {
		return nil, err
	}
	s.ensure()
	return s, nil
}

// Zero overwrites b with zeros. Best-effort defence against secrets lingering
// in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
