package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"with-secrets/internal/exchange"
	"with-secrets/internal/store"
)

func TestPreviewSecret(t *testing.T) {
	cases := map[string]string{
		"":                     "(empty)",
		"ab":                   "ab",      // too short to mask: shown in full
		"abcd":                 "abcd",    // (a 6-or-fewer secret is weak anyway)
		"abcde":                "abcde",   //
		"abcdef":               "abcdef",  // len 6: still full
		"abcdefg":              "abc…efg", // len 7: first 3 + last 3, one rune hidden
		"supersecretvalue1234": "sup…234",
		"a\ncdefghij":          "a⏎c…hij", // newline shown as ⏎, never a raw newline
	}
	for in, want := range cases {
		if got := previewSecret(in); got != want {
			t.Errorf("previewSecret(%q) = %q, want %q", in, got, want)
		}
	}
	// A masked value must never leak more than the six edge runes, nor a raw
	// newline that would break the checklist row.
	if got := previewSecret("supersecretvalue1234"); strings.Contains(got, "secret") {
		t.Errorf("preview leaked the middle: %q", got)
	}
	if got := previewSecret("multi\nline\nsecret\nvalue"); strings.ContainsRune(got, '\n') {
		t.Errorf("preview contained a raw newline: %q", got)
	}
}

func TestTargetScope(t *testing.T) {
	ctx := scopeCtx{scope: "acme"}
	if got := targetScope(ctx, exchange.OriginLocal); got != "acme" {
		t.Errorf("local target = %q, want acme", got)
	}
	if got := targetScope(ctx, exchange.OriginGlobal); got != "" {
		t.Errorf("global target = %q, want empty", got)
	}
}

func TestScopeAndCurrentValue(t *testing.T) {
	st := store.NewStore()
	st.Set("acme", "A", "local-a")
	st.SetGlobal("B", "global-b")

	if v, ok := scopeValue(st, "acme", "A"); !ok || v != "local-a" {
		t.Errorf("scopeValue A = %q,%v", v, ok)
	}
	if _, ok := scopeValue(st, "acme", "B"); ok {
		t.Error("scopeValue should not fall back to global")
	}
	if v, ok := currentValue(st, "", "B"); !ok || v != "global-b" {
		t.Errorf("currentValue global B = %q,%v", v, ok)
	}
	if v, ok := currentValue(st, "acme", "A"); !ok || v != "local-a" {
		t.Errorf("currentValue scoped A = %q,%v", v, ok)
	}
	if _, ok := currentValue(st, "acme", "missing"); ok {
		t.Error("currentValue missing should be false")
	}
}

func TestPendingRoundTripAndGC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WITH_SECRETS_STORE", filepath.Join(dir, "store.wsec"))

	pdir, err := pendingDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		t.Fatal(err)
	}

	id, err := exchange.Generate()
	if err != nil {
		t.Fatal(err)
	}
	write := func(created time.Time) string {
		rec := pendingExchange{
			Priv:    base64.StdEncoding.EncodeToString(id.Priv),
			Pub:     base64.StdEncoding.EncodeToString(id.Pub),
			Created: created,
			FP:      exchange.Fingerprint(id.Pub),
		}
		data, _ := json.Marshal(rec)
		p, err := pendingPathFor(exchange.FPBytes(id.Pub))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Fresh record survives GC and round-trips.
	p := write(time.Now())
	if _, err := readPending(p); err != nil {
		t.Fatalf("readPending: %v", err)
	}
	gcExpiredPending()
	if _, err := os.Stat(p); err != nil {
		t.Errorf("fresh pending key should survive GC: %v", err)
	}

	// Expired record is swept.
	write(time.Now().Add(-pendingTTL - time.Minute))
	gcExpiredPending()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("expired pending key should be removed, stat err = %v", err)
	}
}
