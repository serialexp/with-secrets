package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"with-secrets/internal/exchange"
	"with-secrets/internal/manifest"
	"with-secrets/internal/store"
)

// pendingTTL bounds how long a minted exchange key is usable. The two parties are
// meant to be sitting together, so the window is deliberately short.
const pendingTTL = 15 * time.Minute

// pendingExchange is a throwaway receiver keypair awaiting a blob. It is written
// to disk (0600) between `ws request` and `ws receive`, and destroyed on use.
type pendingExchange struct {
	Priv    string    `json:"priv"` // base64 X25519 private key
	Pub     string    `json:"pub"`  // base64 X25519 public key
	Created time.Time `json:"created"`
	FP      string    `json:"fp"` // human fingerprint, for reference
}

// pendingDir is the directory holding pending exchange keys, a sibling of the
// store file.
func pendingDir() (string, error) {
	sp, err := storePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(sp), "exchanges"), nil
}

// gcExpiredPending removes pending keys past their TTL. Best-effort: errors are
// ignored so cleanup never blocks the real work.
func gcExpiredPending() {
	dir, err := pendingDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		rec, err := readPending(p)
		if err != nil || time.Since(rec.Created) > pendingTTL {
			os.Remove(p)
		}
	}
}

func readPending(path string) (pendingExchange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pendingExchange{}, err
	}
	var rec pendingExchange
	if err := json.Unmarshal(data, &rec); err != nil {
		return pendingExchange{}, err
	}
	return rec, nil
}

// pendingPathFor returns the on-disk path for a given recipient fingerprint.
func pendingPathFor(fp []byte) (string, error) {
	dir, err := pendingDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, hex.EncodeToString(fp)+".json"), nil
}

// --- ws request -----------------------------------------------------------

// cmdRequest mints a throwaway keypair, stores the private half locally with a
// short expiry, and prints the public token plus a fingerprint to read aloud.
func cmdRequest(_ []string) error {
	gcExpiredPending()

	id, err := exchange.Generate()
	if err != nil {
		return err
	}
	defer store.Zero(id.Priv)

	dir, err := pendingDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	rec := pendingExchange{
		Priv:    base64.StdEncoding.EncodeToString(id.Priv),
		Pub:     base64.StdEncoding.EncodeToString(id.Pub),
		Created: time.Now(),
		FP:      exchange.Fingerprint(id.Pub),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path, err := pendingPathFor(exchange.FPBytes(id.Pub))
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return err
	}

	fmt.Printf("Send this to the person sharing secrets with you (valid %d minutes):\n\n", int(pendingTTL.Minutes()))
	fmt.Printf("  %s\n\n", exchange.EncodeToken(id.Pub))
	fmt.Printf("Fingerprint: %s\n", rec.FP)
	fmt.Println("When they run `ws send`, check they see the same fingerprint.")
	return nil
}

// --- ws send --------------------------------------------------------------

type outgoing struct {
	entry  manifest.Entry
	value  string
	origin exchange.Origin
}

// cmdSend encrypts the current repo's .secrets set to a recipient token and
// writes the resulting blob. Local secrets are always included; global-fallback
// ones are offered via a checklist.
func cmdSend(args []string) error {
	var token, out, dir string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--to":
			i++
			if i >= len(args) {
				return errors.New("--to needs a token")
			}
			token = args[i]
		case "-o", "--out":
			i++
			if i >= len(args) {
				return errors.New("-o needs a path")
			}
			out = args[i]
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("unknown flag %q", a)
			}
			if dir != "" {
				return errors.New("send takes at most one DIR")
			}
			dir = a
		}
	}
	if token == "" {
		return errors.New("usage: with-secrets send --to <token> [DIR] [-o OUT]")
	}
	recipientPub, err := exchange.DecodeToken(token)
	if err != nil {
		return err
	}

	// Human MITM check before any secrets are read.
	fmt.Fprintf(os.Stderr, "Recipient fingerprint: %s\n", exchange.Fingerprint(recipientPub))
	ok, err := promptYesNo("Does the recipient see the same fingerprint?")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted: fingerprint not confirmed")
	}

	if dir == "" {
		dir, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}

	mpath, err := manifest.FindUp(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no %s found in %s or any parent — nothing to send", manifest.DefaultName, dir)
		}
		return err
	}
	m, err := manifest.Load(mpath)
	if err != nil {
		return err
	}
	if len(m.Entries) == 0 {
		return fmt.Errorf("%s is empty; nothing to send", mpath)
	}
	scope := m.Scope
	if scope == "" {
		scope = filepath.Dir(mpath)
	}

	st, key, f, err := unlock()
	if err != nil {
		return err
	}
	defer store.Zero(key)

	// Ensure this store has a persistent signing identity; persist it once if we
	// just minted it, so the sender fingerprint stays stable across handoffs.
	created, err := st.EnsureIdentity()
	if err != nil {
		return err
	}
	if created {
		if err := f.save(key, st); err != nil {
			return err
		}
	}
	signPriv, ok := st.Identity()
	if !ok {
		return errors.New("store has no signing identity")
	}
	fmt.Fprintf(os.Stderr, "Your sender fingerprint: %s (the recipient will confirm it)\n", exchange.Fingerprint(signPriv.Public().(ed25519.PublicKey)))

	// Classify each entry by where its value lives.
	var locals, globals []outgoing
	var missing []string
	for _, e := range m.Entries {
		if v, ok := scopeValue(st, scope, e.StoreKey); ok {
			locals = append(locals, outgoing{e, v, exchange.OriginLocal})
		} else if v, ok := st.Global[e.StoreKey]; ok {
			globals = append(globals, outgoing{e, v, exchange.OriginGlobal})
		} else {
			missing = append(missing, e.StoreKey)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("secrets not found in store: %s", strings.Join(missing, ", "))
	}

	included := locals
	if len(globals) > 0 {
		items := make([]checklistItem, len(globals))
		for i, g := range globals {
			items[i] = checklistItem{
				label:   g.entry.EnvVar,
				sub:     "global · " + previewSecret(g.value),
				checked: false,
			}
		}
		result, confirmed, err := selectItems("Also include these global secrets?", items)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("send cancelled")
		}
		for i, it := range result {
			if it.checked {
				included = append(included, globals[i])
			}
		}
	}
	if len(included) == 0 {
		return errors.New("nothing to send")
	}

	bundle := &exchange.Bundle{Scope: filepath.Base(scope)}
	for _, o := range included {
		bundle.Entries = append(bundle.Entries, o.entry)
		bundle.Secrets = append(bundle.Secrets, exchange.Secret{
			Name:   o.entry.StoreKey,
			Value:  o.value,
			Origin: o.origin,
		})
	}
	blob, err := exchange.Seal(recipientPub, signPriv, bundle)
	if err != nil {
		return err
	}

	if out == "" {
		base := filepath.Base(scope)
		if base == "." || base == string(os.PathSeparator) || base == "" {
			base = "secrets"
		}
		out = base + ".wsx"
	}
	if err := writeFileAtomic(out, blob, 0o600); err != nil {
		return err
	}
	abs, _ := filepath.Abs(out)
	fmt.Printf("Wrote %s (%d secret(s)). Hand it to the recipient; they run `ws receive`.\n", abs, len(included))
	return nil
}

// --- ws receive -----------------------------------------------------------

// cmdReceive decrypts a blob with a matching pending key and lands its secrets
// into the receiver's own store, then destroys the pending key.
func cmdReceive(args []string) error {
	var blobPath, dir string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("unknown flag %q", a)
		}
		if blobPath == "" {
			blobPath = a
		} else if dir == "" {
			dir = a
		} else {
			return errors.New("receive takes at most BLOB and DIR")
		}
	}
	if blobPath == "" {
		return errors.New("usage: with-secrets receive BLOB [DIR]")
	}

	blob, err := os.ReadFile(blobPath)
	if err != nil {
		return err
	}
	fp, err := exchange.RecipientFP(blob)
	if err != nil {
		return err
	}
	recPath, err := pendingPathFor(fp)
	if err != nil {
		return err
	}
	rec, err := readPending(recPath)
	if err != nil {
		return errors.New("no matching exchange for this blob — did it expire? run `ws request` again")
	}
	if time.Since(rec.Created) > pendingTTL {
		os.Remove(recPath)
		return fmt.Errorf("this exchange expired (older than %d min) — run `ws request` again", int(pendingTTL.Minutes()))
	}
	priv, err := base64.StdEncoding.DecodeString(rec.Priv)
	if err != nil {
		return err
	}
	defer store.Zero(priv)

	bundle, senderPub, err := exchange.Open(priv, blob)
	if err != nil {
		return err
	}

	// Confirm who sent it before importing anything. A poisoned blob from an
	// attacker on the channel carries a different signing key, so its fingerprint
	// won't match what the real sender reads aloud. Leave the pending key intact
	// on rejection so a genuine blob can still be received.
	fmt.Fprintf(os.Stderr, "Sender fingerprint: %s\n", exchange.Fingerprint(senderPub))
	ok, err := promptYesNo("Does the sender confirm this same fingerprint?")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted: sender fingerprint not confirmed")
	}

	// Split by origin; offer the globals for acceptance before touching any store.
	var incoming []exchange.Secret
	var globals []exchange.Secret
	for _, s := range bundle.Secrets {
		if s.Origin == exchange.OriginGlobal {
			globals = append(globals, s)
		} else {
			incoming = append(incoming, s)
		}
	}
	if len(globals) > 0 {
		items := make([]checklistItem, len(globals))
		for i, g := range globals {
			items[i] = checklistItem{
				label:   g.Name,
				sub:     "→ your global · " + previewSecret(g.Value),
				checked: true,
			}
		}
		result, confirmed, err := selectItems("Accept these global secrets into your global scope?", items)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("receive cancelled")
		}
		for i, it := range result {
			if it.checked {
				incoming = append(incoming, globals[i])
			}
		}
	}
	if len(incoming) == 0 {
		// Nothing accepted: leave the pending key for a retry (it GCs after the TTL).
		fmt.Fprintln(os.Stderr, "Nothing accepted; nothing imported.")
		return nil
	}

	// Resolve (and possibly create) the local scope only now that we know there
	// is something to import, and before any crypto/touch.
	if dir == "" {
		dir, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	ctx, err := resolveWriteContextIn(false, dir)
	if err != nil {
		return err
	}

	st, key, f, err := unlock()
	if err != nil {
		return err
	}
	defer store.Zero(key)

	// Detect collisions (same name, different value) at each secret's target.
	type conflict struct {
		s        exchange.Secret
		existing string
	}
	var conflicts []conflict
	var toApply []exchange.Secret
	identical := 0
	for _, s := range incoming {
		target := targetScope(ctx, s.Origin)
		if existing, ok := currentValue(st, target, s.Name); ok {
			if existing == s.Value {
				identical++
				continue // already have this exact value
			}
			conflicts = append(conflicts, conflict{s, existing})
			continue
		}
		toApply = append(toApply, s)
	}
	kept := 0
	if len(conflicts) > 0 {
		items := make([]checklistItem, len(conflicts))
		for i, c := range conflicts {
			items[i] = checklistItem{
				label:   c.s.Name,
				sub:     fmt.Sprintf("yours %s → theirs %s", previewSecret(c.existing), previewSecret(c.s.Value)),
				checked: false,
			}
		}
		result, confirmed, err := selectItems("Name clashes — check the ones to OVERWRITE with the received value:", items)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("receive cancelled")
		}
		for i, it := range result {
			if it.checked {
				toApply = append(toApply, conflicts[i].s)
			} else {
				kept++
			}
		}
	}

	for _, s := range toApply {
		st.Set(targetScope(ctx, s.Origin), s.Name, s.Value)
	}
	if err := f.save(key, st); err != nil {
		return err
	}
	// Secrets are committed — destroy the one-time key immediately, so a failure
	// in the (non-crypto) steps below can't leave it on disk.
	os.Remove(recPath)

	// Record mappings for every accepted secret in one atomic append so `run`
	// works immediately.
	accepted := map[string]bool{}
	for _, s := range incoming {
		accepted[s.Name] = true
	}
	var mappings []manifest.Entry
	for _, e := range bundle.Entries {
		if accepted[e.StoreKey] {
			mappings = append(mappings, e)
		}
	}
	if err := manifest.AddMappings(ctx.manifestPath, mappings); err != nil {
		return err
	}

	fmt.Printf("Received %d secret(s) into %s. Pending key destroyed.\n", len(toApply), ctx.label())
	if kept > 0 {
		fmt.Printf("Kept your existing value for %d name(s).\n", kept)
	}
	if identical > 0 {
		fmt.Printf("%d name(s) already matched and were left unchanged.\n", identical)
	}
	return nil
}

// --- helpers --------------------------------------------------------------

// targetScope maps a secret's origin to the receiver bucket: local-origin lands
// in the current scope, global-origin in the global bucket (scope "").
func targetScope(ctx scopeCtx, origin exchange.Origin) string {
	if origin == exchange.OriginGlobal {
		return ""
	}
	return ctx.scope
}

// scopeValue reads a value directly from a scope bucket (no global fallback), so
// the caller can tell a scoped secret from a global one.
func scopeValue(st *store.Store, scope, name string) (string, bool) {
	m, ok := st.Scopes[scope]
	if !ok {
		return "", false
	}
	v, ok := m[name]
	return v, ok
}

// currentValue reads the value at an exact location (scope "" = global bucket).
func currentValue(st *store.Store, scope, name string) (string, bool) {
	if scope == "" {
		v, ok := st.Global[name]
		return v, ok
	}
	return scopeValue(st, scope, name)
}

// selectItems runs an interactive checklist on the controlling terminal.
func selectItems(title string, items []checklistItem) ([]checklistItem, bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, false, errors.New("this step needs an interactive terminal")
	}
	defer tty.Close()
	return runChecklist(tty, title, items)
}

// previewSecret renders a value for on-screen checklists: enough to tell two
// entries apart while eliding the middle of anything long enough to hide. It
// shows the first three and last three runes with the middle elided. Values of
// six runes or fewer can't be masked that way (first-3/last-3 would overlap and
// reveal everything), so they're shown in full — a secret that short is already
// weak and should be rotated regardless. Newlines become ⏎ so a multi-line value
// can't break the row or smuggle a real newline into the revealed edges.
func previewSecret(v string) string {
	r := []rune(strings.ReplaceAll(v, "\n", "⏎"))
	switch {
	case len(r) == 0:
		return "(empty)"
	case len(r) <= 6:
		// 7 is the shortest length that still hides at least one middle rune;
		// anything shorter reveals in full whether we like it or not.
		return string(r)
	default:
		return string(r[:3]) + "…" + string(r[len(r)-3:])
	}
}
