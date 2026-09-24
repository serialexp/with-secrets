package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	in := `
# @scope acme-api
# project secrets
AWS_SECRET_ACCESS_KEY=aws/prod/secret
DB_PASSWORD = db/main/password    # inline comment
STRIPE_KEY        # shorthand, key == env var

_LEADING_UNDERSCORE=x
`
	m, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope != "acme-api" {
		t.Errorf("scope = %q, want %q", m.Scope, "acme-api")
	}
	want := []Entry{
		{"AWS_SECRET_ACCESS_KEY", "aws/prod/secret"},
		{"DB_PASSWORD", "db/main/password"},
		{"STRIPE_KEY", "STRIPE_KEY"},
		{"_LEADING_UNDERSCORE", "x"},
	}
	if len(m.Entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(m.Entries), len(want), m.Entries)
	}
	for i := range want {
		if m.Entries[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, m.Entries[i], want[i])
		}
	}
}

func TestParseNoScope(t *testing.T) {
	m, err := Parse(strings.NewReader("FOO=bar\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope != "" {
		t.Errorf("scope = %q, want empty", m.Scope)
	}
}

func TestParseEmptyScopeDirectiveErrors(t *testing.T) {
	if _, err := Parse(strings.NewReader("# @scope\n")); err == nil {
		t.Error("expected error for empty @scope directive")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"invalid env name (dash)":  "MY-VAR=x",
		"invalid env name (digit)": "1VAR=x",
		"empty key after equals":   "FOO=",
		"empty env before equals":  "=bar",
		"duplicate env var":        "FOO=a\nFOO=b",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); err == nil {
				t.Errorf("expected error for %q", in)
			}
		})
	}
}

func TestFindUp(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "a", DefaultName)
	if err := os.WriteFile(manifestPath, []byte("# @scope x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := FindUp(sub)
	if err != nil {
		t.Fatal(err)
	}
	if got != manifestPath {
		t.Errorf("FindUp = %q, want %q", got, manifestPath)
	}

	// Nothing above a fresh temp dir with no manifest.
	if _, err := FindUp(t.TempDir()); !os.IsNotExist(err) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}
}

func TestCreateAndAddEntry(t *testing.T) {
	dir := t.TempDir()
	path, err := Create(dir, "myscope")
	if err != nil {
		t.Fatal(err)
	}

	// Creating again must fail.
	if _, err := Create(dir, "again"); err == nil {
		t.Error("expected Create to fail when manifest exists")
	}

	if err := AddEntry(path, "DATABASE_URL"); err != nil {
		t.Fatal(err)
	}
	if err := AddEntry(path, "STRIPE_KEY"); err != nil {
		t.Fatal(err)
	}
	// Duplicate add is a no-op.
	if err := AddEntry(path, "DATABASE_URL"); err != nil {
		t.Fatal(err)
	}

	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope != "myscope" {
		t.Errorf("scope = %q, want myscope", m.Scope)
	}
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %+v, want 2 (no duplicate)", m.Entries)
	}
	got := map[string]bool{}
	for _, e := range m.Entries {
		got[e.EnvVar] = true
		if e.StoreKey != e.EnvVar {
			t.Errorf("AddEntry should write shorthand; got %+v", e)
		}
	}
	if !got["DATABASE_URL"] || !got["STRIPE_KEY"] {
		t.Errorf("missing expected entries: %+v", m.Entries)
	}
}

func TestParseExtends(t *testing.T) {
	m, err := Parse(strings.NewReader("# @scope kid\n# @extends ../..\nFOO\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Extends != "../.." {
		t.Errorf("extends = %q, want ../..", m.Extends)
	}
	if m.Scope != "kid" {
		t.Errorf("scope = %q, want kid", m.Scope)
	}
}

func TestParseExtendsErrors(t *testing.T) {
	cases := map[string]string{
		"empty ref":       "# @extends\n",
		"empty ref space": "# @extends   \n",
		"duplicate":       "# @extends ..\n# @extends ../..\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); err == nil {
				t.Errorf("expected error for %q", in)
			}
		})
	}
}

// writeManifest writes dir/.secrets with the given body, creating dir.
func writeManifest(t *testing.T, dir, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, DefaultName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestChain(t *testing.T) {
	root := t.TempDir()
	// grand (root) <- parent <- child, each extends the dir above it.
	writeManifest(t, root, "# @scope grand\nG\n")
	writeManifest(t, filepath.Join(root, "p"), "# @scope parent\n# @extends ..\nP\n")
	childDir := filepath.Join(root, "p", "c")
	writeManifest(t, childDir, "# @scope kid\n# @extends ..\nC\n")

	links, err := Chain(childDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 3 {
		t.Fatalf("got %d links, want 3: %+v", len(links), links)
	}
	wantScopes := []string{"kid", "parent", "grand"}
	if got := Scopes(links); !equalStrings(got, wantScopes) {
		t.Errorf("Scopes = %v, want %v", got, wantScopes)
	}

	// MergedEntries: nearest-first, union.
	merged := MergedEntries(links)
	var envs []string
	for _, e := range merged {
		envs = append(envs, e.EnvVar)
	}
	if !equalStrings(envs, []string{"C", "P", "G"}) {
		t.Errorf("MergedEntries order = %v, want [C P G]", envs)
	}
}

func TestChainNearestWinsOnConflict(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "# @scope parent\nSHARED=parent/key\n")
	childDir := filepath.Join(root, "c")
	writeManifest(t, childDir, "# @scope kid\n# @extends ..\nSHARED=kid/key\n")

	links, err := Chain(childDir)
	if err != nil {
		t.Fatal(err)
	}
	merged := MergedEntries(links)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged entry, got %+v", merged)
	}
	if merged[0].StoreKey != "kid/key" {
		t.Errorf("child should win: got %+v", merged[0])
	}
}

func TestChainNoManifest(t *testing.T) {
	if _, err := Chain(t.TempDir()); !os.IsNotExist(err) {
		t.Errorf("want ErrNotExist, got %v", err)
	}
}

func TestChainMissingParent(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "# @extends ../nowhere\nFOO\n")
	if _, err := Chain(dir); err == nil {
		t.Error("expected error when @extends points at a dir with no .secrets")
	}
}

func TestChainCycle(t *testing.T) {
	root := t.TempDir()
	// a/.secrets extends b, b/.secrets extends a — a cycle.
	writeManifest(t, filepath.Join(root, "a"), "# @extends ../b\nA\n")
	writeManifest(t, filepath.Join(root, "b"), "# @extends ../a\nB\n")
	if _, err := Chain(filepath.Join(root, "a")); err == nil {
		t.Error("expected cycle error")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestInlineCommentStripping(t *testing.T) {
	m, err := Parse(strings.NewReader("FOO=bar#nospace"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 1 || m.Entries[0].StoreKey != "bar" {
		t.Fatalf("inline comment not stripped: %+v", m.Entries)
	}
}

func TestAddMapping(t *testing.T) {
	dir := t.TempDir()
	path, err := Create(dir, "acme")
	if err != nil {
		t.Fatal(err)
	}

	// Shorthand when env == store key.
	if err := AddEntry(path, "DB_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	// Full form when they differ.
	if err := AddMapping(path, "AWS_SECRET_ACCESS_KEY", "aws/prod/secret"); err != nil {
		t.Fatal(err)
	}
	// Idempotent: adding the same env var again is a no-op.
	if err := AddMapping(path, "AWS_SECRET_ACCESS_KEY", "aws/prod/other"); err != nil {
		t.Fatal(err)
	}

	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope != "acme" {
		t.Errorf("scope = %q", m.Scope)
	}
	want := map[string]string{
		"DB_PASSWORD":           "DB_PASSWORD",
		"AWS_SECRET_ACCESS_KEY": "aws/prod/secret", // first mapping wins; no duplicate
	}
	if len(m.Entries) != len(want) {
		t.Fatalf("entries = %+v, want %d", m.Entries, len(want))
	}
	for _, e := range m.Entries {
		if want[e.EnvVar] != e.StoreKey {
			t.Errorf("entry %s = %q, want %q", e.EnvVar, e.StoreKey, want[e.EnvVar])
		}
	}
}

func TestAddMappings(t *testing.T) {
	dir := t.TempDir()
	path, err := Create(dir, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := AddEntry(path, "EXISTING"); err != nil {
		t.Fatal(err)
	}

	// Batch: one already present, one duplicate within the batch, one full form.
	batch := []Entry{
		{EnvVar: "EXISTING", StoreKey: "EXISTING"},   // skipped: already present
		{EnvVar: "TOKEN", StoreKey: "TOKEN"},         // shorthand
		{EnvVar: "AWS", StoreKey: "aws/prod/secret"}, // full form
		{EnvVar: "TOKEN", StoreKey: "different"},     // dup in batch: ignored
	}
	if err := AddMappings(path, batch); err != nil {
		t.Fatal(err)
	}

	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"EXISTING": "EXISTING",
		"TOKEN":    "TOKEN",
		"AWS":      "aws/prod/secret",
	}
	if len(m.Entries) != len(want) {
		t.Fatalf("entries = %+v, want %d", m.Entries, len(want))
	}
	for _, e := range m.Entries {
		if want[e.EnvVar] != e.StoreKey {
			t.Errorf("entry %s = %q, want %q", e.EnvVar, e.StoreKey, want[e.EnvVar])
		}
	}

	// Empty/all-present batch is a no-op that doesn't error.
	if err := AddMappings(path, []Entry{{EnvVar: "TOKEN", StoreKey: "TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	if m2, _ := Load(path); len(m2.Entries) != len(want) {
		t.Errorf("no-op batch changed entries to %+v", m2.Entries)
	}
}
