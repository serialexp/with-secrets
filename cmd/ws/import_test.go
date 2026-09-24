package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLooksSecret(t *testing.T) {
	secret := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "x",
		"GITHUB_TOKEN":          "x",
		"DB_PASSWORD":           "x",
		"STRIPE_API_KEY":        "x",
		"SESSION_SECRET":        "x",
		"DATABASE_DSN":          "x",
	}
	for name, val := range secret {
		if !looksSecret(name, val) {
			t.Errorf("looksSecret(%q) = false, want true", name)
		}
	}

	notSecret := map[string]string{
		"NODE_ENV":            "production",
		"PORT":                "3000",
		"NEXT_PUBLIC_API_KEY": "pk_live_visible", // public prefix beats KEY hint
		"VITE_APP_TITLE":      "My App",
		"LOG_LEVEL":           "debug",
	}
	for name, val := range notSecret {
		if looksSecret(name, val) {
			t.Errorf("looksSecret(%q) = true, want false", name)
		}
	}
}

func TestHighEntropyValue(t *testing.T) {
	// No secret-y name, but a long mixed-charset value should be pre-checked.
	if !looksSecret("RANDO", "aB3xK9mQ2pL7wZ4nR8tV1cY") {
		t.Error("high-entropy value should look secret")
	}
	if looksSecret("GREETING", "hello there friend") {
		t.Error("low-entropy prose should not look secret")
	}
	if looksSecret("SHORT", "aB3x") {
		t.Error("short value should not trip entropy check")
	}
}

func TestResolveSelected(t *testing.T) {
	sel := []envVar{
		{key: "A", value: "1", file: "a"},
		{key: "B", value: "2", file: "a"},
		{key: "A", value: "1", file: "b"}, // same key+value across files: fine
	}
	values, conflicts := resolveSelected(sel)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if values["A"] != "1" || values["B"] != "2" || len(values) != 2 {
		t.Fatalf("values = %v", values)
	}

	sel = append(sel, envVar{key: "A", value: "different", file: "c"})
	_, conflicts = resolveSelected(sel)
	if len(conflicts) != 1 || conflicts[0] != "A" {
		t.Fatalf("conflicts = %v, want [A]", conflicts)
	}
}

func TestDiscoverEnvFiles(t *testing.T) {
	root := t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk(".env", "A=1\n")
	mk(".env.local", "B=2\n")
	mk(".env.example", "A=\n")           // template: skipped
	mk(".env.bak", "OLD=x\n")            // our own backup: skipped
	mk("app/.env", "C=3\n")              // nested: found
	mk("node_modules/pkg/.env", "D=4\n") // skipped dir
	mk(".pnpm-store/x/.env", "F=6\n")    // skipped dir
	mk(".next/standalone/.env", "G=7\n") // skipped dir
	mk("notenv.txt", "E=5\n")            // not a .env

	var entered []string
	got, err := discoverEnvFiles(root, false, func(dir string) { entered = append(entered, dir) })
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		filepath.Join(root, ".env"):        true,
		filepath.Join(root, ".env.local"):  true,
		filepath.Join(root, "app", ".env"): true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d files", got, len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected file discovered: %s", p)
		}
	}

	// onEnter fires for the root and the descended app dir, but never for a
	// skipped dir like node_modules.
	seenApp, seenNodeMods := false, false
	for _, d := range entered {
		if d == filepath.Join(root, "app") {
			seenApp = true
		}
		if d == filepath.Join(root, "node_modules") {
			seenNodeMods = true
		}
	}
	if !seenApp {
		t.Errorf("onEnter should have reported the app dir; got %v", entered)
	}
	if seenNodeMods {
		t.Errorf("onEnter should not report skipped node_modules; got %v", entered)
	}

	// --all disables every auto-ignore: templates, backups, and skipped dirs
	// all come through.
	all, err := discoverEnvFiles(root, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	allWant := []string{
		filepath.Join(root, ".env"),
		filepath.Join(root, ".env.local"),
		filepath.Join(root, ".env.example"),
		filepath.Join(root, ".env.bak"),
		filepath.Join(root, "app", ".env"),
		filepath.Join(root, "node_modules", "pkg", ".env"),
		filepath.Join(root, ".pnpm-store", "x", ".env"),
		filepath.Join(root, ".next", "standalone", ".env"),
	}
	allGot := map[string]bool{}
	for _, p := range all {
		allGot[p] = true
	}
	for _, w := range allWant {
		if !allGot[w] {
			t.Errorf("--all should have found %s; got %v", w, all)
		}
	}
}

func TestParseImportArgs(t *testing.T) {
	cases := []struct {
		args    []string
		wantDir string
		wantAll bool
		wantErr bool
	}{
		{nil, ".", false, false},
		{[]string{"sub"}, "sub", false, false},
		{[]string{"--all"}, ".", true, false},
		{[]string{"sub", "--all"}, "sub", true, false},
		{[]string{"--all", "sub"}, "sub", true, false},
		{[]string{"a", "b"}, "", false, true}, // two dirs
	}
	for _, c := range cases {
		dir, all, err := parseImportArgs(c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("parseImportArgs(%v) err = %v, wantErr %v", c.args, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if dir != c.wantDir || all != c.wantAll {
			t.Errorf("parseImportArgs(%v) = (%q,%v), want (%q,%v)", c.args, dir, all, c.wantDir, c.wantAll)
		}
	}
}

func TestKeyCollisions(t *testing.T) {
	vars := []envVar{
		{key: "SAME", value: "x", file: "a"},
		{key: "SAME", value: "x", file: "b"}, // same value across files: not a collision
		{key: "DB_URL", value: "prod", file: "a"},
		{key: "DB_URL", value: "dev", file: "b"},
		{key: "DB_URL", value: "dev", file: "c"}, // two distinct values (prod / dev)
		{key: "SOLO", value: "only", file: "a"},  // single occurrence: not a collision
	}
	got := keyCollisions(vars)
	if len(got) != 1 {
		t.Fatalf("got %d collisions, want 1: %+v", len(got), got)
	}
	c := got[0]
	if c.key != "DB_URL" {
		t.Fatalf("collision key = %q, want DB_URL", c.key)
	}
	if len(c.byValue) != 2 {
		t.Fatalf("want 2 distinct values, got %+v", c.byValue)
	}
	// First-seen order: prod (file a) then dev (files b, c).
	if c.byValue[0].value != "prod" || len(c.byValue[0].files) != 1 {
		t.Errorf("first value = %+v, want prod in 1 file", c.byValue[0])
	}
	if c.byValue[1].value != "dev" || len(c.byValue[1].files) != 2 {
		t.Errorf("second value = %+v, want dev in 2 files", c.byValue[1])
	}
}

func TestKeyCollisionsNoneWhenConsistent(t *testing.T) {
	vars := []envVar{
		{key: "A", value: "1", file: "x"},
		{key: "A", value: "1", file: "y"},
		{key: "B", value: "2", file: "x"},
	}
	if got := keyCollisions(vars); len(got) != 0 {
		t.Fatalf("expected no collisions, got %+v", got)
	}
}

func TestStripFromEnvFiles(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	original := "# header\nSECRET=shh\nKEEP=me\n"
	if err := os.WriteFile(envPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// KEEP remains, so no empty-file prompt is triggered.
	backups, err := stripFromEnvFiles(root, []envVar{{key: "SECRET", value: "shh", file: envPath}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# header\nKEEP=me\n" {
		t.Errorf("rewritten .env = %q", got)
	}

	if len(backups) != 1 {
		t.Fatalf("want 1 backup, got %v", backups)
	}
	bak, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(bak) != original {
		t.Errorf("backup should hold the original verbatim, got %q", bak)
	}
}
