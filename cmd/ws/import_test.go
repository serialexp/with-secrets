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
	mk(".env.example", "A=\n")            // template: skipped
	mk(".env.bak", "OLD=x\n")             // our own backup: skipped
	mk("app/.env", "C=3\n")               // nested: found
	mk("node_modules/pkg/.env", "D=4\n")  // skipped dir
	mk("notenv.txt", "E=5\n")             // not a .env

	got, err := discoverEnvFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		filepath.Join(root, ".env"):       true,
		filepath.Join(root, ".env.local"): true,
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

func TestValuePreview(t *testing.T) {
	if valuePreview("") != "(empty)" {
		t.Error("empty preview")
	}
	long := valuePreview(string(make([]byte, 0)) + "0123456789012345678901234567890123456789")
	if []rune(long)[len([]rune(long))-1] != '…' {
		t.Errorf("long value should be truncated with ellipsis: %q", long)
	}
	if valuePreview("line1\nline2") != "line1⏎line2" {
		t.Error("newlines should be shown as ⏎")
	}
}
