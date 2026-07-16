package dotenv

import (
	"strings"
	"testing"
)

func TestParseValues(t *testing.T) {
	in := `# a comment
export FOO=bar
BAZ = qux
QUOTED="hello world"
SINGLE='raw $notexpanded'
EMPTY=
WITHHASH=abc # trailing comment
HASHNOSPACE=a#b
DQESC="line1\nline2\ttab"
NUM=12345

INVALID KEY=nope
lowercase_ok=1
`
	f, err := Parse(".env", strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range f.Entries {
		got[e.Key] = e.Value
	}
	want := map[string]string{
		"FOO":          "bar",
		"BAZ":          "qux",
		"QUOTED":       "hello world",
		"SINGLE":       "raw $notexpanded",
		"EMPTY":        "",
		"WITHHASH":     "abc",
		"HASHNOSPACE":  "a#b", // no space before # -> not a comment
		"DQESC":        "line1\nline2\ttab",
		"NUM":          "12345",
		"lowercase_ok": "1",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %v, want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["INVALID"]; ok {
		t.Error("key with a space must be skipped")
	}
}

func TestParseLineNumbers(t *testing.T) {
	f, _ := Parse(".env", strings.NewReader("# c\nFOO=1\n\nBAR=2\n"))
	if len(f.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(f.Entries))
	}
	if f.Entries[0].Line != 2 || f.Entries[1].Line != 4 {
		t.Errorf("line numbers = %d,%d want 2,4", f.Entries[0].Line, f.Entries[1].Line)
	}
}

func TestWithoutPreservesVerbatim(t *testing.T) {
	in := "# header\nFOO=bar\nSECRET=shh\nKEEP=me\n"
	f, _ := Parse(".env", strings.NewReader(in))
	out := f.Without(map[string]bool{"SECRET": true, "FOO": true})
	if out != "# header\nKEEP=me\n" {
		t.Errorf("Without =\n%q", out)
	}
}

func TestWithoutDuplicateKeys(t *testing.T) {
	f, _ := Parse(".env", strings.NewReader("A=1\nB=2\nA=3\n"))
	if len(f.Entries) != 3 {
		t.Fatalf("want 3 entries (dup A), got %d", len(f.Entries))
	}
	out := f.Without(map[string]bool{"A": true})
	if out != "B=2\n" {
		t.Errorf("both A lines should go; got %q", out)
	}
}

func TestWithoutEmptyResult(t *testing.T) {
	f, _ := Parse(".env", strings.NewReader("ONLY=1\n"))
	if out := f.Without(map[string]bool{"ONLY": true}); out != "" {
		t.Errorf("want empty string, got %q", out)
	}
}

func TestRemainingIsEmpty(t *testing.T) {
	f, _ := Parse(".env", strings.NewReader("# just a comment\nFOO=bar\n\n"))
	if !f.RemainingIsEmpty(map[string]bool{"FOO": true}) {
		t.Error("only comment/blank should remain after removing FOO")
	}
	if f.RemainingIsEmpty(map[string]bool{}) {
		t.Error("FOO still present -> not empty")
	}
}
