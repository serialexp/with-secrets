package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"with-secrets/internal/fido"
	"with-secrets/internal/store"
)

func TestPrintNamesInheritance(t *testing.T) {
	idx := store.Index{
		Global: []string{"GLOBAL_ONLY", "SHARED"},
		Scopes: map[string][]string{
			"kid":    {"KID_ONLY", "SHARED"}, // SHARED shadows parent + global
			"parent": {"PARENT_ONLY", "SHARED"},
		},
	}
	var buf bytes.Buffer
	printNames(&buf, []string{"kid", "parent"}, idx)
	out := buf.String()

	// Nearest scope headed [scope kid]; parent headed [inherited from parent].
	if !strings.Contains(out, "[scope kid]") {
		t.Errorf("missing nearest-scope header:\n%s", out)
	}
	if !strings.Contains(out, "[inherited from parent]") {
		t.Errorf("missing inherited header:\n%s", out)
	}
	if !strings.Contains(out, "[global]") {
		t.Errorf("missing global header:\n%s", out)
	}
	// SHARED appears once (under kid), never repeated for parent/global.
	if n := strings.Count(out, "SHARED"); n != 1 {
		t.Errorf("SHARED shown %d times, want 1 (nearest wins):\n%s", n, out)
	}
	// PARENT_ONLY surfaces as inherited; GLOBAL_ONLY as global.
	if !strings.Contains(out, "PARENT_ONLY") || !strings.Contains(out, "GLOBAL_ONLY") {
		t.Errorf("inherited/global names missing:\n%s", out)
	}
}

func TestPrintNamesEmpty(t *testing.T) {
	var buf bytes.Buffer
	printNames(&buf, nil, store.Index{})
	if !strings.Contains(buf.String(), "No global secrets") {
		t.Errorf("unexpected empty output: %q", buf.String())
	}
}

func TestTouchWithRetrySucceedsFirstTry(t *testing.T) {
	reconnects := 0
	out, err := touchWithRetry(
		func() ([]byte, error) { return []byte("ok"), nil },
		func() bool { reconnects++; return true },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "ok" {
		t.Fatalf("got %q, want %q", out, "ok")
	}
	if reconnects != 0 {
		t.Fatalf("reconnect called %d times, want 0", reconnects)
	}
}

func TestTouchWithRetryRetriesUntilDevicePresent(t *testing.T) {
	attempts := 0
	out, err := touchWithRetry(
		func() ([]byte, error) {
			attempts++
			if attempts < 3 {
				return nil, fido.ErrNoDevice
			}
			return []byte("ok"), nil
		},
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "ok" {
		t.Fatalf("got %q, want %q", out, "ok")
	}
	if attempts != 3 {
		t.Fatalf("op ran %d times, want 3", attempts)
	}
}

func TestTouchWithRetryGivesUp(t *testing.T) {
	attempts := 0
	_, err := touchWithRetry(
		func() ([]byte, error) { attempts++; return nil, fido.ErrNoDevice },
		func() bool { return false }, // user gives up immediately
	)
	if !errors.Is(err, fido.ErrNoDevice) {
		t.Fatalf("got %v, want ErrNoDevice", err)
	}
	if attempts != 1 {
		t.Fatalf("op ran %d times, want 1", attempts)
	}
}

func TestTouchWithRetryPassesThroughOtherErrors(t *testing.T) {
	sentinel := fmt.Errorf("boom")
	reconnects := 0
	_, err := touchWithRetry(
		func() ([]byte, error) { return nil, sentinel },
		func() bool { reconnects++; return true },
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want sentinel", err)
	}
	if reconnects != 0 {
		t.Fatalf("reconnect called %d times, want 0 (only retry on ErrNoDevice)", reconnects)
	}
}

func TestParseGetArgs(t *testing.T) {
	cases := []struct {
		args      []string
		wantName  string
		wantForce bool
		wantErr   bool
	}{
		{[]string{"API_KEY"}, "API_KEY", false, false},
		{[]string{"API_KEY", "-f"}, "API_KEY", true, false},
		{[]string{"-f", "API_KEY"}, "API_KEY", true, false},
		{[]string{"--force", "API_KEY"}, "API_KEY", true, false},
		{[]string{}, "", false, true},         // no name
		{[]string{"-f"}, "", false, true},     // flag but no name
		{[]string{"A", "B"}, "", false, true}, // two names
		{[]string{"A", "B", "-f"}, "", false, true},
	}
	for _, c := range cases {
		name, force, err := parseGetArgs(c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("parseGetArgs(%v) err = %v, wantErr %v", c.args, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if name != c.wantName || force != c.wantForce {
			t.Errorf("parseGetArgs(%v) = (%q,%v), want (%q,%v)", c.args, name, force, c.wantName, c.wantForce)
		}
	}
}

// feed runs each byte of in through a fresh maskState and returns the final
// buffer, the concatenated terminal output, and whether a line-complete
// (Enter) was seen.
func feed(in string) (buf string, emitted string, done bool, err error) {
	var m maskState
	for i := 0; i < len(in); i++ {
		e, d, serr := m.step(in[i])
		emitted += e
		if serr != nil {
			return string(m.buf), emitted, false, serr
		}
		if d {
			return string(m.buf), emitted, true, nil
		}
	}
	return string(m.buf), emitted, false, nil
}

func TestMaskBasic(t *testing.T) {
	buf, emitted, done, err := feed("abc\r")
	if err != nil {
		t.Fatal(err)
	}
	if !done {
		t.Error("expected done on carriage return")
	}
	if buf != "abc" {
		t.Errorf("buf = %q, want %q", buf, "abc")
	}
	if emitted != "***" {
		t.Errorf("emitted = %q, want %q", emitted, "***")
	}
}

func TestMaskNewlineTerminates(t *testing.T) {
	buf, _, done, err := feed("hi\n")
	if err != nil || !done || buf != "hi" {
		t.Fatalf("buf=%q done=%v err=%v", buf, done, err)
	}
}

func TestMaskBackspace(t *testing.T) {
	buf, emitted, _, err := feed("ab\x7fc\r")
	if err != nil {
		t.Fatal(err)
	}
	if buf != "ac" {
		t.Errorf("buf = %q, want %q", buf, "ac")
	}
	// two stars, an erase, then one star.
	if emitted != "**\b \b*" {
		t.Errorf("emitted = %q", emitted)
	}
}

func TestMaskBackspaceOnEmpty(t *testing.T) {
	buf, emitted, _, err := feed("\x7f\x7fx\r")
	if err != nil {
		t.Fatal(err)
	}
	if buf != "x" {
		t.Errorf("buf = %q, want %q", buf, "x")
	}
	if emitted != "*" {
		t.Errorf("emitted = %q, want a single star", emitted)
	}
}

func TestMaskCtrlUClearsLine(t *testing.T) {
	buf, emitted, _, err := feed("abc\x15de\r")
	if err != nil {
		t.Fatal(err)
	}
	if buf != "de" {
		t.Errorf("buf = %q, want %q", buf, "de")
	}
	// ***, then three erases, then **.
	want := "***" + "\b \b\b \b\b \b" + "**"
	if emitted != want {
		t.Errorf("emitted = %q, want %q", emitted, want)
	}
}

func TestMaskIgnoresControlChars(t *testing.T) {
	buf, emitted, _, err := feed("a\x01\x02b\r") // Ctrl-A, Ctrl-B ignored
	if err != nil {
		t.Fatal(err)
	}
	if buf != "ab" {
		t.Errorf("buf = %q, want %q", buf, "ab")
	}
	if emitted != "**" {
		t.Errorf("emitted = %q, want %q", emitted, "**")
	}
}

func TestMaskUTF8OneStarPerRune(t *testing.T) {
	// "é" = 0xC3 0xA9 (2 bytes), "€" = 0xE2 0x82 0xAC (3 bytes).
	buf, emitted, _, err := feed("a\xc3\xa9\xe2\x82\xac\r")
	if err != nil {
		t.Fatal(err)
	}
	if buf != "aé€" {
		t.Errorf("buf = %q, want %q", buf, "aé€")
	}
	if emitted != "***" { // one star per rune, not per byte
		t.Errorf("emitted = %q, want three stars", emitted)
	}
}

func TestMaskUTF8Backspace(t *testing.T) {
	// Type "é" then backspace should remove both bytes.
	buf, _, _, err := feed("a\xc3\xa9\x7f\r")
	if err != nil {
		t.Fatal(err)
	}
	if buf != "a" {
		t.Errorf("buf = %q, want %q", buf, "a")
	}
}

func TestMaskCtrlCInterrupts(t *testing.T) {
	_, _, _, err := feed("ab\x03")
	if !errors.Is(err, errInterrupted) {
		t.Errorf("err = %v, want errInterrupted", err)
	}
}
