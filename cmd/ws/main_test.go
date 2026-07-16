package main

import (
	"errors"
	"testing"
)

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
