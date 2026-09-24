package main

import (
	"testing"
	"unicode/utf8"
)

func items(n int) []checklistItem {
	out := make([]checklistItem, n)
	for i := range out {
		out[i].label = string(rune('A' + i))
	}
	return out
}

func TestChecklistMoveClamps(t *testing.T) {
	c := &checklist{items: items(3)}
	c.apply(kUp) // already at top
	if c.cursor != 0 {
		t.Fatalf("cursor = %d, want 0", c.cursor)
	}
	c.apply(kDown)
	c.apply(kDown)
	c.apply(kDown) // past the end
	if c.cursor != 2 {
		t.Fatalf("cursor = %d, want 2 (clamped)", c.cursor)
	}
}

func TestChecklistToggle(t *testing.T) {
	c := &checklist{items: items(3)}
	c.apply(kDown)
	c.apply(kToggle)
	if !c.items[1].checked || c.items[0].checked || c.items[2].checked {
		t.Fatalf("only row 1 should be checked: %+v", c.items)
	}
	c.apply(kToggle)
	if c.items[1].checked {
		t.Fatal("toggling again should uncheck")
	}
}

func TestChecklistToggleAll(t *testing.T) {
	c := &checklist{items: items(3)}
	c.apply(kToggleAll) // none checked -> all on
	for i, it := range c.items {
		if !it.checked {
			t.Fatalf("row %d not checked after toggle-all-on", i)
		}
	}
	c.apply(kToggleAll) // all checked -> all off
	for i, it := range c.items {
		if it.checked {
			t.Fatalf("row %d still checked after toggle-all-off", i)
		}
	}
	// Mixed state -> toggle-all turns everything on.
	c.items[0].checked = true
	c.apply(kToggleAll)
	for i, it := range c.items {
		if !it.checked {
			t.Fatalf("row %d not checked after toggle-all from mixed", i)
		}
	}
}

func TestChecklistConfirmCancel(t *testing.T) {
	c := &checklist{items: items(2)}
	if c.apply(kConfirm) != clConfirm {
		t.Error("enter should confirm")
	}
	if c.apply(kCancel) != clCancel {
		t.Error("q/esc should cancel")
	}
	if c.apply(kDown) != clContinue {
		t.Error("movement should continue")
	}
}

func TestClampScroll(t *testing.T) {
	const visible = 5
	c := &checklist{items: items(20)}

	// Cursor within the initial window: no scroll.
	c.cursor = 3
	c.clampScroll(visible)
	if c.top != 0 {
		t.Fatalf("top = %d, want 0 (cursor still on screen)", c.top)
	}

	// Cursor past the bottom edge: window follows so cursor is the last row.
	c.cursor = 7
	c.clampScroll(visible)
	if c.top != 3 { // rows 3..7 visible
		t.Fatalf("top = %d, want 3", c.top)
	}

	// Cursor back above the window: top snaps to cursor.
	c.cursor = 2
	c.clampScroll(visible)
	if c.top != 2 {
		t.Fatalf("top = %d, want 2", c.top)
	}

	// Cursor at the very end: top clamps to len-visible, never beyond.
	c.cursor = 19
	c.clampScroll(visible)
	if c.top != 15 {
		t.Fatalf("top = %d, want 15", c.top)
	}
}

func TestClampScrollShorterThanWindow(t *testing.T) {
	c := &checklist{items: items(3)}
	c.cursor = 2
	c.clampScroll(10) // window bigger than the list
	if c.top != 0 {
		t.Fatalf("top = %d, want 0 (everything fits)", c.top)
	}
}

func TestTruncVisible(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"}, // fits
		{"hello", 5, "hello"},  // exact
		{"hello", 4, "hel…"},   // cut with ellipsis
		{"hello", 1, "…"},      // only the ellipsis fits
		{"hello", 0, ""},       // no room
		{"héllo", 3, "hé…"},    // multi-byte runes counted by rune, not byte
	}
	for _, c := range cases {
		if got := truncVisible(c.in, c.max); got != c.want {
			t.Errorf("truncVisible(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestFitRow(t *testing.T) {
	// width 0 => unknown size, no truncation.
	if l, s := fitRow("LABEL", "sub", 0); l != "LABEL" || s != "sub" {
		t.Errorf("width 0 changed row: %q %q", l, s)
	}

	// Comfortable width: both kept whole. prefix(6)+label(5)+gap(2)+sub(3)=16 < 40.
	if l, s := fitRow("LABEL", "sub", 40); l != "LABEL" || s != "sub" {
		t.Errorf("wide term truncated: %q %q", l, s)
	}

	// Sub trimmed first when it doesn't all fit; label kept whole.
	l, s := fitRow("LABEL", "0123456789", 20)
	if l != "LABEL" {
		t.Errorf("label should stay whole: %q", l)
	}
	// avail = 20-1-6 = 13; subBudget = 13-5-2 = 6 -> "01234…"
	if s != "01234…" {
		t.Errorf("sub = %q, want %q", s, "01234…")
	}

	// Label itself too long: label truncated, sub dropped entirely.
	l, s = fitRow("THIS_IS_A_VERY_LONG_LABEL", "sub", 20)
	if s != "" {
		t.Errorf("sub should be dropped when label overflows, got %q", s)
	}
	if utf8.RuneCountInString(l) > 20 {
		t.Errorf("truncated label still too wide: %q", l)
	}
}

func TestChecklistPaging(t *testing.T) {
	c := &checklist{items: items(20), page: 5}

	c.apply(kPageDown)
	if c.cursor != 5 {
		t.Fatalf("PageDown cursor = %d, want 5", c.cursor)
	}
	c.apply(kEnd)
	if c.cursor != 19 {
		t.Fatalf("End cursor = %d, want 19", c.cursor)
	}
	c.apply(kPageDown) // already at the end: clamps, no overshoot
	if c.cursor != 19 {
		t.Fatalf("PageDown past end = %d, want 19", c.cursor)
	}
	c.apply(kPageUp)
	if c.cursor != 14 {
		t.Fatalf("PageUp cursor = %d, want 14", c.cursor)
	}
	c.apply(kHome)
	if c.cursor != 0 {
		t.Fatalf("Home cursor = %d, want 0", c.cursor)
	}
	c.apply(kPageUp) // at the top: clamps at 0
	if c.cursor != 0 {
		t.Fatalf("PageUp past top = %d, want 0", c.cursor)
	}
}

func TestPageStepDefaultsToOne(t *testing.T) {
	c := &checklist{items: items(10)} // page unset (0)
	c.apply(kPageDown)
	if c.cursor != 1 {
		t.Fatalf("PageDown with unset page = %d, want 1", c.cursor)
	}
}

func TestDecodeKeys(t *testing.T) {
	cases := []struct {
		in   []byte
		want []key
	}{
		{[]byte{0x1b, '[', 'A'}, []key{kUp}},
		{[]byte{0x1b, '[', 'B'}, []key{kDown}},
		{[]byte{0x1b, '[', '5', '~'}, []key{kPageUp}},   // Page Up
		{[]byte{0x1b, '[', '6', '~'}, []key{kPageDown}}, // Page Down
		{[]byte{0x1b, '[', 'H'}, []key{kHome}},          // Home (letter form)
		{[]byte{0x1b, '[', 'F'}, []key{kEnd}},           // End (letter form)
		{[]byte{0x1b, '[', '1', '~'}, []key{kHome}},     // Home (numeric form)
		{[]byte{0x1b, '[', '4', '~'}, []key{kEnd}},      // End (numeric form)
		{[]byte{0x1b, '[', '3', '~'}, nil},              // Delete: unmapped, no spurious cancel
		{[]byte{0x1b, '[', 'C'}, nil},                   // right arrow: ignored
		// A PageDown followed by 'j' must decode both, not swallow or garble.
		{[]byte{0x1b, '[', '6', '~', 'j'}, []key{kPageDown, kDown}},
		{[]byte("jk"), []key{kDown, kUp}},
		{[]byte(" "), []key{kToggle}},
		{[]byte("a"), []key{kToggleAll}},
		{[]byte("\r"), []key{kConfirm}},
		{[]byte("q"), []key{kCancel}},
		{[]byte{0x1b}, []key{kCancel}}, // lone ESC
		{[]byte{0x1b, '['}, nil},       // incomplete CSI at buffer end: dropped
		{[]byte{3}, []key{kCancel}},    // Ctrl-C
		{[]byte("x"), nil},             // unmapped
	}
	for _, tc := range cases {
		got := decodeKeys(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("decodeKeys(%v) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("decodeKeys(%v)[%d] = %v, want %v", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
