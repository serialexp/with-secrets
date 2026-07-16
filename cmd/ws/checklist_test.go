package main

import "testing"

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

func TestDecodeKeys(t *testing.T) {
	cases := []struct {
		in   []byte
		want []key
	}{
		{[]byte{0x1b, '[', 'A'}, []key{kUp}},
		{[]byte{0x1b, '[', 'B'}, []key{kDown}},
		{[]byte("jk"), []key{kDown, kUp}},
		{[]byte(" "), []key{kToggle}},
		{[]byte("a"), []key{kToggleAll}},
		{[]byte("\r"), []key{kConfirm}},
		{[]byte("q"), []key{kCancel}},
		{[]byte{0x1b}, []key{kCancel}}, // lone ESC
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
