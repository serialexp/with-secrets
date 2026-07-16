package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// checklistItem is one selectable row.
type checklistItem struct {
	label   string // primary text (e.g. the env var name)
	sub     string // dim trailing text (e.g. value preview + source path)
	checked bool
}

// checklist is the pure state behind the interactive multi-select: no terminal
// I/O, so its behaviour is unit-testable. Key decoding and rendering live in the
// tty layer below.
type checklist struct {
	items  []checklistItem
	cursor int
}

type key int

const (
	kNone key = iota
	kUp
	kDown
	kToggle
	kToggleAll
	kConfirm
	kCancel
)

type clStatus int

const (
	clContinue clStatus = iota
	clConfirm
	clCancel
)

// apply mutates the checklist for one key and reports whether the interaction is
// done (confirmed or cancelled).
func (c *checklist) apply(k key) clStatus {
	switch k {
	case kUp:
		if c.cursor > 0 {
			c.cursor--
		}
	case kDown:
		if c.cursor < len(c.items)-1 {
			c.cursor++
		}
	case kToggle:
		if len(c.items) > 0 {
			c.items[c.cursor].checked = !c.items[c.cursor].checked
		}
	case kToggleAll:
		allChecked := true
		for _, it := range c.items {
			if !it.checked {
				allChecked = false
				break
			}
		}
		for i := range c.items {
			c.items[i].checked = !allChecked
		}
	case kConfirm:
		return clConfirm
	case kCancel:
		return clCancel
	}
	return clContinue
}

// decodeKeys translates a raw input buffer into higher-level keys, handling ANSI
// arrow sequences (ESC [ A/B), vi keys, and control chars.
func decodeKeys(b []byte) []key {
	var out []key
	for i := 0; i < len(b); i++ {
		switch c := b[i]; c {
		case 0x1b: // ESC: arrow sequence or a lone Escape (cancel)
			if i+2 < len(b) && b[i+1] == '[' {
				switch b[i+2] {
				case 'A':
					out = append(out, kUp)
					i += 2
					continue
				case 'B':
					out = append(out, kDown)
					i += 2
					continue
				case 'C', 'D': // left/right: ignore
					i += 2
					continue
				}
			}
			out = append(out, kCancel)
		case 'k', 16: // k, Ctrl-P
			out = append(out, kUp)
		case 'j', 14: // j, Ctrl-N
			out = append(out, kDown)
		case ' ':
			out = append(out, kToggle)
		case 'a', 'A':
			out = append(out, kToggleAll)
		case '\r', '\n':
			out = append(out, kConfirm)
		case 'q', 3: // q, Ctrl-C
			out = append(out, kCancel)
		}
	}
	return out
}

// runChecklist renders an interactive multi-select on tty and returns the items
// with their final checked state plus whether the user confirmed (vs cancelled).
func runChecklist(tty *os.File, title string, items []checklistItem) ([]checklistItem, bool, error) {
	if len(items) == 0 {
		return items, false, nil
	}
	fd := int(tty.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, false, err
	}
	defer term.Restore(fd, old)

	c := &checklist{items: items}
	fmt.Fprintf(tty, "%s\r\n", title)
	fmt.Fprintf(tty, "  \x1b[2m↑/↓ move · space toggle · a all · enter confirm · q cancel\x1b[0m\r\n")

	first := true
	draw := func() {
		render(tty, c, first)
		first = false
	}
	draw()

	buf := make([]byte, 32)
	for {
		n, rerr := tty.Read(buf)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return c.items, false, nil
			}
			return nil, false, rerr
		}
		for _, k := range decodeKeys(buf[:n]) {
			switch c.apply(k) {
			case clConfirm:
				draw()
				return c.items, true, nil
			case clCancel:
				draw()
				return c.items, false, nil
			}
		}
		draw()
	}
}

// render repaints the item rows in place. On every call but the first it moves the
// cursor up over the previously drawn rows so the list updates without scrolling.
func render(tty *os.File, c *checklist, first bool) {
	if !first {
		fmt.Fprintf(tty, "\x1b[%dA", len(c.items))
	}
	for i, it := range c.items {
		pointer := " "
		if i == c.cursor {
			pointer = "\x1b[36m>\x1b[0m" // cyan cursor
		}
		box := "[ ]"
		if it.checked {
			box = "[\x1b[32mx\x1b[0m]" // green check
		}
		line := fmt.Sprintf("%s %s %s", pointer, box, it.label)
		if it.sub != "" {
			line += fmt.Sprintf("  \x1b[2m%s\x1b[0m", it.sub)
		}
		// \r to column 0, line, \x1b[K clear to EOL, then newline.
		fmt.Fprintf(tty, "\r%s\x1b[K\r\n", line)
	}
}
