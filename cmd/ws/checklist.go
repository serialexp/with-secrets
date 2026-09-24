package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

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
	top    int // index of the first visible row (scroll offset)
	page   int // rows to jump on PageUp/PageDown (one window); <1 means 1
}

type key int

const (
	kNone key = iota
	kUp
	kDown
	kPageUp
	kPageDown
	kHome
	kEnd
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
	case kPageUp:
		c.cursor -= c.pageStep()
		if c.cursor < 0 {
			c.cursor = 0
		}
	case kPageDown:
		c.cursor += c.pageStep()
		if c.cursor > len(c.items)-1 {
			c.cursor = len(c.items) - 1
		}
	case kHome:
		c.cursor = 0
	case kEnd:
		c.cursor = len(c.items) - 1
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

// pageStep is how far PageUp/PageDown move the cursor: one window, or a single
// row if the page size was never set.
func (c *checklist) pageStep() int {
	if c.page < 1 {
		return 1
	}
	return c.page
}

// clampScroll adjusts top so the cursor stays within a window of visible rows,
// keeping top within [0, len-visible]. A non-positive visible is treated as 1.
func (c *checklist) clampScroll(visible int) {
	if visible < 1 {
		visible = 1
	}
	if c.cursor < c.top {
		c.top = c.cursor
	}
	if c.cursor >= c.top+visible {
		c.top = c.cursor - visible + 1
	}
	if maxTop := len(c.items) - visible; c.top > maxTop {
		c.top = maxTop
	}
	if c.top < 0 {
		c.top = 0
	}
}

// decodeKeys translates a raw input buffer into higher-level keys, handling ANSI
// CSI sequences (arrows, Page Up/Down, Home/End), vi keys, and control chars.
func decodeKeys(b []byte) []key {
	var out []key
	for i := 0; i < len(b); i++ {
		switch c := b[i]; c {
		case 0x1b: // ESC: a CSI sequence (ESC [ … final) or a lone Escape (cancel)
			if i+1 < len(b) && b[i+1] == '[' {
				// Consume params up to the final byte (0x40–0x7E). This keeps a
				// sequence we don't map (e.g. an unknown CSI) from spilling its
				// leftover bytes back into the loop as stray keys.
				j := i + 2
				for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
					j++
				}
				if j >= len(b) {
					return out // incomplete sequence at buffer end: drop it
				}
				if k := csiKey(b[i+2:j], b[j]); k != kNone {
					out = append(out, k)
				}
				i = j
				continue
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

// csiKey maps a decoded CSI sequence (its parameter bytes and final byte) to a
// key, or kNone if we don't handle it. Handles both the letter finals (arrows,
// Home/End) and the tilde-terminated numeric forms (Page Up/Down, Home/End).
func csiKey(params []byte, final byte) key {
	switch final {
	case 'A':
		return kUp
	case 'B':
		return kDown
	case 'C', 'D': // left/right: no horizontal movement here
		return kNone
	case 'H':
		return kHome
	case 'F':
		return kEnd
	case '~':
		switch string(params) {
		case "1", "7":
			return kHome
		case "4", "8":
			return kEnd
		case "5":
			return kPageUp
		case "6":
			return kPageDown
		}
	}
	return kNone
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
	fmt.Fprintf(tty, "  \x1b[2m↑/↓ move · PgUp/PgDn page · space toggle · a all · enter confirm · q cancel\x1b[0m\r\n")

	// Size the scrolling window to the terminal: reserve rows for the title and
	// help printed above, the footer below, and one trailing line so the block
	// never runs off the bottom (which would break the in-place redraw). Cap the
	// width too, so a long row is truncated to a single line rather than wrapping
	// onto a second — a wrapped row would desync the move-up redraw count.
	visible := len(items)
	width := 0
	if cols, rows, gerr := term.GetSize(fd); gerr == nil {
		if rows > 0 {
			if v := rows - 4; v < visible {
				visible = v
			}
		}
		if cols > 0 {
			width = cols
		}
	}
	if visible < 1 {
		visible = 1
	}
	c.page = visible

	first := true
	draw := func() {
		c.clampScroll(visible)
		render(tty, c, visible, width, first)
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

// render repaints a window of at most `visible` item rows plus a footer, in
// place. On every call but the first it moves the cursor up over the previously
// drawn block (visible rows + footer) so the list updates without scrolling.
// width, when > 0, caps each row's display width so no row wraps onto a second
// physical line (which would desync the move-up count).
func render(tty *os.File, c *checklist, visible, width int, first bool) {
	if visible > len(c.items) {
		visible = len(c.items)
	}
	if !first {
		fmt.Fprintf(tty, "\x1b[%dA", visible+1) // rows window + footer line
	}
	end := c.top + visible
	for i := c.top; i < end; i++ {
		it := c.items[i]
		pointer := " "
		if i == c.cursor {
			pointer = "\x1b[36m>\x1b[0m" // cyan cursor
		}
		box := "[ ]"
		if it.checked {
			box = "[\x1b[32mx\x1b[0m]" // green check
		}
		label, sub := fitRow(it.label, it.sub, width)
		line := fmt.Sprintf("%s %s %s", pointer, box, label)
		if sub != "" {
			line += fmt.Sprintf("  \x1b[2m%s\x1b[0m", sub)
		}
		// \r to column 0, line, \x1b[K clear to EOL, then newline.
		fmt.Fprintf(tty, "\r%s\x1b[K\r\n", line)
	}
	fmt.Fprintf(tty, "\r%s\x1b[K\r\n", footerText(c, visible, width))
}

// fitRow truncates a row's label and sub so their combined visible width plus
// the fixed decoration ("> [x] " prefix and the two-space gap before sub) fits
// within width columns (leaving the final column free to avoid edge-wrap). The
// label is kept whole where possible; the sub is trimmed first, then the label.
// width <= 0 means "unknown size" — return both unchanged.
func fitRow(label, sub string, width int) (string, string) {
	if width <= 0 {
		return label, sub
	}
	const prefix = 6 // "> [x] " — pointer, space, [x], space
	avail := width - 1 - prefix
	if avail < 1 {
		return truncVisible(label, width-1), "" // degenerate: tiny terminal
	}
	if utf8.RuneCountInString(label) >= avail {
		return truncVisible(label, avail), ""
	}
	if sub == "" {
		return label, ""
	}
	subBudget := avail - utf8.RuneCountInString(label) - 2 // two-space gap
	if subBudget < 2 {
		return label, ""
	}
	return label, truncVisible(sub, subBudget)
}

// truncVisible shortens s to at most max display runes, replacing the tail with
// a single-rune ellipsis when it has to cut. ANSI-free input is assumed (labels
// and previews carry no escape codes).
func truncVisible(s string, max int) string {
	if max < 1 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}

// footerText summarises selection count and, when the list is scrolled, how many
// rows lie above and below the current window. The visible text is truncated to
// width so the footer, like every item row, stays on a single line.
func footerText(c *checklist, visible, width int) string {
	checked := 0
	for _, it := range c.items {
		if it.checked {
			checked++
		}
	}
	text := fmt.Sprintf("  %d/%d selected", checked, len(c.items))
	if above := c.top; above > 0 {
		text += fmt.Sprintf(" · ↑%d more", above)
	}
	if below := len(c.items) - (c.top + visible); below > 0 {
		text += fmt.Sprintf(" · ↓%d more", below)
	}
	if width > 0 {
		text = truncVisible(text, width-1)
	}
	return "\x1b[2m" + text + "\x1b[0m"
}
