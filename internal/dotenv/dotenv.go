// Package dotenv parses .env files well enough to migrate their values into the
// secrets store and rewrite the file with selected keys removed. It deliberately
// keeps the original lines verbatim so a rewrite touches only the keys we import.
package dotenv

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"
)

// Entry is a single KEY=VALUE assignment. Line is the 1-based index into File.Lines.
type Entry struct {
	Key   string
	Value string
	Line  int
}

// File is a parsed .env: its raw lines (newlines stripped) and the assignments
// found among them.
type File struct {
	Path    string
	Lines   []string
	Entries []Entry
}

// Parse reads a .env document. name is used only for File.Path.
func Parse(name string, r io.Reader) (*File, error) {
	f := &File{Path: name}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		f.Lines = append(f.Lines, raw)

		t := strings.TrimLeft(raw, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		t = strings.TrimPrefix(t, "export ")
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(t[:eq])
		if !validKey(key) {
			continue
		}
		f.Entries = append(f.Entries, Entry{
			Key:   key,
			Value: parseValue(t[eq+1:]),
			Line:  line,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return f, nil
}

// ParseFile reads and parses the .env at path.
func ParseFile(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, bytes.NewReader(b))
}

// Without returns the file content with the lines defining any of keys removed,
// preserving every other line verbatim. All lines of a duplicated key are
// dropped. The result ends with a trailing newline unless it is empty.
func (f *File) Without(keys map[string]bool) string {
	remove := f.removedLines(keys)
	var out []string
	for i, l := range f.Lines {
		if remove[i+1] {
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// RemainingIsEmpty reports whether, after removing keys, only blank and comment
// lines would remain.
func (f *File) RemainingIsEmpty(keys map[string]bool) bool {
	remove := f.removedLines(keys)
	for i, l := range f.Lines {
		if remove[i+1] {
			continue
		}
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

func (f *File) removedLines(keys map[string]bool) map[int]bool {
	remove := map[int]bool{}
	for _, e := range f.Entries {
		if keys[e.Key] {
			remove[e.Line] = true
		}
	}
	return remove
}

// parseValue interprets the text after '=' per common .env conventions:
// double-quoted values honour \n \t \r \\ \" escapes; single-quoted values are
// literal; unquoted values are trimmed and lose a trailing " #..." inline comment.
func parseValue(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return ""
	}
	switch s[0] {
	case '"':
		return parseDoubleQuoted(s[1:])
	case '\'':
		if i := strings.IndexByte(s[1:], '\''); i >= 0 {
			return s[1 : 1+i]
		}
		return s[1:] // unterminated; take the rest
	default:
		if i := strings.Index(s, " #"); i >= 0 {
			s = s[:i]
		}
		return strings.TrimRight(s, " \t")
	}
}

func parseDoubleQuoted(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(s[i]) // \\ \" and anything else: keep the literal char
			}
			continue
		}
		if c == '"' {
			break // closing quote; ignore trailing content (e.g. a comment)
		}
		b.WriteByte(c)
	}
	return b.String()
}

// validKey reports whether s is a POSIX-ish env var name.
func validKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
