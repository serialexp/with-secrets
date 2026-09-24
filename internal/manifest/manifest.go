// Package manifest parses and maintains a project's .secrets file: the
// committable declaration of which secrets to inject and which scope they belong
// to. It names secrets, never values.
//
// Format (one entry per line):
//
//	# @scope NAME        scope directive (optional; defaults to the file's dir)
//	# @extends REF       inherit a parent manifest (optional; see below)
//	ENV_VAR=store-key    map environment variable ENV_VAR to store key
//	ENV_VAR              shorthand: env var and store key are the same name
//	# comment            full-line comment
//	                     blank lines ignored
//
// Trailing "# ..." comments on an entry line are stripped.
//
// @extends declares an explicit parent: REF is a path to the directory holding
// the parent .secrets, resolved relative to this manifest's own directory
// (e.g. "../.." for a monorepo app pointing at the repo root). A child inherits
// the union of its ancestors' entries and resolves values across the scope chain
// nearest-first, so most-specific wins: child scope, then each parent scope, then
// global. Inheritance is opt-in — nothing is inherited without an @extends.
package manifest

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultName is the file name looked up in (and walked up from) the working dir.
const DefaultName = ".secrets"

const (
	scopeDirective   = "@scope"
	extendsDirective = "@extends"
)

// maxChainDepth bounds how many manifests an @extends chain may span, as a
// backstop against pathological configurations (cycles are caught separately).
const maxChainDepth = 32

// Entry maps an environment variable to a key in the secrets store.
type Entry struct {
	EnvVar   string
	StoreKey string
}

// Manifest is a parsed .secrets file.
type Manifest struct {
	Scope   string // declared scope name, or "" if none declared
	Extends string // @extends ref (path to parent's dir), or "" if none
	Entries []Entry
}

// Parse reads a manifest from r.
func Parse(r io.Reader) (Manifest, error) {
	var m Manifest
	seen := map[string]int{} // EnvVar -> line number

	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()

		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			// Comment or directive.
			body := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			if rest, ok := strings.CutPrefix(body, scopeDirective); ok {
				name := strings.TrimSpace(rest)
				if name == "" {
					return Manifest{}, fmt.Errorf("%s:%d: @scope directive needs a name", DefaultName, line)
				}
				m.Scope = name
			} else if rest, ok := strings.CutPrefix(body, extendsDirective); ok {
				ref := strings.TrimSpace(rest)
				if ref == "" {
					return Manifest{}, fmt.Errorf("%s:%d: @extends directive needs a path", DefaultName, line)
				}
				if m.Extends != "" {
					return Manifest{}, fmt.Errorf("%s:%d: duplicate @extends directive", DefaultName, line)
				}
				m.Extends = ref
			}
			continue
		}

		// Strip inline comment, then whitespace.
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = raw[:i]
		}
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}

		var env, key string
		if eq := strings.IndexByte(text, '='); eq >= 0 {
			env = strings.TrimSpace(text[:eq])
			key = strings.TrimSpace(text[eq+1:])
		} else {
			env = text
			key = text
		}

		if env == "" {
			return Manifest{}, fmt.Errorf("%s:%d: missing environment variable name", DefaultName, line)
		}
		if key == "" {
			return Manifest{}, fmt.Errorf("%s:%d: entry %q has no store key", DefaultName, line, env)
		}
		if !ValidEnvName(env) {
			return Manifest{}, fmt.Errorf("%s:%d: invalid environment variable name %q", DefaultName, line, env)
		}
		if prev, dup := seen[env]; dup {
			return Manifest{}, fmt.Errorf("%s:%d: duplicate environment variable %q (first seen on line %d)", DefaultName, line, env, prev)
		}
		seen[env] = line

		m.Entries = append(m.Entries, Entry{EnvVar: env, StoreKey: key})
	}
	if err := sc.Err(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Load reads and parses the manifest at path.
func Load(path string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	return Parse(f)
}

// FindUp walks up from startDir looking for a manifest file, returning its path.
// Returns os.ErrNotExist if none is found before the filesystem root.
func FindUp(startDir string) (string, error) {
	dir := startDir
	for {
		p := filepath.Join(dir, DefaultName)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// Link is one manifest in a resolved @extends chain.
type Link struct {
	Path    string // absolute path to this manifest
	Scope   string // @scope, or the manifest's directory if none declared
	Entries []Entry
}

// scopeOf returns a manifest's effective scope: its @scope name, or its
// directory path when no @scope is declared.
func scopeOf(m Manifest, path string) string {
	if m.Scope != "" {
		return m.Scope
	}
	return filepath.Dir(path)
}

// Chain finds the nearest manifest at or above startDir (see FindUp), then
// follows @extends links to the end of the chain. Links are returned
// nearest-first. It returns os.ErrNotExist when no manifest is found at all, and
// errors on a missing parent (an @extends pointing where there's no .secrets), a
// cycle, or a chain deeper than maxChainDepth.
func Chain(startDir string) ([]Link, error) {
	path, err := FindUp(startDir)
	if err != nil {
		return nil, err
	}

	var links []Link
	visited := map[string]bool{}
	for {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if visited[abs] {
			return nil, fmt.Errorf("%s: @extends cycle through %s", DefaultName, abs)
		}
		visited[abs] = true
		if len(links) >= maxChainDepth {
			return nil, fmt.Errorf("%s: @extends chain deeper than %d manifests", DefaultName, maxChainDepth)
		}

		m, err := Load(abs)
		if err != nil {
			return nil, err
		}
		links = append(links, Link{Path: abs, Scope: scopeOf(m, abs), Entries: m.Entries})

		if m.Extends == "" {
			return links, nil
		}
		ref := m.Extends
		if !filepath.IsAbs(ref) {
			ref = filepath.Join(filepath.Dir(abs), ref)
		}
		parent := filepath.Join(filepath.Clean(ref), DefaultName)
		if fi, err := os.Stat(parent); err != nil || fi.IsDir() {
			return nil, fmt.Errorf("%s: @extends %q from %s: no %s there", DefaultName, m.Extends, abs, DefaultName)
		}
		path = parent
	}
}

// MergedEntries returns the union of entries across links with nearest-first
// precedence: a nearer link's EnvVar replaces a farther one's. Nearest entries
// come first (in file order), then entries introduced only by parents, and so on.
func MergedEntries(links []Link) []Entry {
	seen := map[string]bool{}
	var out []Entry
	for _, l := range links {
		for _, e := range l.Entries {
			if seen[e.EnvVar] {
				continue
			}
			seen[e.EnvVar] = true
			out = append(out, e)
		}
	}
	return out
}

// Scopes returns the links' scope names in resolution order (nearest-first).
// Global is not included; the store applies it as the final fallback.
func Scopes(links []Link) []string {
	out := make([]string, len(links))
	for i, l := range links {
		out[i] = l.Scope
	}
	return out
}

// Create writes a new manifest in dir with the given scope directive. It fails
// if a manifest already exists there.
func Create(dir, scope string) (string, error) {
	path := filepath.Join(dir, DefaultName)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists", path)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	content := fmt.Sprintf("# @scope %s\n", scope)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// AddEntry appends a shorthand entry (ENV_VAR, store key == env var) to the
// manifest at path if that environment variable is not already mapped. It is a
// no-op when the entry already exists.
func AddEntry(path, envVar string) error { return AddMapping(path, envVar, envVar) }

// AddMapping appends an entry mapping envVar to storeKey to the manifest at path
// if that environment variable is not already mapped. When storeKey is empty or
// equal to envVar the shorthand form is written; otherwise "ENV_VAR=store-key".
// It is a no-op when the environment variable already exists in the manifest.
func AddMapping(path, envVar, storeKey string) error {
	m, err := Load(path)
	if err != nil {
		return err
	}
	for _, e := range m.Entries {
		if e.EnvVar == envVar {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if storeKey == "" || storeKey == envVar {
		_, err = fmt.Fprintf(f, "%s\n", envVar)
	} else {
		_, err = fmt.Fprintf(f, "%s=%s\n", envVar, storeKey)
	}
	return err
}

// AddMappings appends every entry in entries that is not already mapped, in a
// single write, so a partial/interrupted append can't leave the manifest with
// only some of a batch. Entries already present (by env var) are skipped, as are
// duplicates within entries. Shorthand is used when env var == store key.
func AddMappings(path string, entries []Entry) error {
	m, err := Load(path)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, e := range m.Entries {
		have[e.EnvVar] = true
	}
	var b strings.Builder
	for _, e := range entries {
		if have[e.EnvVar] {
			continue
		}
		have[e.EnvVar] = true
		if e.StoreKey == "" || e.StoreKey == e.EnvVar {
			fmt.Fprintf(&b, "%s\n", e.EnvVar)
		} else {
			fmt.Fprintf(&b, "%s=%s\n", e.EnvVar, e.StoreKey)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

// ValidEnvName reports whether s is a POSIX-ish environment variable name:
// starts with a letter or underscore, followed by letters, digits, underscores.
func ValidEnvName(s string) bool {
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return s != ""
}
