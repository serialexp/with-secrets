package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"with-secrets/internal/dotenv"
	"with-secrets/internal/manifest"
	"with-secrets/internal/store"
)

// envVar is one variable discovered in a .env file.
type envVar struct {
	key   string
	value string
	file  string // absolute path to the source .env
}

// cmdImport scans DIR (default CWD) for .env files, lets the user pick which
// variables are secrets, imports them into the store (+ .secrets mapping), and
// strips the imported lines from the .env files (keeping a .bak).
func cmdImport(global bool, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if info, err := os.Stat(root); err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}

	files, err := discoverEnvFiles(root)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .env files found under %s", root)
	}

	// Parse everything up front.
	var vars []envVar
	countByFile := map[string]int{}
	dirs := map[string]bool{}
	for _, fp := range files {
		f, err := dotenv.ParseFile(fp)
		if err != nil {
			return fmt.Errorf("parse %s: %w", fp, err)
		}
		for _, e := range f.Entries {
			vars = append(vars, envVar{key: e.Key, value: e.Value, file: fp})
			countByFile[fp]++
		}
		dirs[filepath.Dir(fp)] = true
	}
	if len(vars) == 0 {
		return fmt.Errorf("found %d .env file(s) but no variables in them", len(files))
	}

	// Warn when results span multiple files/dirs — they probably want separate scopes.
	if len(files) > 1 || len(dirs) > 1 {
		fmt.Fprintf(os.Stderr, "Found %d .env files across %d director%s:\n", len(files), len(dirs), plural(len(dirs), "y", "ies"))
		for _, fp := range files {
			fmt.Fprintf(os.Stderr, "  %s (%d vars)\n", rel(root, fp), countByFile[fp])
		}
		fmt.Fprintln(os.Stderr, "They will all import into one scope. For separate scopes, run `ws import` inside each project instead.")
		ok, err := promptYesNo("Continue importing everything into one scope?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("import cancelled")
		}
	}

	// Interactive selection.
	items := make([]checklistItem, len(vars))
	for i, v := range vars {
		items[i] = checklistItem{
			label:   v.key,
			sub:     fmt.Sprintf("%s  ·  %s", valuePreview(v.value), rel(root, v.file)),
			checked: looksSecret(v.key, v.value),
		}
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("import needs an interactive terminal")
	}
	defer tty.Close()

	title := fmt.Sprintf("Select secrets to import (%d found):", len(vars))
	result, confirmed, err := runChecklist(tty, title, items)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("import cancelled")
	}

	var selected []envVar
	for i, it := range result {
		if it.checked {
			selected = append(selected, vars[i])
		}
	}
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "Nothing selected; nothing imported.")
		return nil
	}

	values, conflicts := resolveSelected(selected)
	if len(conflicts) > 0 {
		return fmt.Errorf("selected keys have conflicting values across files: %s — deselect the duplicates and re-run", strings.Join(conflicts, ", "))
	}

	// Resolve (and possibly create) the write context before any crypto.
	ctx, err := resolveWriteContextIn(global, root)
	if err != nil {
		return err
	}

	st, key, h, path, err := unlock()
	if err != nil {
		return err
	}
	defer store.Zero(key)

	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		st.Set(ctx.scope, k, values[k])
	}
	if err := reseal(key, h, st, path); err != nil {
		return err
	}
	// Best-effort scrub of plaintext we copied around.
	for k := range values {
		values[k] = ""
	}
	for i := range vars {
		vars[i].value = ""
	}
	for i := range selected {
		selected[i].value = ""
	}

	if !ctx.global {
		for _, k := range names {
			if err := manifest.AddEntry(ctx.manifestPath, k); err != nil {
				return err
			}
		}
	}
	fmt.Printf("Imported %d secret(s) into %s.\n", len(names), ctx.label())

	backups, err := stripFromEnvFiles(root, selected)
	if err != nil {
		return err
	}
	if len(backups) > 0 {
		fmt.Fprintln(os.Stderr, "\nBackups still contain the PLAINTEXT secrets — delete them once you've verified the store:")
		for _, b := range backups {
			fmt.Fprintf(os.Stderr, "  %s\n", rel(root, b))
		}
	}
	return nil
}

// stripFromEnvFiles rewrites each source file with its imported keys removed,
// writing a .bak first. Returns the backup paths created. Offers to delete a file
// left with no variables.
func stripFromEnvFiles(root string, selected []envVar) ([]string, error) {
	byFile := map[string]map[string]bool{}
	for _, v := range selected {
		if byFile[v.file] == nil {
			byFile[v.file] = map[string]bool{}
		}
		byFile[v.file][v.key] = true
	}

	filesInOrder := make([]string, 0, len(byFile))
	for fp := range byFile {
		filesInOrder = append(filesInOrder, fp)
	}
	sort.Strings(filesInOrder)

	var backups []string
	for _, fp := range filesInOrder {
		keys := byFile[fp]
		f, err := dotenv.ParseFile(fp)
		if err != nil {
			return backups, err
		}
		orig, err := os.ReadFile(fp)
		if err != nil {
			return backups, err
		}
		bak := fp + ".bak"
		if err := os.WriteFile(bak, orig, 0o600); err != nil {
			return backups, err
		}
		backups = append(backups, bak)

		if f.RemainingIsEmpty(keys) {
			del, err := promptYesNo(fmt.Sprintf("%s has no variables left. Delete it?", rel(root, fp)))
			if err != nil {
				return backups, err
			}
			if del {
				if err := os.Remove(fp); err != nil {
					return backups, err
				}
				fmt.Printf("Deleted %s\n", rel(root, fp))
				continue
			}
		}

		mode := os.FileMode(0o600)
		if fi, err := os.Stat(fp); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := writeFileAtomic(fp, []byte(f.Without(keys)), mode); err != nil {
			return backups, err
		}
		fmt.Printf("Rewrote %s (removed %d key%s)\n", rel(root, fp), len(keys), plural(len(keys), "", "s"))
	}
	return backups, nil
}

// resolveSelected dedups selected vars by key and returns the value map plus any
// keys that appear with conflicting values across files (sorted).
func resolveSelected(selected []envVar) (map[string]string, []string) {
	byKey := map[string]string{}
	conflict := map[string]bool{}
	for _, v := range selected {
		if prev, ok := byKey[v.key]; ok && prev != v.value {
			conflict[v.key] = true
		} else {
			byKey[v.key] = v.value
		}
	}
	var cs []string
	for k := range conflict {
		cs = append(cs, k)
	}
	sort.Strings(cs)
	return byKey, cs
}

// discoverEnvFiles walks root for .env / .env.* files, skipping heavy/irrelevant
// directories and template files.
func discoverEnvFiles(root string) ([]string, error) {
	skipDirs := map[string]bool{"node_modules": true, ".git": true, ".hg": true, "vendor": true}
	// Skip templates and our own backups.
	tmplSuffixes := []string{".example", ".sample", ".template", ".dist", ".bak"}

	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if name != ".env" && !strings.HasPrefix(name, ".env.") {
			return nil
		}
		for _, s := range tmplSuffixes {
			if strings.HasSuffix(name, s) {
				return nil
			}
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

var (
	secretNameHints = []string{
		"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PASS", "PRIVATE",
		"CREDENTIAL", "CRED", "AUTH", "APIKEY", "API_KEY", "ACCESS",
		"DSN", "SIGNING", "CERT", "SALT", "SESSION", "KEY",
	}
	publicNamePrefixes = []string{"NEXT_PUBLIC_", "VITE_", "PUBLIC_", "REACT_APP_"}
	publicNames        = map[string]bool{
		"NODE_ENV": true, "PORT": true, "HOST": true, "HOSTNAME": true,
		"LOG_LEVEL": true, "TZ": true, "LANG": true, "DEBUG": true, "ENV": true,
	}
)

// looksSecret is the heuristic default for pre-checking a row: secret-sounding
// name or high-entropy value, unless the name is public by convention.
func looksSecret(name, value string) bool {
	up := strings.ToUpper(name)
	for _, p := range publicNamePrefixes {
		if strings.HasPrefix(up, p) {
			return false
		}
	}
	if publicNames[up] {
		return false
	}
	for _, h := range secretNameHints {
		if strings.Contains(up, h) {
			return true
		}
	}
	return highEntropy(value)
}

// highEntropy is a crude "looks like a random credential" test: reasonably long
// and mixing at least three character classes.
func highEntropy(v string) bool {
	if len(v) < 20 {
		return false
	}
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	return classes >= 3
}

func valuePreview(v string) string {
	v = strings.ReplaceAll(v, "\n", "⏎")
	r := []rune(v)
	if len(r) == 0 {
		return "(empty)"
	}
	if len(r) > 32 {
		return string(r[:31]) + "…"
	}
	return v
}

func rel(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil {
		return r
	}
	return p
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
