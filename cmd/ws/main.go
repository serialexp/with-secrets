// Command ws (with-secrets) stores development secrets encrypted at rest behind
// two required factors — a passphrase (Argon2id) and a YubiKey FIDO2 hmac-secret
// touch — and injects them into a child process's environment on demand.
//
// Secrets are either global or scoped to a project. A project's scope is declared
// in its .secrets manifest (see package manifest); walking up from the working
// directory finds the nearest one. Scoped lookups fall back to global.
//
// Usage:
//
//	ws init                 create the store (passphrase + 2 touches)
//	ws set  NAME            store a secret in the current scope
//	ws -g set NAME          store a global secret
//	ws rm   NAME            remove a secret from the current scope
//	ws -g rm NAME           remove a global secret
//	ws list                 list secret names (current scope + global; alias: ls)
//	ws -g list              list global secret names only
//	ws scopes               list all scope names
//	ws import [DIR]         migrate .env secrets into the store (interactive)
//	ws request             mint a one-time key to receive secrets from someone
//	ws send --to TOKEN     encrypt this repo's secrets to a recipient token
//	ws receive BLOB        decrypt a received blob into your own store
//	ws session              unlock once, then set/rm/list many
//	ws run -- CMD [ARGS]    inject the nearest .secrets, run CMD
//	ws CMD [ARGS]           shorthand for `run -- CMD [ARGS]`
//
// Listing (list, scopes) reads a cleartext name index in the envelope and needs
// no passphrase or touch; only secret values are encrypted.
package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/term"

	"with-secrets/internal/fido"
	"with-secrets/internal/manifest"
	"with-secrets/internal/store"
)

func main() {
	args := os.Args[1:]

	// Global flags may precede the subcommand: `with-secrets -g set NAME`.
	global := false
	for len(args) > 0 {
		switch args[0] {
		case "-g", "--global":
			global = true
			args = args[1:]
			continue
		case "-h", "--help", "help":
			usage(os.Stdout)
			return
		}
		break
	}

	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd := args[0]
	rest := args[1:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(rest)
	case "set":
		err = cmdSet(global, rest)
	case "rm":
		err = cmdRm(global, rest)
	case "list", "ls":
		err = cmdList(global, rest)
	case "scopes":
		err = cmdScopes(rest)
	case "import":
		err = cmdImport(global, rest)
	case "request":
		err = cmdRequest(rest)
	case "send":
		err = cmdSend(rest)
	case "receive":
		err = cmdReceive(rest)
	case "session":
		err = cmdSession(global, rest)
	case "run":
		err = cmdRun(rest)
	default:
		// Shorthand: `with-secrets pnpm run dev` == `with-secrets run -- pnpm run dev`.
		err = cmdRun(append([]string{"--"}, args...))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "with-secrets: %v\n", err)
		os.Exit(1)
	}
}

// progName is the name the binary was invoked as, so help matches how you call
// it (`ws` or the full `with-secrets`).
func progName() string { return filepath.Base(os.Args[0]) }

func usage(w io.Writer) {
	p := progName()
	fmt.Fprintf(w, `with-secrets — local secrets behind a passphrase + YubiKey touch

  %[1]s init                 create the store
  %[1]s set  NAME            store a secret in the current project scope
  %[1]s -g set NAME          store a global secret
  %[1]s rm   NAME            remove a secret from the current scope
  %[1]s -g rm NAME           remove a global secret
  %[1]s list                 list current scope + global names (no touch; alias: ls)
  %[1]s -g list              list global names only (no touch)
  %[1]s scopes               list all scope names (no touch)
  %[1]s import [DIR]         scan .env files, pick secrets, import + strip them
  %[1]s request             mint a one-time key to receive secrets from someone
  %[1]s send --to TOKEN [DIR] encrypt this repo's secrets to a recipient token
  %[1]s receive BLOB [DIR]   decrypt a received blob into your own store
  %[1]s session              unlock once, then set/rm/list many (touch per change)
  %[1]s run -- CMD [ARGS]    inject the nearest .secrets, then run CMD
  %[1]s CMD [ARGS]           shorthand for the above

A project's scope is declared in its .secrets file. Setting a scoped secret in a
directory with no .secrets offers to create one; the env-var mapping is recorded
there automatically.

Store location: $WITH_SECRETS_STORE or $XDG_DATA_HOME/with-secrets/store.wsec
`, p)
}

// --- store location -------------------------------------------------------

func storePath() (string, error) {
	if p := os.Getenv("WITH_SECRETS_STORE"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "with-secrets", "store.wsec"), nil
}

// --- scope resolution -----------------------------------------------------

// scopeCtx names where a mutation lands and, for scoped writes, which manifest to
// keep in sync. A global context has global==true, scope=="" and manifestPath=="".
type scopeCtx struct {
	global       bool
	scope        string
	manifestPath string
}

func (c scopeCtx) label() string {
	if c.global {
		return "global"
	}
	return "scope " + c.scope
}

// currentScope resolves the scope for the working directory. See currentScopeFrom.
func currentScope() (scope, manifestPath string, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	return currentScopeFrom(wd)
}

// currentScopeFrom walks up from dir for a manifest and returns its scope name and
// path. A manifest with no explicit @scope directive defaults to its own directory
// path. Returns ("", "", nil) when no manifest is found.
func currentScopeFrom(dir string) (scope, manifestPath string, err error) {
	p, err := manifest.FindUp(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	m, err := manifest.Load(p)
	if err != nil {
		return "", "", err
	}
	s := m.Scope
	if s == "" {
		s = filepath.Dir(p)
	}
	return s, p, nil
}

// resolveWriteContext resolves the write context for the working directory.
func resolveWriteContext(global bool) (scopeCtx, error) {
	if global {
		return scopeCtx{global: true}, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return scopeCtx{}, err
	}
	return resolveWriteContextIn(global, wd)
}

// resolveWriteContextIn determines where a set/session/import write goes, based on
// dir. For global it returns immediately. Otherwise it finds the nearest scope; if
// none exists it offers — before any passphrase or touch — to create a .secrets in
// dir.
func resolveWriteContextIn(global bool, dir string) (scopeCtx, error) {
	if global {
		return scopeCtx{global: true}, nil
	}
	scope, mpath, err := currentScopeFrom(dir)
	if err != nil {
		return scopeCtx{}, err
	}
	if scope != "" {
		return scopeCtx{scope: scope, manifestPath: mpath}, nil
	}

	create, err := promptYesNo(fmt.Sprintf("No .secrets context found. Create one in %s?", dir))
	if err != nil {
		return scopeCtx{}, err
	}
	if !create {
		return scopeCtx{}, errors.New("no context created (use -g to set a global secret)")
	}
	def := filepath.Base(dir)
	name, err := promptLine(fmt.Sprintf("Scope name [%s]: ", def))
	if err != nil {
		return scopeCtx{}, err
	}
	if name == "" {
		name = def
	}
	p, err := manifest.Create(dir, name)
	if err != nil {
		return scopeCtx{}, err
	}
	fmt.Fprintf(os.Stderr, "Created %s (scope %q)\n", p, name)
	return scopeCtx{scope: name, manifestPath: p}, nil
}

// --- crypto helpers -------------------------------------------------------

func randCDH() ([]byte, error) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

// readStore loads and parses the store file, returning the header, the cleartext
// name index, the ciphertext, the AEAD additional data, and the path.
func readStore() (h store.Header, idx store.Index, ct, aad []byte, path string, err error) {
	path, err = storePath()
	if err != nil {
		return store.Header{}, store.Index{}, nil, nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store.Header{}, store.Index{}, nil, nil, "", fmt.Errorf("no store found at %s — run `with-secrets init` first", path)
		}
		return store.Header{}, store.Index{}, nil, nil, "", err
	}
	h, idx, ct, aad, err = store.ParseHeader(data)
	if err != nil {
		return store.Header{}, store.Index{}, nil, nil, "", err
	}
	return h, idx, ct, aad, path, nil
}

// touchDeriveDecrypt performs the YubiKey touch, folds the result into the given
// passKey, and decrypts. The caller owns (and must Zero) the returned key.
func touchDeriveDecrypt(passKey []byte, h store.Header, ct, aad []byte) (*store.Store, []byte, error) {
	cdh, err := randCDH()
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintln(os.Stderr, "Touch your YubiKey…")
	hmacOut, err := fido.HMACSecret(h.CredID, h.HMACSalt, cdh)
	if err != nil {
		return nil, nil, err
	}
	defer store.Zero(hmacOut)

	key, err := store.CombineKey(passKey, hmacOut)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Decrypt(key, h, ct, aad)
	if err != nil {
		store.Zero(key)
		return nil, nil, err
	}
	return st, key, nil
}

// unlock reads the store, prompts for the passphrase, performs the YubiKey
// touch, and returns the decrypted store plus everything needed to re-seal.
func unlock() (st *store.Store, key []byte, h store.Header, path string, err error) {
	h, _, ct, aad, path, err := readStore()
	if err != nil {
		return nil, nil, store.Header{}, "", err
	}
	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return nil, nil, store.Header{}, "", err
	}
	passKey := store.DerivePassKey(pass, h)
	store.Zero(pass)
	defer store.Zero(passKey)

	st, key, err = touchDeriveDecrypt(passKey, h, ct, aad)
	if err != nil {
		return nil, nil, store.Header{}, "", err
	}
	return st, key, h, path, nil
}

// reseal re-encrypts the store under the existing header/key and writes atomically.
func reseal(key []byte, h store.Header, st *store.Store, path string) error {
	data, err := store.Encrypt(key, h, st)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

// --- commands -------------------------------------------------------------

func cmdInit(args []string) error {
	path, err := storePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("store already exists at %s (refusing to overwrite)", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	pass, err := readSecret("New passphrase: ")
	if err != nil {
		return err
	}
	defer store.Zero(pass)
	if len(pass) == 0 {
		return errors.New("passphrase must not be empty")
	}
	confirm, err := readSecret("Confirm passphrase: ")
	if err != nil {
		return err
	}
	defer store.Zero(confirm)
	if string(pass) != string(confirm) {
		return errors.New("passphrases do not match")
	}
	if len(pass) < 12 {
		fmt.Fprintln(os.Stderr, "warning: short passphrase; the on-disk store is only as strong as this.")
	}

	cdh, err := randCDH()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Enrolling a credential — touch your YubiKey (1/2)…")
	credID, err := fido.Enroll(cdh)
	if err != nil {
		return err
	}

	h, err := store.NewHeader(store.DefaultParams(), credID)
	if err != nil {
		return err
	}

	cdh2, err := randCDH()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Deriving key — touch your YubiKey (2/2)…")
	hmacOut, err := fido.HMACSecret(credID, h.HMACSalt, cdh2)
	if err != nil {
		return err
	}
	defer store.Zero(hmacOut)

	key, err := store.DeriveKey(pass, hmacOut, h)
	if err != nil {
		return err
	}
	defer store.Zero(key)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	st := store.NewStore()
	if _, err := st.EnsureIdentity(); err != nil {
		return err
	}
	if err := reseal(key, h, st, path); err != nil {
		return err
	}
	fmt.Printf("Created empty store at %s\n", path)
	return nil
}

func cmdSet(global bool, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: with-secrets [-g] set NAME")
	}
	name := args[0]
	if !manifest.ValidEnvName(name) {
		return fmt.Errorf("invalid secret name %q: use a valid environment variable name (letters, digits, underscore; not starting with a digit)", name)
	}

	// Resolve (and possibly create) the context before any crypto.
	ctx, err := resolveWriteContext(global)
	if err != nil {
		return err
	}

	st, key, h, path, err := unlock()
	if err != nil {
		return err
	}
	defer store.Zero(key)

	value, err := readSecret(fmt.Sprintf("Value for %s: ", name))
	if err != nil {
		return err
	}
	defer store.Zero(value)

	st.Set(ctx.scope, name, string(value))
	if err := reseal(key, h, st, path); err != nil {
		return err
	}
	if !ctx.global {
		if err := manifest.AddEntry(ctx.manifestPath, name); err != nil {
			return err
		}
	}
	fmt.Printf("Stored %s (%s)\n", name, ctx.label())
	return nil
}

func cmdRm(global bool, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: with-secrets [-g] rm NAME")
	}
	name := args[0]

	scope := ""
	label := "global"
	if !global {
		s, _, err := currentScope()
		if err != nil {
			return err
		}
		if s == "" {
			return errors.New("not inside a .secrets context (use -g to remove a global secret)")
		}
		scope = s
		label = "scope " + s
	}

	st, key, h, path, err := unlock()
	if err != nil {
		return err
	}
	defer store.Zero(key)

	if !st.Remove(scope, name) {
		return fmt.Errorf("no secret named %q in %s", name, label)
	}
	if err := reseal(key, h, st, path); err != nil {
		return err
	}
	fmt.Printf("Removed %s (%s)\n", name, label)
	return nil
}

// cmdList prints secret names without decrypting: it reads the cleartext index,
// so no passphrase or touch is required. Within a scope it shows that scope's
// names plus the global names that still apply there (a global name shadowed by a
// scoped one of the same name does not apply and is omitted).
func cmdList(global bool, _ []string) error {
	_, idx, _, _, _, err := readStore()
	if err != nil {
		return err
	}
	scope := ""
	if !global {
		scope, _, err = currentScope()
		if err != nil {
			return err
		}
	}
	printNames(scope, idx)
	return nil
}

// printNames prints secret names grouped as [scope] then [global]. When scope is
// empty only global names are shown. Global names shadowed by a same-named scoped
// secret are omitted (the scoped value wins). Empty groups are skipped, and when
// nothing matches it says so instead of printing a bare header.
func printNames(scope string, idx store.Index) {
	var scopeNames []string
	shadowed := map[string]bool{}
	if scope != "" {
		scopeNames = idx.Scopes[scope]
		for _, n := range scopeNames {
			shadowed[n] = true
		}
	}
	var globalNames []string
	for _, n := range idx.Global {
		if !shadowed[n] {
			globalNames = append(globalNames, n)
		}
	}

	if len(scopeNames) == 0 && len(globalNames) == 0 {
		if scope != "" {
			fmt.Printf("No secrets in scope %q or global.\n", scope)
		} else {
			fmt.Println("No global secrets stored.")
		}
		return
	}
	if len(scopeNames) > 0 {
		fmt.Printf("[scope %s]\n", scope)
		for _, n := range scopeNames {
			fmt.Println("  " + n)
		}
	}
	if len(globalNames) > 0 {
		fmt.Println("[global]")
		for _, n := range globalNames {
			fmt.Println("  " + n)
		}
	}
}

// cmdScopes lists all scope names in the store (cleartext index; no decryption).
func cmdScopes(_ []string) error {
	_, idx, _, _, _, err := readStore()
	if err != nil {
		return err
	}
	names := idx.ScopeNames()
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "no scopes yet")
		return nil
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func cmdRun(args []string) error {
	// Accept an optional leading "--" separating our args from the command.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: with-secrets run -- CMD [ARGS...]")
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	mpath, err := manifest.FindUp(wd)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no %s found in %s or any parent directory", manifest.DefaultName, wd)
		}
		return err
	}
	m, err := manifest.Load(mpath)
	if err != nil {
		return err
	}
	if len(m.Entries) == 0 {
		return fmt.Errorf("%s is empty; nothing to inject", mpath)
	}
	scope := m.Scope
	if scope == "" {
		scope = filepath.Dir(mpath)
	}

	st, key, _, _, err := unlock()
	if err != nil {
		return err
	}
	store.Zero(key)

	// Resolve all entries before touching the environment.
	env := os.Environ()
	var missing []string
	for _, e := range m.Entries {
		val, ok := st.Resolve(scope, e.StoreKey)
		if !ok {
			missing = append(missing, e.StoreKey)
			continue
		}
		env = append(env, e.EnvVar+"="+val)
	}
	if len(missing) > 0 {
		return fmt.Errorf("secrets not found in store: %s (add with `with-secrets set`)", strings.Join(missing, ", "))
	}

	bin, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}
	// Replace this process so signals and exit codes pass through cleanly.
	return syscall.Exec(bin, args, env)
}

// cmdSession opens an interactive session: the passphrase is entered once and
// cached in memory for the life of the process, while every mutation still
// requires a YubiKey touch. No master key or plaintext is held between commands.
func cmdSession(global bool, _ []string) error {
	// Resolve (and possibly create) the context before any crypto.
	ctx, err := resolveWriteContext(global)
	if err != nil {
		return err
	}

	h, _, ct, aad, _, err := readStore()
	if err != nil {
		return err
	}

	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}
	passKey := store.DerivePassKey(pass, h)
	store.Zero(pass)
	defer store.Zero(passKey)

	// Validate the passphrase up front (one touch) so a typo is caught before
	// you start entering values.
	fmt.Fprintln(os.Stderr, "Unlocking…")
	_, key, err := touchDeriveDecrypt(passKey, h, ct, aad)
	if err != nil {
		return err
	}
	store.Zero(key)

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer tty.Close()

	fmt.Fprintf(tty, "Unlocked (%s). Passphrase cached until you exit; each change needs a touch.\n", ctx.label())
	fmt.Fprintln(tty, "Commands: set NAME | rm NAME | list | help | quit  (Ctrl-D to exit)")

	reader := bufio.NewReader(tty)
	for {
		fmt.Fprintf(tty, "%s> ", progName())
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(tty)
				return nil
			}
			return err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var cerr error
		switch fields[0] {
		case "quit", "exit":
			return nil
		case "help":
			fmt.Fprintln(tty, "set NAME | rm NAME | list | help | quit")
		case "list":
			cerr = sessionList(ctx)
		case "set":
			if len(fields) != 2 {
				fmt.Fprintln(tty, "usage: set NAME")
				continue
			}
			cerr = sessionSet(passKey, ctx, fields[1])
		case "rm":
			if len(fields) != 2 {
				fmt.Fprintln(tty, "usage: rm NAME")
				continue
			}
			cerr = sessionRm(passKey, ctx, fields[1])
		default:
			fmt.Fprintf(tty, "unknown command %q (try: help)\n", fields[0])
		}
		if cerr != nil {
			fmt.Fprintf(tty, "error: %v\n", cerr)
		}
	}
}

func sessionSet(passKey []byte, ctx scopeCtx, name string) error {
	if !manifest.ValidEnvName(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	value, err := readSecret(fmt.Sprintf("Value for %s: ", name))
	if err != nil {
		return err
	}
	defer store.Zero(value)

	h, _, ct, aad, path, err := readStore()
	if err != nil {
		return err
	}
	st, key, err := touchDeriveDecrypt(passKey, h, ct, aad)
	if err != nil {
		return err
	}
	defer store.Zero(key)

	st.Set(ctx.scope, name, string(value))
	if err := reseal(key, h, st, path); err != nil {
		return err
	}
	if !ctx.global {
		if err := manifest.AddEntry(ctx.manifestPath, name); err != nil {
			return err
		}
	}
	fmt.Printf("Stored %s (%s)\n", name, ctx.label())
	return nil
}

func sessionRm(passKey []byte, ctx scopeCtx, name string) error {
	h, _, ct, aad, path, err := readStore()
	if err != nil {
		return err
	}
	st, key, err := touchDeriveDecrypt(passKey, h, ct, aad)
	if err != nil {
		return err
	}
	defer store.Zero(key)

	if !st.Remove(ctx.scope, name) {
		return fmt.Errorf("no secret named %q in %s", name, ctx.label())
	}
	if err := reseal(key, h, st, path); err != nil {
		return err
	}
	fmt.Printf("Removed %s (%s)\n", name, ctx.label())
	return nil
}

// sessionList reads the cleartext index — no touch needed to list names.
func sessionList(ctx scopeCtx) error {
	_, idx, _, _, _, err := readStore()
	if err != nil {
		return err
	}
	scope := ""
	if !ctx.global {
		scope = ctx.scope
	}
	printNames(scope, idx)
	return nil
}

// --- io helpers -----------------------------------------------------------

// errInterrupted is returned when the user hits Ctrl-C at a masked prompt.
var errInterrupted = errors.New("interrupted")

// promptLine writes prompt to the controlling terminal and reads a line with
// normal echo, returning it trimmed of surrounding whitespace.
func promptLine(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, prompt)
		s, e := bufio.NewReader(os.Stdin).ReadString('\n')
		if e != nil && !errors.Is(e, io.EOF) {
			return "", e
		}
		return strings.TrimSpace(s), nil
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	s, e := bufio.NewReader(tty).ReadString('\n')
	if e != nil && !errors.Is(e, io.EOF) {
		return "", e
	}
	return strings.TrimSpace(s), nil
}

// promptYesNo asks a yes/no question, defaulting to no.
func promptYesNo(prompt string) (bool, error) {
	s, err := promptLine(prompt + " [y/N]: ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(s) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// readSecret prompts on and reads a line from the controlling terminal,
// echoing a '*' per character so keystrokes register (and can be counted)
// without revealing the value in scrollback, argv, or on screen.
func readSecret(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// No controlling tty (e.g. piped stdin): read without echo.
		fmt.Fprint(os.Stderr, prompt)
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	b, err := readMasked(tty)
	fmt.Fprintln(tty)
	return b, err
}

// readMasked puts tty in raw mode and reads a line, echoing '*' per character.
func readMasked(tty *os.File) ([]byte, error) {
	fd := int(tty.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, old)

	var m maskState
	b := make([]byte, 1)
	for {
		n, rerr := tty.Read(b)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return m.buf, nil
			}
			return nil, rerr
		}
		if n == 0 {
			continue
		}
		emit, done, serr := m.step(b[0])
		if serr != nil {
			return nil, serr
		}
		if emit != "" {
			fmt.Fprint(tty, emit)
		}
		if done {
			return m.buf, nil
		}
	}
}

// maskState is the keystroke state machine behind readMasked. It is kept
// separate from any terminal I/O so it can be unit-tested directly.
type maskState struct {
	buf  []byte
	cont int // remaining continuation bytes of an in-progress UTF-8 rune
}

// step consumes one input byte and returns the terminal output to emit, whether
// the line is complete, and any terminal condition (e.g. interrupt). One '*' is
// emitted per rune, not per byte, so multi-byte characters count as one.
func (m *maskState) step(c byte) (emit string, done bool, err error) {
	switch c {
	case '\r', '\n':
		return "", true, nil
	case 3: // Ctrl-C
		return "", false, errInterrupted
	case 8, 127: // Backspace / DEL
		if len(m.buf) == 0 {
			return "", false, nil
		}
		_, size := utf8.DecodeLastRune(m.buf)
		if size < 1 {
			size = 1
		}
		m.buf = m.buf[:len(m.buf)-size]
		m.cont = 0
		return "\b \b", false, nil
	case 21: // Ctrl-U: clear the whole line
		stars := utf8.RuneCount(m.buf)
		m.buf = m.buf[:0]
		m.cont = 0
		return strings.Repeat("\b \b", stars), false, nil
	default:
		if m.cont > 0 { // continuation byte of a multi-byte rune
			m.buf = append(m.buf, c)
			m.cont--
			return "", false, nil
		}
		if c < 0x20 { // ignore other control characters
			return "", false, nil
		}
		m.buf = append(m.buf, c)
		switch {
		case c&0x80 == 0x00:
			m.cont = 0
		case c&0xE0 == 0xC0:
			m.cont = 1
		case c&0xF0 == 0xE0:
			m.cont = 2
		case c&0xF8 == 0xF0:
			m.cont = 3
		default:
			m.cont = 0
		}
		return "*", false, nil
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".with-secrets-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeded

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
