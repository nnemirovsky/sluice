package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	"golang.org/x/term"
)

func handleCredCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice cred [add|list|remove]")
	}

	switch args[0] {
	case "add":
		return handleCredAdd(args[1:])
	case "list":
		return handleCredList(args[1:])
	case "remove":
		return handleCredRemove(args[1:])
	case "update":
		return handleCredUpdate(args[1:])
	default:
		return fmt.Errorf("unknown cred command: %s (usage: sluice cred [add|list|remove|update] ...)", args[0])
	}
}

// openVaultStore opens the age-encrypted vault store for CLI credential
// management. It reads vault_dir and vault_provider from the SQLite config
// to ensure the CLI operates on the same backend as the running proxy.
// If a non-age provider is configured, it returns an error so the caller
// can report it clearly instead of silently mutating the wrong backend.
func openVaultStore(dbPath string) (*vault.Store, error) {
	var vaultDir string

	// Read vault config from the DB to ensure the CLI uses the
	// same backend as the running proxy.
	if dbPath != "" {
		if _, statErr := os.Stat(dbPath); statErr != nil && !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("cannot access database %s: %w", dbPath, statErr)
		} else if statErr == nil {
			db, dbErr := store.New(dbPath)
			if dbErr != nil {
				return nil, fmt.Errorf("open store %s: %w", dbPath, dbErr)
			}
			cfg, cfgErr := db.GetConfig()
			if cfgErr != nil {
				_ = db.Close()
				return nil, fmt.Errorf("read config from store: %w", cfgErr)
			}
			_ = db.Close()

			if cfg.VaultDir != "" {
				vaultDir = cfg.VaultDir
			}

			// If a chain provider is configured, verify that the age backend
			// is part of the chain. If age is not included, the CLI would
			// write credentials that the proxy never reads.
			if len(cfg.VaultProviders) > 0 {
				hasAge := false
				ageFirst := false
				for i, p := range cfg.VaultProviders {
					if p == "age" {
						hasAge = true
						if i == 0 {
							ageFirst = true
						}
						break
					}
				}
				if !hasAge {
					return nil, fmt.Errorf("vault_providers is configured as %v without the age backend, "+
						"CLI credential management only supports the age backend, "+
						"manage credentials through the configured providers' native tools", cfg.VaultProviders)
				}
				if !ageFirst {
					log.Printf("warning: vault_providers is %v. The age backend is not the "+
						"primary provider. Credentials added via CLI may be shadowed by "+
						"earlier providers in the chain.", cfg.VaultProviders)
				}
			} else if cfg.VaultProvider != "" && cfg.VaultProvider != "age" {
				// Single provider that is not age.
				return nil, fmt.Errorf("vault provider is %q, CLI credential management only supports the age backend, "+
					"manage credentials through the %s provider's native tools", cfg.VaultProvider, cfg.VaultProvider)
			}
		}
	}

	if vaultDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("determine home dir: %w", err)
		}
		vaultDir = filepath.Join(home, ".sluice")
	}

	vs, err := vault.NewStore(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	return vs, nil
}

func handleCredAdd(args []string) error {
	fs := flag.NewFlagSet("cred add", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	var destinations []string
	seenDest := make(map[string]bool)
	fs.Func("destination", "auto-create allow rule and binding for this destination (repeatable)", func(s string) error {
		// De-duplicate destinations so "--destination foo --destination foo"
		// does not try to create two bindings on the same (cred, dest) pair.
		// The partial UNIQUE index would otherwise reject the second insert
		// with a duplicate error after the first one succeeded, leaving the
		// credential in a partially-applied state for the caller to untangle.
		if seenDest[s] {
			return nil
		}
		seenDest[s] = true
		destinations = append(destinations, s)
		return nil
	})
	portsStr := fs.String("ports", "", "comma-separated port list for the allow rule (e.g. 443,80)")
	header := fs.String("header", "", "header for the binding (e.g. Authorization)")
	template := fs.String("template", "", "template for credential injection (e.g. \"Bearer {value}\")")
	credType := fs.String("type", "static", "credential type: static or oauth")
	tokenURL := fs.String("token-url", "", "OAuth token endpoint URL (required when type=oauth)")
	envVar := fs.String("env-var", "", "environment variable name for phantom injection (e.g. OPENAI_API_KEY)")
	// Reorder args so the positional name is always last. Go's flag package
	// stops at the first non-flag argument, so "cred add myname --type oauth"
	// would otherwise silently ignore --type. Using the shared helper keeps
	// this logic in sync with the binding/mcp subcommands and avoids a stale
	// hardcoded value-flag list.
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice cred add <name> [--type static|oauth] [--token-url URL] [--destination host]... [--ports 443] [--header Authorization] [--template \"Bearer {value}\"] [--env-var OPENAI_API_KEY]")
	}
	name := fs.Arg(0)

	// Validate --type flag.
	if *credType != "static" && *credType != "oauth" {
		return fmt.Errorf("invalid credential type %q: must be static or oauth", *credType)
	}

	// Validate --token-url: required for oauth, forbidden for static.
	if *credType == "oauth" {
		if *tokenURL == "" {
			return fmt.Errorf("--token-url is required when --type=oauth")
		}
		parsed, err := url.Parse(*tokenURL)
		if err != nil {
			return fmt.Errorf("invalid token URL %q: %w", *tokenURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid token URL %q: must include scheme and host (e.g. https://auth.example.com/token)", *tokenURL)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return fmt.Errorf("invalid token URL %q: scheme must be http or https", *tokenURL)
		}
	} else if *tokenURL != "" {
		return fmt.Errorf("--token-url is only valid with --type=oauth")
	}

	// --env-var requires --destination because the env var is stored on the
	// binding, which only exists when a destination is provided.
	if *envVar != "" && len(destinations) == 0 {
		return fmt.Errorf("--env-var requires --destination (env var is stored on the binding)")
	}

	// Read credential input from terminal or stdin.
	var secret []byte
	if *credType == "oauth" {
		oauthCred, err := readOAuthCredentialInput(*tokenURL)
		if err != nil {
			return err
		}
		data, marshalErr := oauthCred.Marshal()
		if marshalErr != nil {
			return fmt.Errorf("marshal oauth credential: %w", marshalErr)
		}
		secret = data
	} else {
		s, err := readStaticSecretInput()
		if err != nil {
			return err
		}
		secret = s
	}

	// Validate --destination inputs and open the DB before persisting
	// anything to the vault. This prevents orphaned vault credentials
	// when the glob pattern is invalid, a port is out of range, or the
	// DB path is unreachable.
	var ports []int

	if len(destinations) > 0 {
		for _, d := range destinations {
			if _, err := policy.CompileGlob(d); err != nil {
				return fmt.Errorf("invalid destination pattern %q: %w", d, err)
			}
		}

		var err error
		ports, err = parsePortsList(*portsStr)
		if err != nil {
			return err
		}
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Inputs validated and DB is open. Now persist the credential.
	vs, err := openVaultStore(*dbPath)
	if err != nil {
		return err
	}

	// Back up existing credential ciphertext in case we need to roll back
	// after a DB failure. This prevents losing a previously working secret
	// when overwriting it and then hitting a transient DB error.
	var prevCiphertext []byte
	var readErr error
	prevCiphertext, readErr = vs.ReadRawCredential(name)
	if readErr != nil {
		return fmt.Errorf("backup existing credential %q before overwrite: %w", name, readErr)
	}

	ourCiphertext, addErr := vs.Add(name, string(secret))
	for i := range secret {
		secret[i] = 0
	}
	if addErr != nil {
		return fmt.Errorf("add credential: %w", addErr)
	}

	// rollbackVault restores or removes the vault credential on DB failure
	// using compare-and-swap. See (*vault.Store).RollbackAdd for semantics.
	rollbackVault := func() {
		owned, rbErr := vs.RollbackAdd(name, prevCiphertext, ourCiphertext)
		if !owned {
			log.Printf("warning: credential %q was modified concurrently; skipping vault rollback", name)
			return
		}
		if rbErr != nil {
			log.Printf("warning: failed to roll back vault credential %q after DB error: %v", name, rbErr)
		}
	}

	// rollbackCredentialMeta removes the credential_meta row we just inserted
	// using compare-and-swap on (cred_type, token_url). If a concurrent writer
	// has already overwritten the row with different values we leave their
	// state alone and log a warning so operators can investigate.
	rollbackCredentialMeta := func() {
		_, noConcurrent, rmErr := db.RemoveCredentialMetaCAS(name, *credType, *tokenURL)
		if rmErr != nil {
			log.Printf("warning: failed to remove credential meta for %q after rollback: %v", name, rmErr)
			return
		}
		if !noConcurrent {
			log.Printf("warning: credential meta %q was modified concurrently; skipping meta rollback", name)
		}
	}

	// Store credential_meta for all credential types.
	if err := db.AddCredentialMeta(name, *credType, *tokenURL); err != nil {
		rollbackVault()
		return fmt.Errorf("add credential meta: %w", err)
	}

	// Create rule and binding atomically for each destination. If any DB
	// insert fails, roll back: remove all previously created rules and
	// bindings for this credential, then restore or remove the vault entry.
	// The vault rollback uses compare-and-swap: only restore/delete if the
	// credential still matches what we wrote, avoiding clobber of concurrent
	// writes.
	if len(destinations) > 0 {
		type addedRuleBinding struct {
			destination string
			ruleID      int64
			bindingID   int64
		}
		var addedEntries []addedRuleBinding

		rollbackDB := func() {
			for _, entry := range addedEntries {
				if _, rmErr := db.RemoveBinding(entry.bindingID); rmErr != nil {
					log.Printf("warning: failed to remove binding [%d] during rollback: %v", entry.bindingID, rmErr)
				}
				if _, rmErr := db.RemoveRule(entry.ruleID); rmErr != nil {
					log.Printf("warning: failed to remove rule [%d] during rollback: %v", entry.ruleID, rmErr)
				}
			}
		}

		for _, dest := range destinations {
			ruleID, bindingID, addErr := db.AddRuleAndBinding(
				"allow",
				store.RuleOpts{
					Destination: dest,
					Ports:       ports,
					Name:        fmt.Sprintf("auto-created for credential %q", name),
					Source:      store.CredAddSourcePrefix + name,
				},
				name,
				store.BindingOpts{
					Ports:    ports,
					Header:   *header,
					Template: *template,
					EnvVar:   *envVar,
				},
			)
			if addErr != nil {
				rollbackDB()
				// Also clean up credential_meta with CAS so a concurrent
				// writer that overwrote our row is not clobbered.
				rollbackCredentialMeta()
				rollbackVault()
				return fmt.Errorf("add rule and binding for %q: %w", dest, addErr)
			}
			addedEntries = append(addedEntries, addedRuleBinding{destination: dest, ruleID: ruleID, bindingID: bindingID})
		}

		fmt.Printf("credential %q added (type: %s)\n", name, *credType)
		for _, entry := range addedEntries {
			fmt.Printf("added allow rule [%d] for %s\n", entry.ruleID, entry.destination)
			fmt.Printf("added binding [%d] %s -> %s\n", entry.bindingID, entry.destination, name)
		}
	} else {
		fmt.Printf("credential %q added (type: %s)\n", name, *credType)
	}

	// Report env var name if set, so the operator knows what variable name
	// will be injected into the agent container.
	if *envVar != "" {
		fmt.Printf("env var: %s\n", *envVar)
	}

	return nil
}

// readStaticSecretInput reads a single secret value from terminal or stdin.
func readStaticSecretInput() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Enter secret: ")
		s, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
		return s, nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("read secret from stdin: no input")
	}
	return []byte(strings.TrimRight(scanner.Text(), "\r\n")), nil
}

// readOAuthCredentialInput reads access token and optional refresh token from
// terminal or stdin and builds an OAuthCredential. When reading from stdin
// (piped input), it expects one or two lines: access token, then optional
// refresh token.
func readOAuthCredentialInput(tokenURL string) (*vault.OAuthCredential, error) {
	return readOAuthCredentialForUpdate(tokenURL, "", false)
}

// readOAuthCredentialForUpdate reads an access token and optional refresh
// token from terminal or stdin. When preserveExisting is true, an empty
// response for the refresh token means "keep the existing refresh token"
// rather than "clear it".
//
// Terminal mode:
//   - Enter access token (required).
//   - Enter refresh token (empty means preserve existing when preserveExisting,
//     otherwise skip/clear).
//
// Stdin (piped) mode:
//   - Line 1: access token.
//   - Line 2 (optional): refresh token. Absence means preserve existing when
//     preserveExisting, otherwise leave empty.
func readOAuthCredentialForUpdate(tokenURL, existingRefreshToken string, preserveExisting bool) (*vault.OAuthCredential, error) {
	var accessToken, refreshToken string
	refreshProvided := false

	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Enter access token: ")
		at, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read access token: %w", err)
		}
		accessToken = string(at)

		// Single prompt works for both the add path (no existing token, so
		// "keep current" is effectively "leave empty") and the update path
		// (preserveExisting=true actually keeps the stored refresh token).
		fmt.Print("Enter refresh token (press Enter to keep current): ")
		rt, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read refresh token: %w", err)
		}
		refreshToken = string(rt)
		refreshProvided = refreshToken != ""
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return nil, fmt.Errorf("read access token from stdin: no input")
		}
		accessToken = strings.TrimRight(scanner.Text(), "\r\n")
		if scanner.Scan() {
			refreshToken = strings.TrimRight(scanner.Text(), "\r\n")
			refreshProvided = true
		}
	}

	if accessToken == "" {
		return nil, fmt.Errorf("access token is required for oauth credentials")
	}

	// Preserve the existing refresh token when the user did not explicitly
	// provide a new one. In stdin mode "did not provide" means only one line
	// was piped; in terminal mode it means the second prompt was empty.
	if preserveExisting && !refreshProvided {
		refreshToken = existingRefreshToken
	}

	cred := &vault.OAuthCredential{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenURL:     tokenURL,
	}
	return cred, nil
}

func handleCredList(args []string) error {
	fs := flag.NewFlagSet("cred list", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vs, err := openVaultStore(*dbPath)
	if err != nil {
		return err
	}
	names, err := vs.List()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	if len(names) == 0 {
		return nil
	}

	// Try to open the store to show binding info and credential type.
	// Skip if DB doesn't exist to avoid creating files as a side effect
	// of a read-only operation.
	if _, statErr := os.Stat(*dbPath); statErr != nil {
		if !os.IsNotExist(statErr) {
			fmt.Fprintf(os.Stderr, "warning: cannot access database %s: %v\n", *dbPath, statErr)
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}
	db, dbErr := store.New(*dbPath)
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open store %s: %v\n", *dbPath, dbErr)
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}
	defer func() { _ = db.Close() }()

	// Build a lookup map from credential_meta for type information.
	metaMap := make(map[string]*store.CredentialMeta)
	metas, metaErr := db.ListCredentialMeta()
	if metaErr == nil {
		for i := range metas {
			metaMap[metas[i].Name] = &metas[i]
		}
	}

	for _, n := range names {
		// Determine credential type from metadata.
		ct := "static"
		if meta, ok := metaMap[n]; ok {
			ct = meta.CredType
		}

		bindings, bErr := db.ListBindingsByCredential(n)
		if bErr != nil || len(bindings) == 0 {
			fmt.Printf("%s [%s]\n", n, ct)
			continue
		}
		for _, b := range bindings {
			ports := ""
			if len(b.Ports) > 0 {
				portStrs := make([]string, len(b.Ports))
				for i, p := range b.Ports {
					portStrs[i] = strconv.Itoa(p)
				}
				ports = ":" + strings.Join(portStrs, ",")
			}
			hdr := ""
			if b.Header != "" {
				hdr = " header=" + b.Header
			}
			tmpl := ""
			if b.Template != "" {
				tmpl = " template=" + b.Template
			}
			env := ""
			if b.EnvVar != "" {
				env = " env=" + b.EnvVar
			}
			fmt.Printf("%s [%s] -> %s%s%s%s%s\n", n, ct, b.Destination, ports, hdr, tmpl, env)
		}
	}
	return nil
}

func handleCredRemove(args []string) error {
	fs := flag.NewFlagSet("cred remove", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice cred remove <name>")
	}
	name := fs.Arg(0)

	vs, err := openVaultStore(*dbPath)
	if err != nil {
		return err
	}

	// Remove from vault. If already gone (previous partial cleanup),
	// continue to DB cleanup so stale rules/bindings can be removed.
	if err := vs.Remove(name); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("remove: %w", err)
		}
		fmt.Printf("credential %q already removed from vault, cleaning up database\n", name)
	} else {
		fmt.Printf("credential %q removed\n", name)
	}

	// Clean up associated bindings and auto-created rules. Only open the
	// store if the DB file exists to avoid creating it as a side effect of
	// a credential removal.
	if _, statErr := os.Stat(*dbPath); statErr != nil {
		if !os.IsNotExist(statErr) {
			log.Printf("warning: cannot access database %q for cleanup: %v (stale rules/bindings may remain)", *dbPath, statErr)
		}
		return nil
	}

	db, err := store.New(*dbPath)
	if err != nil {
		log.Printf("warning: could not open database %q for cleanup: %v (stale rules/bindings may remain)", *dbPath, err)
		return nil
	}
	defer func() { _ = db.Close() }()

	// Remove rules tagged either by "sluice cred add --destination"
	// (cred-add:<name>) or by "sluice binding add" (binding-add:<name>).
	// Both paths may have produced rules associated with this credential,
	// and failing to clean up either set leaves orphan allow rules in
	// the store.
	var total int64
	for _, src := range []string{
		store.CredAddSourcePrefix + name,
		store.BindingAddSourcePrefix + name,
	} {
		n, rmErr := db.RemoveRulesBySource(src)
		if rmErr != nil {
			log.Printf("warning: failed to remove rules with source %q for credential %q: %v", src, name, rmErr)
			continue
		}
		total += n
	}
	if total > 0 {
		fmt.Printf("removed %d auto-created rule(s) for credential %q\n", total, name)
	}
	removed, rmBindErr := db.RemoveBindingsByCredential(name)
	if rmBindErr != nil {
		log.Printf("warning: failed to remove bindings for %q: %v", name, rmBindErr)
	} else if removed > 0 {
		fmt.Printf("removed %d binding(s) for %q\n", removed, name)
	}

	// Remove credential metadata (type, token_url).
	metaDeleted, rmMetaErr := db.RemoveCredentialMeta(name)
	if rmMetaErr != nil {
		log.Printf("warning: failed to remove credential meta for %q: %v", name, rmMetaErr)
	} else if metaDeleted {
		fmt.Printf("removed credential metadata for %q\n", name)
	}
	return nil
}

// handleCredUpdate replaces the value of an existing credential without
// touching its bindings, rules, or metadata. The caller is prompted for the
// new value (static) or new access/refresh tokens (oauth) on stdin or the
// terminal. The existing value is never displayed. Vault.Add is atomic
// (temp file + rename), so a failed write leaves the old value intact.
//
// Since phantom tokens are deterministic and derived from the credential
// name, they do not need to be regenerated when only the value changes.
// The proxy picks up the new value on the next request or SIGHUP.
func handleCredUpdate(args []string) error {
	fs := flag.NewFlagSet("cred update", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	// Same name-before-flags convention as "cred add": use the shared
	// reorderFlagsBeforePositional helper.
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice cred update <name>")
	}
	name := fs.Arg(0)

	vs, err := openVaultStore(*dbPath)
	if err != nil {
		return err
	}

	// Verify the credential exists before prompting so the user is not
	// asked for a secret and then told the name is invalid.
	names, err := vs.List()
	if err != nil {
		return fmt.Errorf("list credentials: %w", err)
	}
	found := false
	for _, n := range names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("credential %q not found", name)
	}

	// Determine credential type from credential_meta (authoritative source).
	// Using vault.IsOAuth on the stored bytes alone would misclassify a
	// static credential whose value happens to be JSON matching the OAuth
	// shape. We only fall back to payload-shape detection for legacy bare
	// credentials that have no credential_meta row (pre-migration 000002).
	var credMeta *store.CredentialMeta
	if _, statErr := os.Stat(*dbPath); statErr == nil {
		db, dbErr := store.New(*dbPath)
		if dbErr != nil {
			return fmt.Errorf("open store %s: %w", *dbPath, dbErr)
		}
		m, metaErr := db.GetCredentialMeta(name)
		_ = db.Close()
		if metaErr != nil {
			return fmt.Errorf("read credential metadata: %w", metaErr)
		}
		credMeta = m
	}

	// Read the existing credential. For OAuth we need the token URL from the
	// existing blob so we can rebuild the JSON with new tokens but the same
	// endpoint. We also preserve the existing refresh token so an update
	// that only supplies a new access token does not silently clear refresh.
	// The value itself is never shown to the user. The existing secret bytes
	// are released as soon as we have extracted the fields we need.
	existing, err := vs.Get(name)
	if err != nil {
		return fmt.Errorf("read existing credential: %w", err)
	}
	var isOAuth bool
	switch {
	case credMeta != nil:
		isOAuth = credMeta.CredType == "oauth"
	default:
		// Legacy row with no credential_meta. Fall back to payload shape.
		isOAuth = vault.IsOAuth(existing.Bytes())
	}
	var existingTokenURL, existingRefreshToken string
	if isOAuth {
		parsed, parseErr := vault.ParseOAuth(existing.Bytes())
		if parseErr != nil {
			existing.Release()
			return fmt.Errorf("parse existing oauth credential: %w", parseErr)
		}
		existingTokenURL = parsed.TokenURL
		existingRefreshToken = parsed.RefreshToken
	}
	existing.Release()

	// Prompt for the new value(s). Reuses the same helpers as "cred add"
	// so terminal and piped-stdin input work identically. For OAuth we use
	// the preserve-existing variant so pressing Enter (terminal) or
	// omitting the second line (stdin) keeps the stored refresh token.
	var secret []byte
	if isOAuth {
		oauthCred, readErr := readOAuthCredentialForUpdate(existingTokenURL, existingRefreshToken, true)
		if readErr != nil {
			return readErr
		}
		data, marshalErr := oauthCred.Marshal()
		if marshalErr != nil {
			return fmt.Errorf("marshal oauth credential: %w", marshalErr)
		}
		secret = data
	} else {
		s, readErr := readStaticSecretInput()
		if readErr != nil {
			return readErr
		}
		secret = s
	}

	if _, addErr := vs.Add(name, string(secret)); addErr != nil {
		for i := range secret {
			secret[i] = 0
		}
		return fmt.Errorf("update credential: %w", addErr)
	}
	for i := range secret {
		secret[i] = 0
	}

	credType := "static"
	if isOAuth {
		credType = "oauth"
	}
	fmt.Printf("credential %q updated (type: %s)\n", name, credType)
	return nil
}
