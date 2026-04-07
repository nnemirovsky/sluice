package main

import (
	"bufio"
	"bytes"
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

// credAddSourcePrefix is the source tag prefix for rules auto-created by
// "sluice cred add --destination". The full source is "cred-add:<credential_name>"
// so that removing one credential does not delete rules belonging to another
// credential that shares the same destination.
const credAddSourcePrefix = "cred-add:"

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
	default:
		return fmt.Errorf("unknown cred command: %s (usage: sluice cred [add|list|remove] ...)", args[0])
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
	// Reorder args so the positional name is always at the end.
	// Go's flag package stops at the first non-flag argument, so
	// "cred add myname --type oauth" silently ignores --type.
	// We move the name to the end: "cred add --type oauth myname".
	args = reorderPositionalLast(args)

	fs := flag.NewFlagSet("cred add", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	destination := fs.String("destination", "", "auto-create allow rule and binding for this destination")
	portsStr := fs.String("ports", "", "comma-separated port list for the allow rule (e.g. 443,80)")
	header := fs.String("header", "", "header for the binding (e.g. Authorization)")
	template := fs.String("template", "", "template for credential injection (e.g. \"Bearer {value}\")")
	credType := fs.String("type", "static", "credential type: static or oauth")
	tokenURL := fs.String("token-url", "", "OAuth token endpoint URL (required when type=oauth)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice cred add <name> [--type static|oauth] [--token-url URL] [--destination host] [--ports 443] [--header Authorization] [--template \"Bearer {value}\"]")
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

	if *destination != "" {
		if _, err := policy.CompileGlob(*destination); err != nil {
			return fmt.Errorf("invalid destination pattern %q: %w", *destination, err)
		}

		if *portsStr != "" {
			for _, ps := range strings.Split(*portsStr, ",") {
				ps = strings.TrimSpace(ps)
				p, err := strconv.Atoi(ps)
				if err != nil {
					return fmt.Errorf("invalid port %q: %w", ps, err)
				}
				if p < 1 || p > 65535 {
					return fmt.Errorf("port %d out of range (1-65535)", p)
				}
				ports = append(ports, p)
			}
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

	// rollbackVault restores or removes the vault credential on DB failure.
	rollbackVault := func() {
		currentCiphertext, casErr := vs.ReadRawCredential(name)
		concurrentWrite := casErr != nil || !bytes.Equal(currentCiphertext, ourCiphertext)
		if concurrentWrite {
			log.Printf("warning: credential %q was modified concurrently; skipping vault rollback", name)
		} else if prevCiphertext != nil {
			if restoreErr := vs.WriteRawCredential(name, prevCiphertext); restoreErr != nil {
				log.Printf("warning: failed to restore previous credential %q after DB error: %v", name, restoreErr)
			}
		} else {
			if rmErr := vs.Remove(name); rmErr != nil {
				log.Printf("warning: failed to clean up vault credential %q after DB error: %v", name, rmErr)
			}
		}
	}

	// Store credential_meta for all credential types.
	if err := db.AddCredentialMeta(name, *credType, *tokenURL); err != nil {
		rollbackVault()
		return fmt.Errorf("add credential meta: %w", err)
	}

	// Create rule and binding atomically. If the DB insert fails, roll back
	// the vault change: restore the previous ciphertext if overwriting, or
	// remove the new file if the credential was brand new. Rollback uses
	// compare-and-swap: only restore/delete if the credential still matches
	// what we wrote, avoiding clobber of concurrent writes.
	if *destination != "" {
		ruleID, bindingID, err := db.AddRuleAndBinding(
			"allow",
			store.RuleOpts{
				Destination: *destination,
				Ports:       ports,
				Name:        fmt.Sprintf("auto-created for credential %q", name),
				Source:      credAddSourcePrefix + name,
			},
			name,
			store.BindingOpts{
				Ports:    ports,
				Header:   *header,
				Template: *template,
			},
		)
		if err != nil {
			// Also clean up credential_meta if it was just created.
			if _, rmErr := db.RemoveCredentialMeta(name); rmErr != nil {
				log.Printf("warning: failed to remove credential meta for %q after rule/binding error: %v", name, rmErr)
			}
			rollbackVault()
			return fmt.Errorf("add rule and binding: %w", err)
		}
		fmt.Printf("credential %q added (type: %s)\n", name, *credType)
		fmt.Printf("added allow rule [%d] for %s\n", ruleID, *destination)
		fmt.Printf("added binding [%d] %s -> %s\n", bindingID, *destination, name)
	} else {
		fmt.Printf("credential %q added (type: %s)\n", name, *credType)
	}

	// Report OAuth phantom env var names so the operator knows what the
	// agent container will see after secrets are reloaded.
	if *credType == "oauth" {
		envAccess := vault.CredNameToEnvVar(name) + "_ACCESS"
		envRefresh := vault.CredNameToEnvVar(name) + "_REFRESH"
		fmt.Printf("oauth phantom env vars: %s, %s\n", envAccess, envRefresh)
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
	var accessToken, refreshToken string

	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Enter access token: ")
		at, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read access token: %w", err)
		}
		accessToken = string(at)

		fmt.Print("Enter refresh token (press Enter to skip): ")
		rt, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read refresh token: %w", err)
		}
		refreshToken = string(rt)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return nil, fmt.Errorf("read access token from stdin: no input")
		}
		accessToken = strings.TrimRight(scanner.Text(), "\r\n")
		if scanner.Scan() {
			refreshToken = strings.TrimRight(scanner.Text(), "\r\n")
		}
	}

	if accessToken == "" {
		return nil, fmt.Errorf("access token is required for oauth credentials")
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
			fmt.Printf("%s [%s] -> %s%s%s%s\n", n, ct, b.Destination, ports, hdr, tmpl)
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

	// Clean up associated bindings and auto-created rules.
	// Only open the store if the DB file exists to avoid creating it as a side effect.
	dbExists := false
	if _, statErr := os.Stat(*dbPath); statErr == nil {
		dbExists = true
	} else if !os.IsNotExist(statErr) {
		log.Printf("warning: cannot access database %q for cleanup: %v (stale rules/bindings may remain)", *dbPath, statErr)
	}
	var db *store.Store
	var dbErr error
	if dbExists {
		db, dbErr = store.New(*dbPath)
	} else {
		dbErr = fmt.Errorf("database file not found or inaccessible")
	}
	if dbErr != nil && dbExists {
		log.Printf("warning: could not open database %q for cleanup: %v (stale rules/bindings may remain)", *dbPath, dbErr)
	}
	if dbErr == nil {
		defer func() { _ = db.Close() }()

		credSource := credAddSourcePrefix + name
		n, rmErr := db.RemoveRulesBySource(credSource)
		if rmErr != nil {
			log.Printf("warning: failed to remove rules for credential %q: %v", name, rmErr)
		} else if n > 0 {
			fmt.Printf("removed %d auto-created rule(s) for credential %q\n", n, name)
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
	}
	return nil
}

// reorderPositionalLast moves the first positional (non-flag) argument to the
// end of the slice so Go's flag package sees all flags before stopping at the
// positional. Flags and their values (e.g. "--db path") are kept in order.
// This lets users write "cred add myname --type oauth" or
// "cred add --type oauth myname" interchangeably.
func reorderPositionalLast(args []string) []string {
	// Known flags that consume the next argument as a value.
	valueFlags := map[string]bool{
		"-db": true, "--db": true,
		"-destination": true, "--destination": true,
		"-ports": true, "--ports": true,
		"-header": true, "--header": true,
		"-template": true, "--template": true,
		"-type": true, "--type": true,
		"-token-url": true, "--token-url": true,
	}

	var positional string
	var reordered []string
	skip := false
	for i, a := range args {
		if skip {
			skip = false
			reordered = append(reordered, a)
			continue
		}
		if strings.HasPrefix(a, "-") {
			reordered = append(reordered, a)
			if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
				skip = true
			}
			continue
		}
		if positional == "" {
			positional = a
		} else {
			reordered = append(reordered, a)
		}
	}
	if positional != "" {
		reordered = append(reordered, positional)
	}
	return reordered
}
