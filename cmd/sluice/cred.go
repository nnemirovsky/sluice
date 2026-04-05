package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
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
	fs := flag.NewFlagSet("cred add", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	destination := fs.String("destination", "", "auto-create allow rule and binding for this destination")
	portsStr := fs.String("ports", "", "comma-separated port list for the allow rule (e.g. 443,80)")
	header := fs.String("header", "", "header for the binding (e.g. Authorization)")
	template := fs.String("template", "", "template for credential injection (e.g. \"Bearer {value}\")")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice cred add <name> [--destination host] [--ports 443] [--header Authorization] [--template \"Bearer {value}\"]")
	}
	name := fs.Arg(0)

	// Read secret from terminal or stdin.
	var secret []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Enter secret: ")
		s, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("read secret: %w", err)
		}
		secret = s
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return fmt.Errorf("read secret from stdin: no input")
		}
		secret = []byte(strings.TrimRight(scanner.Text(), "\r\n"))
	}

	// Validate --destination inputs and open the DB before persisting
	// anything to the vault. This prevents orphaned vault credentials
	// when the glob pattern is invalid, a port is out of range, or the
	// DB path is unreachable.
	var ports []int
	var db *store.Store
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

		var err error
		db, err = store.New(*dbPath)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer func() { _ = db.Close() }()
	}

	// Inputs validated and DB is open. Now persist the credential.
	vs, err := openVaultStore(*dbPath)
	if err != nil {
		return err
	}

	// Back up existing credential ciphertext in case we need to roll back
	// after a DB failure. This prevents losing a previously working secret
	// when overwriting it and then hitting a transient DB error.
	var prevCiphertext []byte
	if db != nil {
		var readErr error
		prevCiphertext, readErr = vs.ReadRawCredential(name)
		if readErr != nil {
			return fmt.Errorf("backup existing credential %q before overwrite: %w", name, readErr)
		}
	}

	ourCiphertext, addErr := vs.Add(name, string(secret))
	for i := range secret {
		secret[i] = 0
	}
	if addErr != nil {
		return fmt.Errorf("add credential: %w", addErr)
	}

	// Create rule and binding atomically. If the DB insert fails, roll back
	// the vault change: restore the previous ciphertext if overwriting, or
	// remove the new file if the credential was brand new. Rollback uses
	// compare-and-swap: only restore/delete if the credential still matches
	// what we wrote, avoiding clobber of concurrent writes.
	if db != nil {
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
			// Compare-and-swap: only rollback if the credential file still
			// contains what we wrote. If a concurrent writer changed it,
			// leave their value in place.
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
			return fmt.Errorf("add rule and binding: %w", err)
		}
		fmt.Printf("credential %q added\n", name)
		fmt.Printf("added allow rule [%d] for %s\n", ruleID, *destination)
		fmt.Printf("added binding [%d] %s -> %s\n", bindingID, *destination, name)
	} else {
		fmt.Printf("credential %q added\n", name)
	}
	return nil
}

func handleCredList(args []string) error {
	fs := flag.NewFlagSet("cred list", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
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

	// Try to open the store to show binding info. Skip if DB doesn't exist
	// to avoid creating files as a side effect of a read-only operation.
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

	for _, n := range names {
		bindings, bErr := db.ListBindingsByCredential(n)
		if bErr != nil || len(bindings) == 0 {
			fmt.Println(n)
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
			fmt.Printf("%s -> %s%s%s%s\n", n, b.Destination, ports, hdr, tmpl)
		}
	}
	return nil
}

func handleCredRemove(args []string) error {
	fs := flag.NewFlagSet("cred remove", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
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
	}
	return nil
}
