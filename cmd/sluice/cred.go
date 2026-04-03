package main

import (
	"bufio"
	"bytes"
	"encoding/json"
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

func handleCredCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice cred [add|list|remove] ...")
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		handleCredAdd(args[1:])
	case "list":
		handleCredList(args[1:])
	case "remove":
		handleCredRemove(args[1:])
	default:
		fmt.Printf("unknown cred command: %s\n", args[0])
		fmt.Println("usage: sluice cred [add|list|remove] ...")
		os.Exit(1)
	}
}

// openVaultStore opens the age-encrypted vault store for CLI credential
// management. It reads vault_dir and vault_provider from the SQLite config
// to ensure the CLI operates on the same backend as the running proxy.
// If a non-age provider is configured, it returns an error so the caller
// can report it clearly instead of silently mutating the wrong backend.
func openVaultStore(dbPath string) *vault.Store {
	var vaultDir string

	// Read vault_dir and provider from the DB to ensure the CLI uses the
	// same backend as the running proxy.
	if dbPath != "" {
		if _, statErr := os.Stat(dbPath); statErr != nil && !os.IsNotExist(statErr) {
			log.Fatalf("cannot access database %s: %v", dbPath, statErr)
		} else if statErr == nil {
			db, dbErr := store.New(dbPath)
			if dbErr != nil {
				log.Fatalf("open store %s: %v", dbPath, dbErr)
			}
			dir, dirErr := db.GetConfig("vault_dir")
			if dirErr != nil {
				db.Close()
				log.Fatalf("read vault_dir from store: %v", dirErr)
			}
			if dir != "" {
				vaultDir = dir
			}
			prov, provErr := db.GetConfig("vault_provider")
			if provErr != nil {
				db.Close()
				log.Fatalf("read vault_provider from store: %v", provErr)
			}

			// Also check vault_providers (chain provider config). The proxy
			// runtime prefers vault_providers over vault_provider when both
			// are set, so we must check it to avoid silently writing to the
			// wrong backend.
			providersJSON, chainErr := db.GetConfig("vault_providers")
			if chainErr != nil {
				db.Close()
				log.Fatalf("read vault_providers from store: %v", chainErr)
			}
			db.Close()

			// If a chain provider is configured, verify that the age backend
			// is part of the chain. If age is not included, the CLI would
			// write credentials that the proxy never reads.
			if providersJSON != "" {
				var providers []string
				if err := json.Unmarshal([]byte(providersJSON), &providers); err != nil {
					log.Fatalf("parse vault_providers config: %v", err)
				}
				hasAge := false
				ageFirst := false
				for i, p := range providers {
					if p == "age" {
						hasAge = true
						if i == 0 {
							ageFirst = true
						}
						break
					}
				}
				if !hasAge {
					log.Fatalf("vault_providers is configured as %v without the age backend. "+
						"CLI credential management only supports the age backend. "+
						"Manage credentials through the configured providers' native tools.", providers)
				}
				if !ageFirst {
					log.Printf("warning: vault_providers is %v. The age backend is not the "+
						"primary provider. Credentials added via CLI may be shadowed by "+
						"earlier providers in the chain.", providers)
				}
			} else if prov != "" && prov != "age" {
				// Single provider that is not age.
				log.Fatalf("vault provider is %q; CLI credential management only supports the age backend. "+
					"Manage credentials through the %s provider's native tools.", prov, prov)
			}
		}
	}

	if vaultDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("determine home dir: %v", err)
		}
		vaultDir = filepath.Join(home, ".sluice")
	}

	vs, err := vault.NewStore(vaultDir)
	if err != nil {
		log.Fatalf("open vault: %v", err)
	}
	return vs
}

func handleCredAdd(args []string) {
	fs := flag.NewFlagSet("cred add", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	destination := fs.String("destination", "", "auto-create allow rule and binding for this destination")
	portsStr := fs.String("ports", "", "comma-separated port list for the allow rule (e.g. 443,80)")
	header := fs.String("header", "", "inject_header for the binding (e.g. Authorization)")
	template := fs.String("template", "", "template for credential injection (e.g. \"Bearer {value}\")")
	fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice cred add <name> [--destination host] [--ports 443] [--header Authorization] [--template \"Bearer {value}\"]")
		os.Exit(1)
	}
	name := fs.Arg(0)

	// Read secret from terminal or stdin.
	var secret []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Enter secret: ")
		s, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("read secret: %v", err)
		}
		secret = s
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Fatalf("read secret from stdin: no input")
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
			log.Fatalf("invalid destination pattern %q: %v", *destination, err)
		}

		if *portsStr != "" {
			for _, ps := range strings.Split(*portsStr, ",") {
				ps = strings.TrimSpace(ps)
				p, err := strconv.Atoi(ps)
				if err != nil {
					log.Fatalf("invalid port %q: %v", ps, err)
				}
				if p < 1 || p > 65535 {
					log.Fatalf("port %d out of range (1-65535)", p)
				}
				ports = append(ports, p)
			}
		}

		var err error
		db, err = store.New(*dbPath)
		if err != nil {
			log.Fatalf("open store: %v", err)
		}
		defer db.Close()
	}

	// Inputs validated and DB is open. Now persist the credential.
	vs := openVaultStore(*dbPath)

	// Back up existing credential ciphertext in case we need to roll back
	// after a DB failure. This prevents losing a previously working secret
	// when overwriting it and then hitting a transient DB error.
	var prevCiphertext []byte
	if db != nil {
		var readErr error
		prevCiphertext, readErr = vs.ReadRawCredential(name)
		if readErr != nil {
			log.Fatalf("backup existing credential %q before overwrite: %v", name, readErr)
		}
	}

	ourCiphertext, addErr := vs.Add(name, string(secret))
	for i := range secret {
		secret[i] = 0
	}
	if addErr != nil {
		log.Fatalf("add credential: %v", addErr)
	}

	// Create rule and binding atomically. If the DB insert fails, roll back
	// the vault change: restore the previous ciphertext if overwriting, or
	// remove the new file if the credential was brand new. Rollback uses
	// compare-and-swap: only restore/delete if the credential still matches
	// what we wrote, avoiding clobber of concurrent writes.
	if db != nil {
		ruleID, bindingID, err := db.AddRuleAndBinding(
			"allow", *destination, ports,
			store.RuleOpts{
				Note:   fmt.Sprintf("auto-created for credential %q", name),
				Source: credAddSourcePrefix + name,
			},
			name,
			store.BindingOpts{
				Ports:        ports,
				InjectHeader: *header,
				Template:     *template,
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
			log.Fatalf("add rule and binding: %v", err)
		}
		fmt.Printf("credential %q added\n", name)
		fmt.Printf("added allow rule [%d] for %s\n", ruleID, *destination)
		fmt.Printf("added binding [%d] %s -> %s\n", bindingID, *destination, name)
	} else {
		fmt.Printf("credential %q added\n", name)
	}
}

func handleCredList(args []string) {
	fs := flag.NewFlagSet("cred list", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	fs.Parse(args)

	vs := openVaultStore(*dbPath)
	names, err := vs.List()
	if err != nil {
		log.Fatalf("list: %v", err)
	}

	if len(names) == 0 {
		return
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
		return
	}
	db, dbErr := store.New(*dbPath)
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open store %s: %v\n", *dbPath, dbErr)
		for _, n := range names {
			fmt.Println(n)
		}
		return
	}
	defer db.Close()

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
			if b.InjectHeader != "" {
				hdr = " header=" + b.InjectHeader
			}
			tmpl := ""
			if b.Template != "" {
				tmpl = " template=" + b.Template
			}
			fmt.Printf("%s -> %s%s%s%s\n", n, b.Destination, ports, hdr, tmpl)
		}
	}
}

func handleCredRemove(args []string) {
	fs := flag.NewFlagSet("cred remove", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice cred remove <name>")
		os.Exit(1)
	}
	name := fs.Arg(0)

	vs := openVaultStore(*dbPath)

	// Remove from vault. If already gone (previous partial cleanup),
	// continue to DB cleanup so stale rules/bindings can be removed.
	if err := vs.Remove(name); err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("remove: %v", err)
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
		defer db.Close()

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
}
