package main

import (
	"bufio"
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

func openVaultStore() *vault.Store {
	vaultDir := os.Getenv("SLUICE_VAULT_DIR")
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

	vs := openVaultStore()
	addErr := vs.Add(name, string(secret))
	for i := range secret {
		secret[i] = 0
	}
	if addErr != nil {
		log.Fatalf("add credential: %v", addErr)
	}
	fmt.Printf("credential %q added\n", name)

	// If --destination is provided, also create an allow rule and binding.
	if *destination != "" {
		if _, err := policy.CompileGlob(*destination); err != nil {
			log.Fatalf("invalid destination pattern %q: %v", *destination, err)
		}

		var ports []int
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

		db, err := store.New(*dbPath)
		if err != nil {
			log.Fatalf("open store: %v", err)
		}
		defer db.Close()

		ruleID, err := db.AddRule("allow", *destination, ports, store.RuleOpts{
			Note:   fmt.Sprintf("auto-created for credential %q", name),
			Source: credAddSourcePrefix + name,
		})
		if err != nil {
			log.Fatalf("add allow rule: %v", err)
		}
		fmt.Printf("added allow rule [%d] for %s\n", ruleID, *destination)

		bindingID, err := db.AddBinding(*destination, name, store.BindingOpts{
			Ports:        ports,
			InjectHeader: *header,
			Template:     *template,
		})
		if err != nil {
			log.Fatalf("add binding: %v", err)
		}
		fmt.Printf("added binding [%d] %s -> %s\n", bindingID, *destination, name)
	}
}

func handleCredList(args []string) {
	fs := flag.NewFlagSet("cred list", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	fs.Parse(args)

	vs := openVaultStore()
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

	vs := openVaultStore()

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
	}
	var db *store.Store
	var dbErr error
	if dbExists {
		db, dbErr = store.New(*dbPath)
	} else {
		dbErr = fmt.Errorf("database file not found")
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
