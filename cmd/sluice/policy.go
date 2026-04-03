package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
)

func handlePolicyCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice policy [list|add|remove|import|export] ...")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		handlePolicyList(args[1:])
	case "add":
		handlePolicyAdd(args[1:])
	case "remove":
		handlePolicyRemove(args[1:])
	case "import":
		handlePolicyImport(args[1:])
	case "export":
		handlePolicyExport(args[1:])
	default:
		fmt.Printf("unknown policy command: %s\n", args[0])
		fmt.Println("usage: sluice policy [list|add|remove|import|export] ...")
		os.Exit(1)
	}
}

func handlePolicyList(args []string) {
	fs := flag.NewFlagSet("policy list", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	verdict := fs.String("verdict", "", "filter by verdict (allow, deny, ask)")
	fs.Parse(args)

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	rules, err := db.ListRules(store.RuleFilter{Verdict: *verdict})
	if err != nil {
		log.Fatalf("list rules: %v", err)
	}

	if len(rules) == 0 {
		fmt.Println("no rules found")
		return
	}

	for _, r := range rules {
		target := r.Destination
		if target == "" {
			target = r.Tool
		}
		if target == "" {
			target = r.Pattern
		}
		ports := ""
		if len(r.Ports) > 0 {
			portStrs := make([]string, len(r.Ports))
			for i, p := range r.Ports {
				portStrs[i] = strconv.Itoa(p)
			}
			ports = " ports=" + strings.Join(portStrs, ",")
		}
		proto := ""
		if len(r.Protocols) > 0 {
			proto = " protocols=" + strings.Join(r.Protocols, ",")
		}
		name := ""
		if r.Name != "" {
			name = " (" + r.Name + ")"
		}
		fmt.Printf("[%d] %s %s%s%s%s [%s]\n", r.ID, r.Verdict, target, ports, proto, name, r.Source)
	}
}

func handlePolicyAdd(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice policy add <allow|deny|ask> <destination> [--ports 443,80] [--note \"reason\"]")
		os.Exit(1)
	}

	verdict := args[0]
	if verdict != "allow" && verdict != "deny" && verdict != "ask" {
		fmt.Printf("invalid verdict: %s (must be allow, deny, or ask)\n", verdict)
		os.Exit(1)
	}

	fs := flag.NewFlagSet("policy add", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	portsStr := fs.String("ports", "", "comma-separated port list (e.g. 443,80)")
	note := fs.String("note", "", "human-readable note")
	fs.Parse(args[1:])

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice policy add <allow|deny|ask> <destination> [--ports 443,80] [--note \"reason\"]")
		os.Exit(1)
	}
	destination := fs.Arg(0)

	if _, err := policy.CompileGlob(destination); err != nil {
		log.Fatalf("invalid destination pattern %q: %v", destination, err)
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

	id, err := db.AddRule(verdict, store.RuleOpts{Destination: destination, Ports: ports, Name: *note})
	if err != nil {
		log.Fatalf("add rule: %v", err)
	}
	fmt.Printf("added %s rule [%d] for %s\n", verdict, id, destination)
}

func handlePolicyRemove(args []string) {
	fs := flag.NewFlagSet("policy remove", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice policy remove <id>")
		os.Exit(1)
	}

	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		log.Fatalf("invalid rule ID %q: %v", fs.Arg(0), err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	deleted, err := db.RemoveRule(id)
	if err != nil {
		log.Fatalf("remove rule: %v", err)
	}
	if !deleted {
		fmt.Printf("no rule with ID %d\n", id)
		os.Exit(1)
	}
	fmt.Printf("removed rule [%d]\n", id)
}

func handlePolicyImport(args []string) {
	fs := flag.NewFlagSet("policy import", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice policy import <path.toml>")
		os.Exit(1)
	}

	tomlPath := fs.Arg(0)
	data, err := os.ReadFile(tomlPath)
	if err != nil {
		log.Fatalf("read TOML file: %v", err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	result, err := db.ImportTOML(data)
	if err != nil {
		log.Fatalf("import: %v", err)
	}

	fmt.Printf("imported: %d rules (%d skipped), %d bindings (%d skipped), %d upstreams (%d skipped), %d config\n",
		result.RulesInserted, result.RulesSkipped,
		result.BindingsInserted, result.BindingsSkipped,
		result.UpstreamsInserted, result.UpstreamsSkipped,
		result.ConfigSet,
	)
}

func handlePolicyExport(args []string) {
	fs := flag.NewFlagSet("policy export", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	fs.Parse(args)

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	// Config section.
	cfg, err := db.GetConfig()
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	if cfg.DefaultVerdict != "" || cfg.TimeoutSec != 0 {
		fmt.Println("[policy]")
		if cfg.DefaultVerdict != "" {
			fmt.Printf("default = %q\n", cfg.DefaultVerdict)
		}
		if cfg.TimeoutSec != 0 {
			fmt.Printf("timeout_sec = %d\n", cfg.TimeoutSec)
		}
		fmt.Println()
	}

	// Vault section.
	if cfg.VaultProvider != "" || cfg.VaultDir != "" || len(cfg.VaultProviders) > 0 {
		fmt.Println("[vault]")
		if cfg.VaultProvider != "" {
			fmt.Printf("provider = %q\n", cfg.VaultProvider)
		}
		if cfg.VaultDir != "" {
			fmt.Printf("dir = %q\n", cfg.VaultDir)
		}
		if len(cfg.VaultProviders) > 0 {
			quoted := make([]string, len(cfg.VaultProviders))
			for i, p := range cfg.VaultProviders {
				quoted[i] = fmt.Sprintf("%q", p)
			}
			fmt.Printf("providers = [%s]\n", strings.Join(quoted, ", "))
		}
		fmt.Println()
	}

	// Warn if sensitive HashiCorp values exist but are excluded from export.
	for _, val := range []struct {
		v    string
		name string
	}{
		{cfg.VaultHashicorpToken, "vault_hashicorp_token"},
		{cfg.VaultHashicorpRoleID, "vault_hashicorp_role_id"},
		{cfg.VaultHashicorpSecretID, "vault_hashicorp_secret_id"},
	} {
		if val.v != "" {
			fmt.Fprintf(os.Stderr, "warning: %s excluded from export (use env var indirection instead)\n", val.name)
		}
	}

	// Vault HashiCorp sub-section.
	var hcLines []string
	hcPairs := []struct {
		val, key string
	}{
		{cfg.VaultHashicorpAddr, "addr"},
		{cfg.VaultHashicorpMount, "mount"},
		{cfg.VaultHashicorpPrefix, "prefix"},
		{cfg.VaultHashicorpAuth, "auth"},
		{cfg.VaultHashicorpRoleIDEnv, "role_id_env"},
		{cfg.VaultHashicorpSecretIDEnv, "secret_id_env"},
	}
	for _, kv := range hcPairs {
		if kv.val != "" {
			hcLines = append(hcLines, fmt.Sprintf("%s = %q", kv.key, kv.val))
		}
	}
	if len(hcLines) > 0 {
		fmt.Println("[vault.hashicorp]")
		for _, line := range hcLines {
			fmt.Println(line)
		}
		fmt.Println()
	}

	// Network rules.
	for _, verdict := range []string{"allow", "deny", "ask"} {
		rules, err := db.ListRules(store.RuleFilter{Verdict: verdict, Type: "network"})
		if err != nil {
			log.Fatalf("list %s rules: %v", verdict, err)
		}
		for _, r := range rules {
			fmt.Printf("[[%s]]\n", verdict)
			fmt.Printf("destination = %q\n", r.Destination)
			if len(r.Ports) > 0 {
				portsJSON, _ := json.Marshal(r.Ports)
				fmt.Printf("ports = %s\n", string(portsJSON))
			}
			if len(r.Protocols) > 0 {
				protocolsJSON, _ := json.Marshal(r.Protocols)
				fmt.Printf("protocols = %s\n", string(protocolsJSON))
			}
			if r.Name != "" {
				fmt.Printf("name = %q\n", r.Name)
			}
			fmt.Println()
		}
	}

	// Tool rules (exported as [[allow]], [[deny]], [[ask]] with tool field).
	for _, verdict := range []string{"allow", "deny", "ask"} {
		toolRules, err := db.ListRules(store.RuleFilter{Verdict: verdict, Type: "tool"})
		if err != nil {
			log.Fatalf("list tool %s rules: %v", verdict, err)
		}
		for _, r := range toolRules {
			fmt.Printf("[[%s]]\n", verdict)
			fmt.Printf("tool = %q\n", r.Tool)
			if r.Name != "" {
				fmt.Printf("name = %q\n", r.Name)
			}
			fmt.Println()
		}
	}

	// Content deny rules (pattern-based, exported as [[deny]] with pattern field).
	denyPatterns, err := db.ListRules(store.RuleFilter{Verdict: "deny", Type: "pattern"})
	if err != nil {
		log.Fatalf("list deny pattern rules: %v", err)
	}
	for _, r := range denyPatterns {
		fmt.Println("[[deny]]")
		fmt.Printf("pattern = %q\n", r.Pattern)
		if r.Name != "" {
			fmt.Printf("name = %q\n", r.Name)
		}
		fmt.Println()
	}

	// Redact rules (exported as [[redact]]).
	redactRules, err := db.ListRules(store.RuleFilter{Verdict: "redact", Type: "pattern"})
	if err != nil {
		log.Fatalf("list redact rules: %v", err)
	}
	for _, r := range redactRules {
		fmt.Println("[[redact]]")
		fmt.Printf("pattern = %q\n", r.Pattern)
		if r.Replacement != "" {
			fmt.Printf("replacement = %q\n", r.Replacement)
		}
		if r.Name != "" {
			fmt.Printf("name = %q\n", r.Name)
		}
		fmt.Println()
	}

	// Bindings.
	bindings, err := db.ListBindings()
	if err != nil {
		log.Fatalf("list bindings: %v", err)
	}
	for _, b := range bindings {
		fmt.Println("[[binding]]")
		fmt.Printf("destination = %q\n", b.Destination)
		if len(b.Ports) > 0 {
			portsJSON, _ := json.Marshal(b.Ports)
			fmt.Printf("ports = %s\n", string(portsJSON))
		}
		fmt.Printf("credential = %q\n", b.Credential)
		if b.Header != "" {
			fmt.Printf("header = %q\n", b.Header)
		}
		if b.Template != "" {
			fmt.Printf("template = %q\n", b.Template)
		}
		if len(b.Protocols) > 0 {
			protocolsJSON, _ := json.Marshal(b.Protocols)
			fmt.Printf("protocols = %s\n", string(protocolsJSON))
		}
		fmt.Println()
	}

	// MCP upstreams.
	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		log.Fatalf("list upstreams: %v", err)
	}
	for _, u := range upstreams {
		fmt.Println("[[mcp_upstream]]")
		fmt.Printf("name = %q\n", u.Name)
		fmt.Printf("command = %q\n", u.Command)
		if len(u.Args) > 0 {
			argsJSON, _ := json.Marshal(u.Args)
			fmt.Printf("args = %s\n", string(argsJSON))
		}
		if u.TimeoutSec != 120 {
			fmt.Printf("timeout_sec = %d\n", u.TimeoutSec)
		}
		if len(u.Env) > 0 {
			keys := make([]string, 0, len(u.Env))
			for k := range u.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(u.Env))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%q = %q", k, u.Env[k]))
			}
			fmt.Printf("env = {%s}\n", strings.Join(parts, ", "))
		}
		fmt.Println()
	}
}
