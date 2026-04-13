package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
)

func handlePolicyCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice policy [list|add|remove|import|export]")
	}

	switch args[0] {
	case "list":
		return handlePolicyList(args[1:])
	case "add":
		return handlePolicyAdd(args[1:])
	case "remove":
		return handlePolicyRemove(args[1:])
	case "import":
		return handlePolicyImport(args[1:])
	case "export":
		return handlePolicyExport(args[1:])
	default:
		return fmt.Errorf("unknown policy command: %s (usage: sluice policy [list|add|remove|import|export])", args[0])
	}
}

func handlePolicyList(args []string) error {
	fs := flag.NewFlagSet("policy list", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	verdict := fs.String("verdict", "", "filter by verdict (allow, deny, ask)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{Verdict: *verdict})
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	if len(rules) == 0 {
		fmt.Println("no rules found")
		return nil
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
		replacement := ""
		if r.Replacement != "" {
			replacement = fmt.Sprintf(" -> %q", r.Replacement)
		}
		name := ""
		if r.Name != "" {
			name = " (" + r.Name + ")"
		}
		fmt.Printf("[%d] %s %s%s%s%s%s [%s]\n", r.ID, r.Verdict, target, ports, proto, replacement, name, r.Source)
	}
	return nil
}

func handlePolicyAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice policy add <allow|deny|ask> <destination> [--ports 443,80] [--protocols quic,udp] [--name \"reason\"]")
	}

	verdict := args[0]
	if verdict != "allow" && verdict != "deny" && verdict != "ask" {
		return fmt.Errorf("invalid verdict: %s (must be allow, deny, or ask)", verdict)
	}

	fs := flag.NewFlagSet("policy add", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	portsStr := fs.String("ports", "", "comma-separated port list (e.g. 443,80)")
	protocolsStr := fs.String("protocols", "", "comma-separated protocol list (e.g. quic,udp)")
	note := fs.String("name", "", "human-readable name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice policy add <allow|deny|ask> <destination> [--ports 443,80] [--protocols quic,udp] [--name \"reason\"]")
	}
	destination := fs.Arg(0)

	if _, err := policy.CompileGlob(destination); err != nil {
		return fmt.Errorf("invalid destination pattern %q: %w", destination, err)
	}

	ports, err := parsePortsList(*portsStr)
	if err != nil {
		return err
	}

	protocols, err := parseProtocolsList(*protocolsStr)
	if err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	id, err := db.AddRule(verdict, store.RuleOpts{Destination: destination, Ports: ports, Protocols: protocols, Name: *note})
	if err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	fmt.Printf("added %s rule [%d] for %s\n", verdict, id, destination)
	return nil
}

func handlePolicyRemove(args []string) error {
	fs := flag.NewFlagSet("policy remove", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice policy remove <id>")
	}

	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid rule ID %q: %w", fs.Arg(0), err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	deleted, err := db.RemoveRule(id)
	if err != nil {
		return fmt.Errorf("remove rule: %w", err)
	}
	if !deleted {
		return fmt.Errorf("no rule with ID %d", id)
	}
	fmt.Printf("removed rule [%d]\n", id)
	return nil
}

func handlePolicyImport(args []string) error {
	fs := flag.NewFlagSet("policy import", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice policy import <path.toml>")
	}

	tomlPath := fs.Arg(0)
	data, err := os.ReadFile(tomlPath)
	if err != nil {
		return fmt.Errorf("read TOML file: %w", err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	result, err := db.ImportTOML(data)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	fmt.Printf("imported: %d rules (%d skipped), %d bindings (%d skipped), %d upstreams (%d skipped), %d config\n",
		result.RulesInserted, result.RulesSkipped,
		result.BindingsInserted, result.BindingsSkipped,
		result.UpstreamsInserted, result.UpstreamsSkipped,
		result.ConfigSet,
	)
	return nil
}

func handlePolicyExport(args []string) error {
	fs := flag.NewFlagSet("policy export", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Config section.
	cfg, err := db.GetConfig()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
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

	// Warn if sensitive token values exist but are excluded from export.
	for _, val := range []struct {
		v    string
		name string
	}{
		{cfg.VaultHashicorpToken, "vault_hashicorp_token"},
		{cfg.VaultHashicorpRoleID, "vault_hashicorp_role_id"},
		{cfg.VaultHashicorpSecretID, "vault_hashicorp_secret_id"},
		{cfg.Vault1PasswordToken, "vault_1password_token"},
		{cfg.VaultBitwardenToken, "vault_bitwarden_token"},
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

	// Vault 1Password sub-section (token excluded above).
	var opLines []string
	if cfg.Vault1PasswordVault != "" {
		opLines = append(opLines, fmt.Sprintf("vault = %q", cfg.Vault1PasswordVault))
	}
	if cfg.Vault1PasswordField != "" {
		opLines = append(opLines, fmt.Sprintf("field = %q", cfg.Vault1PasswordField))
	}
	if len(opLines) > 0 {
		fmt.Println("[vault.1password]")
		for _, line := range opLines {
			fmt.Println(line)
		}
		fmt.Println()
	}

	// Vault Bitwarden sub-section (token excluded above).
	if cfg.VaultBitwardenOrgID != "" {
		fmt.Println("[vault.bitwarden]")
		fmt.Printf("org_id = %q\n", cfg.VaultBitwardenOrgID)
		fmt.Println()
	}

	// Vault KeePass sub-section.
	var kpLines []string
	if cfg.VaultKeePassPath != "" {
		kpLines = append(kpLines, fmt.Sprintf("path = %q", cfg.VaultKeePassPath))
	}
	if cfg.VaultKeePassKeyFile != "" {
		kpLines = append(kpLines, fmt.Sprintf("key_file = %q", cfg.VaultKeePassKeyFile))
	}
	if len(kpLines) > 0 {
		fmt.Println("[vault.keepass]")
		for _, line := range kpLines {
			fmt.Println(line)
		}
		fmt.Println()
	}

	// Vault Gopass sub-section.
	if cfg.VaultGopassStore != "" {
		fmt.Println("[vault.gopass]")
		fmt.Printf("store = %q\n", cfg.VaultGopassStore)
		fmt.Println()
	}

	// Network rules.
	for _, verdict := range []string{"allow", "deny", "ask"} {
		rules, listErr := db.ListRules(store.RuleFilter{Verdict: verdict, Type: "network"})
		if listErr != nil {
			return fmt.Errorf("list %s rules: %w", verdict, listErr)
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
		toolRules, listErr := db.ListRules(store.RuleFilter{Verdict: verdict, Type: "tool"})
		if listErr != nil {
			return fmt.Errorf("list tool %s rules: %w", verdict, listErr)
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
		return fmt.Errorf("list deny pattern rules: %w", err)
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
		return fmt.Errorf("list redact rules: %w", err)
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
		return fmt.Errorf("list bindings: %w", err)
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
		return fmt.Errorf("list upstreams: %w", err)
	}
	for _, u := range upstreams {
		fmt.Println("[[mcp_upstream]]")
		fmt.Printf("name = %q\n", u.Name)
		fmt.Printf("command = %q\n", u.Command)
		if u.Transport != "" && u.Transport != "stdio" {
			fmt.Printf("transport = %q\n", u.Transport)
		}
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
	return nil
}
