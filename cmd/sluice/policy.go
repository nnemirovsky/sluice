package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
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

	rules, err := db.ListRules(*verdict)
	if err != nil {
		log.Fatalf("list rules: %v", err)
	}

	if len(rules) == 0 {
		fmt.Println("no rules found")
		return
	}

	for _, r := range rules {
		ports := ""
		if len(r.Ports) > 0 {
			portStrs := make([]string, len(r.Ports))
			for i, p := range r.Ports {
				portStrs[i] = strconv.Itoa(p)
			}
			ports = " ports=" + strings.Join(portStrs, ",")
		}
		proto := ""
		if r.Protocol != "" {
			proto = " protocol=" + r.Protocol
		}
		note := ""
		if r.Note != "" {
			note = " (" + r.Note + ")"
		}
		fmt.Printf("[%d] %s %s%s%s%s [%s]\n", r.ID, r.Verdict, r.Destination, ports, proto, note, r.Source)
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

	id, err := db.AddRule(verdict, destination, ports, store.RuleOpts{Note: *note})
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

	fmt.Printf("imported: %d rules (%d skipped), %d tool rules (%d skipped), %d inspect rules, %d bindings (%d skipped), %d upstreams (%d skipped), %d config\n",
		result.RulesInserted, result.RulesSkipped,
		result.ToolRulesInserted, result.ToolRulesSkipped,
		result.InspectInserted,
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
	defaultVerdict, err := db.GetConfig("default_verdict")
	if err != nil {
		log.Fatalf("read config default_verdict: %v", err)
	}
	timeoutStr, err := db.GetConfig("timeout_sec")
	if err != nil {
		log.Fatalf("read config timeout_sec: %v", err)
	}
	if defaultVerdict != "" || timeoutStr != "" {
		fmt.Println("[policy]")
		if defaultVerdict != "" {
			fmt.Printf("default = %q\n", defaultVerdict)
		}
		if timeoutStr != "" {
			fmt.Printf("timeout_sec = %s\n", timeoutStr)
		}
		fmt.Println()
	}

	// Telegram section.
	botTokenEnv, err := db.GetConfig("telegram_bot_token_env")
	if err != nil {
		log.Fatalf("read config telegram_bot_token_env: %v", err)
	}
	chatIDEnv, err := db.GetConfig("telegram_chat_id_env")
	if err != nil {
		log.Fatalf("read config telegram_chat_id_env: %v", err)
	}
	if botTokenEnv != "" || chatIDEnv != "" {
		fmt.Println("[telegram]")
		if botTokenEnv != "" {
			fmt.Printf("bot_token_env = %q\n", botTokenEnv)
		}
		if chatIDEnv != "" {
			fmt.Printf("chat_id_env = %q\n", chatIDEnv)
		}
		fmt.Println()
	}

	// Vault section.
	vaultProvider, err := db.GetConfig("vault_provider")
	if err != nil {
		log.Fatalf("read config vault_provider: %v", err)
	}
	vaultDir, err := db.GetConfig("vault_dir")
	if err != nil {
		log.Fatalf("read config vault_dir: %v", err)
	}
	vaultProviders, err := db.GetConfig("vault_providers")
	if err != nil {
		log.Fatalf("read config vault_providers: %v", err)
	}
	if vaultProvider != "" || vaultDir != "" || vaultProviders != "" {
		fmt.Println("[vault]")
		if vaultProvider != "" {
			fmt.Printf("provider = %q\n", vaultProvider)
		}
		if vaultDir != "" {
			fmt.Printf("dir = %q\n", vaultDir)
		}
		if vaultProviders != "" {
			// vault_providers is stored as a JSON array; output as TOML array.
			fmt.Printf("providers = %s\n", vaultProviders)
		}
		fmt.Println()
	}

	// Vault HashiCorp sub-section. Sensitive values (token, role_id,
	// secret_id) are excluded from export. Use env var indirection instead.
	hcKeys := []struct {
		dbKey, tomlKey string
	}{
		{"vault_hashicorp_addr", "addr"},
		{"vault_hashicorp_mount", "mount"},
		{"vault_hashicorp_prefix", "prefix"},
		{"vault_hashicorp_auth", "auth"},
		{"vault_hashicorp_role_id_env", "role_id_env"},
		{"vault_hashicorp_secret_id_env", "secret_id_env"},
	}
	var hcLines []string
	for _, kv := range hcKeys {
		val, hcErr := db.GetConfig(kv.dbKey)
		if hcErr != nil {
			log.Fatalf("read config %s: %v", kv.dbKey, hcErr)
		}
		if val != "" {
			hcLines = append(hcLines, fmt.Sprintf("%s = %q", kv.tomlKey, val))
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
		rules, err := db.ListRules(verdict)
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
			if r.Protocol != "" {
				fmt.Printf("protocol = %q\n", r.Protocol)
			}
			if r.Note != "" {
				fmt.Printf("note = %q\n", r.Note)
			}
			fmt.Println()
		}
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
		if b.InjectHeader != "" {
			fmt.Printf("inject_header = %q\n", b.InjectHeader)
		}
		if b.Template != "" {
			fmt.Printf("template = %q\n", b.Template)
		}
		if b.Protocol != "" {
			fmt.Printf("protocol = %q\n", b.Protocol)
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
			fmt.Println("[mcp_upstream.env]")
			for k, v := range u.Env {
				fmt.Printf("%s = %q\n", k, v)
			}
		}
		fmt.Println()
	}

	// Tool rules.
	for _, verdict := range []string{"allow", "deny", "ask"} {
		toolRules, err := db.ListToolRules(verdict)
		if err != nil {
			log.Fatalf("list tool_%s rules: %v", verdict, err)
		}
		for _, r := range toolRules {
			fmt.Printf("[[tool_%s]]\n", verdict)
			fmt.Printf("tool = %q\n", r.Tool)
			if r.Note != "" {
				fmt.Printf("note = %q\n", r.Note)
			}
			fmt.Println()
		}
	}

	// Inspect rules.
	inspectRules, err := db.ListInspectRules("")
	if err != nil {
		log.Fatalf("list inspect rules: %v", err)
	}
	for _, r := range inspectRules {
		if r.Kind == "block" {
			fmt.Println("[[inspect_block]]")
			fmt.Printf("pattern = %q\n", r.Pattern)
			if r.Description != "" {
				fmt.Printf("name = %q\n", r.Description)
			}
			fmt.Println()
		} else if r.Kind == "redact" {
			fmt.Println("[[inspect_redact]]")
			fmt.Printf("pattern = %q\n", r.Pattern)
			if r.Replacement != "" {
				fmt.Printf("replacement = %q\n", r.Replacement)
			}
			if r.Description != "" {
				fmt.Printf("name = %q\n", r.Description)
			}
			fmt.Println()
		}
	}
}
