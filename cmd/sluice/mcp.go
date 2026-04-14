package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/mcp"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/telegram"
	"github.com/nemirovsky/sluice/internal/vault"
)

func handleMCPCommand(args []string) error {
	// Route subcommands: add, list, remove manage upstreams in the store.
	// No args or flag-style args start the gateway as before.
	if len(args) > 0 {
		switch args[0] {
		case "add":
			return handleMCPAdd(args[1:])
		case "list":
			return handleMCPList(args[1:])
		case "remove":
			return handleMCPRemove(args[1:])
		default:
			// Only start the gateway for flag-style args (e.g. --db).
			// Reject unrecognized subcommands to avoid confusing silent
			// gateway startup on typos like "sluice mcp rmeove".
			if !strings.HasPrefix(args[0], "-") {
				return fmt.Errorf("unknown mcp subcommand %q (valid: add, list, remove)", args[0])
			}
		}
	}

	return handleMCPGateway(args)
}

func handleMCPGateway(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	configPath := fs.String("config", "", "path to config TOML file (seeds DB on first run if DB is empty)")
	auditPath := fs.String("audit", "", "path to audit log file (optional)")
	telegramToken := fs.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := fs.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Open the SQLite store.
	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// If --config is specified and the DB is empty, auto-import the TOML file as seed.
	if *configPath != "" {
		empty, err := db.IsEmpty()
		if err != nil {
			return fmt.Errorf("check store: %w", err)
		}
		if empty {
			data, err := os.ReadFile(*configPath)
			if err != nil {
				return fmt.Errorf("read config seed file: %w", err)
			}
			result, err := db.ImportTOML(data)
			if err != nil {
				return fmt.Errorf("import config seed: %w", err)
			}
			log.Printf("seeded DB from %s: %d rules, %d bindings, %d upstreams, %d config",
				*configPath, result.RulesInserted,
				result.BindingsInserted, result.UpstreamsInserted, result.ConfigSet)
		}
	}

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	// Read MCP upstreams from the store.
	upstreamRows, err := db.ListMCPUpstreams()
	if err != nil {
		return fmt.Errorf("list MCP upstreams: %w", err)
	}
	upstreams := make([]mcp.UpstreamConfig, len(upstreamRows))
	for i, r := range upstreamRows {
		upstreams[i] = mcp.UpstreamConfig{
			Name:       r.Name,
			Command:    r.Command,
			Args:       r.Args,
			Env:        r.Env,
			Headers:    r.Headers,
			TimeoutSec: r.TimeoutSec,
			Transport:  r.Transport,
		}
	}

	// Build tool policy from engine's tool rules.
	toolRules := eng.ToolRules()
	toolPolicy, err := mcp.NewToolPolicy(toolRules, eng.Default)
	if err != nil {
		return fmt.Errorf("compile tool policy: %w", err)
	}
	log.Printf("MCP tool policy: %d rules (default: %s)", len(toolRules), eng.Default)

	// Optional audit logger.
	var logger *audit.FileLogger
	if *auditPath != "" {
		logger, err = audit.NewFileLogger(*auditPath)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		defer func() { _ = logger.Close() }()
	}

	// Optional Telegram approval channel and broker.
	// Check the store-backed channel enabled flag before parsing env vars
	// so a disabled channel skips setup entirely (avoids error on malformed
	// TELEGRAM_CHAT_ID when the channel is disabled in the store).
	var broker *channel.Broker
	telegramStoreDisabled := false
	if ch, chErr := db.GetChannel(1); chErr != nil {
		log.Printf("WARNING: failed to read channel state from store: %v", chErr)
	} else if ch != nil && !ch.Enabled {
		log.Printf("telegram channel disabled in store (ask rules will auto-deny)")
		telegramStoreDisabled = true
	}
	if !telegramStoreDisabled && *telegramToken != "" && *telegramChatIDStr != "" {
		chatID, parseErr := strconv.ParseInt(*telegramChatIDStr, 10, 64)
		if parseErr != nil {
			return fmt.Errorf("invalid telegram-chat-id: %w", parseErr)
		}
		if chatID != 0 {
			var enginePtr atomic.Pointer[policy.Engine]
			enginePtr.Store(eng)
			var reloadMu sync.Mutex
			tgChannel, channelErr := telegram.NewTelegramChannel(telegram.ChannelConfig{
				Token:     *telegramToken,
				ChatID:    chatID,
				EnginePtr: &enginePtr,
				ReloadMu:  &reloadMu,
				AuditPath: *auditPath,
				Store:     db,
			})
			if channelErr != nil {
				return fmt.Errorf("telegram channel: %w", channelErr)
			}
			broker = channel.NewBroker([]channel.Channel{tgChannel})
			tgChannel.SetBroker(broker)
			if err := tgChannel.Start(); err != nil {
				return fmt.Errorf("start telegram channel: %w", err)
			}
			defer tgChannel.Stop()
			log.Printf("telegram approval channel started for MCP gateway")
		}
	}

	// Optional content inspector for argument blocking and response redaction.
	var inspector *mcp.ContentInspector
	if len(eng.InspectBlockRules) > 0 || len(eng.InspectRedactRules) > 0 {
		inspector, err = mcp.NewContentInspector(eng.InspectBlockRules, eng.InspectRedactRules)
		if err != nil {
			return fmt.Errorf("create content inspector: %w", err)
		}
		log.Printf("content inspector: %d block rules, %d redact rules",
			len(eng.InspectBlockRules), len(eng.InspectRedactRules))
	}

	// Wire the exec argument inspector with default tool name patterns
	// (*exec*, *shell*, *run_command*, *terminal*). Blocks trampoline
	// patterns, dangerous commands, and GIT_SSH_COMMAND-style env
	// overrides before the tool call reaches the upstream.
	execInspector, err := mcp.NewExecInspector(nil)
	if err != nil {
		return fmt.Errorf("create exec inspector: %w", err)
	}

	// Build credential resolver so vault: prefixed env values in upstream
	// configs are resolved to real credentials.
	var credResolver mcp.CredentialResolver
	vaultCfg, err := readVaultConfig(db)
	if err != nil {
		log.Printf("vault config unavailable (vault: env values will not be resolved): %v", err)
	} else {
		provider, provErr := vault.NewProviderFromConfig(vaultCfg)
		if provErr != nil {
			log.Printf("vault provider unavailable (vault: env values will not be resolved): %v", provErr)
		} else {
			credResolver = func(name string) (string, error) {
				sb, getErr := provider.Get(name)
				if getErr != nil {
					return "", getErr
				}
				val := sb.String()
				sb.Release()
				return val, nil
			}
		}
	}

	gw, err := mcp.NewGateway(mcp.GatewayConfig{
		Upstreams:          upstreams,
		ToolPolicy:         toolPolicy,
		Inspector:          inspector,
		ExecInspector:      execInspector,
		Audit:              logger,
		Broker:             broker,
		TimeoutSec:         eng.TimeoutSec,
		Store:              db,
		CredentialResolver: credResolver,
	})
	if err != nil {
		return fmt.Errorf("start MCP gateway: %w", err)
	}
	defer gw.Stop()

	log.Printf("MCP gateway ready: %d tools from %d upstreams", len(gw.Tools()), len(upstreams))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- gw.RunStdio()
	}()

	select {
	case <-sigCh:
		log.Println("MCP gateway shutting down...")
		// Cancel pending Telegram approval requests so tool calls
		// blocked on approval can complete promptly.
		if broker != nil {
			broker.CancelAll()
		}
	case err := <-errCh:
		if err != nil {
			log.Printf("MCP gateway error: %v", err)
			return err
		}
		log.Println("MCP gateway stdin closed, exiting")
	}
	return nil
}

func handleMCPAdd(args []string) error {
	fs := flag.NewFlagSet("mcp add", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	command := fs.String("command", "", "command to run (stdio) or URL (http/websocket)")
	argsStr := fs.String("args", "", "comma-separated arguments for the command")
	envStr := fs.String("env", "", "comma-separated KEY=VAL environment variables (VAL may be vault:<name> for the whole value, or contain {vault:<name>} substrings for templated substitution)")
	timeout := fs.Int("timeout", 120, "upstream timeout in seconds")
	transport := fs.String("transport", "stdio", "transport type: stdio, http, or websocket")
	headers := make(map[string]string)
	fs.Func("header", "HTTP header to send on every request to an http upstream (repeatable, format: KEY=VAL; VAL may be vault:<name> for the whole value, or contain {vault:<name>} substrings for templated substitution, e.g. \"Authorization=Bearer {vault:github_pat}\")", func(s string) error {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format %q (expected KEY=VAL)", s)
		}
		headers[parts[0]] = parts[1]
		return nil
	})
	// Go's stdlib flag parser stops at the first non-flag argument. Reorder
	// so positional args (upstream name) can come before flags too.
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 || *command == "" {
		return fmt.Errorf("usage: sluice mcp add <name> --command <cmd> [--transport stdio|http|websocket] [--args \"arg1,arg2\"] [--env \"KEY=VAL,...\"] [--header \"KEY=VAL\" ...] [--timeout 120]")
	}
	name := fs.Arg(0)

	if err := mcp.ValidateUpstreamName(name); err != nil {
		return fmt.Errorf("invalid upstream name: %w", err)
	}

	if !mcp.ValidTransport(*transport) {
		return fmt.Errorf("invalid transport %q: must be stdio, http, or websocket", *transport)
	}

	if len(headers) > 0 && *transport != "http" {
		return fmt.Errorf("--header is only valid for --transport http")
	}

	var cmdArgs []string
	if *argsStr != "" {
		cmdArgs = strings.Split(*argsStr, ",")
	}

	env := make(map[string]string)
	if *envStr != "" {
		for _, kv := range strings.Split(*envStr, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid env format %q (expected KEY=VAL)", kv)
			}
			env[parts[0]] = parts[1]
		}
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	id, err := db.AddMCPUpstream(name, *command, store.MCPUpstreamOpts{
		Args:       cmdArgs,
		Env:        env,
		Headers:    headers,
		TimeoutSec: *timeout,
		Transport:  *transport,
	})
	if err != nil {
		return fmt.Errorf("add upstream: %w", err)
	}
	fmt.Printf("added MCP upstream %q [%d] (transport: %s, command: %s)\n", name, id, *transport, *command)
	fmt.Println("NOTE: if the MCP gateway is running, restart sluice for the new upstream to take effect")
	return nil
}

func handleMCPList(args []string) error {
	fs := flag.NewFlagSet("mcp list", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		return fmt.Errorf("list upstreams: %w", err)
	}

	if len(upstreams) == 0 {
		fmt.Println("no MCP upstreams registered")
		return nil
	}

	for _, u := range upstreams {
		transportStr := ""
		if u.Transport != "" && u.Transport != "stdio" {
			transportStr = " transport=" + u.Transport
		}
		argsStr := ""
		if len(u.Args) > 0 {
			argsStr = " args=" + strings.Join(u.Args, ",")
		}
		envStr := ""
		if len(u.Env) > 0 {
			keys := make([]string, 0, len(u.Env))
			for k := range u.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make([]string, 0, len(u.Env))
			for _, k := range keys {
				pairs = append(pairs, k+"="+u.Env[k])
			}
			envStr = " env=" + strings.Join(pairs, ",")
		}
		headersStr := ""
		if len(u.Headers) > 0 {
			keys := make([]string, 0, len(u.Headers))
			for k := range u.Headers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make([]string, 0, len(u.Headers))
			for _, k := range keys {
				pairs = append(pairs, k+"="+u.Headers[k])
			}
			headersStr = " headers=" + strings.Join(pairs, ",")
		}
		timeoutStr := ""
		if u.TimeoutSec != 120 {
			timeoutStr = fmt.Sprintf(" timeout=%ds", u.TimeoutSec)
		}
		fmt.Printf("[%d] %s command=%s%s%s%s%s%s\n", u.ID, u.Name, u.Command, transportStr, argsStr, envStr, headersStr, timeoutStr)
	}
	return nil
}

func handleMCPRemove(args []string) error {
	fs := flag.NewFlagSet("mcp remove", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice mcp remove <name>")
	}
	name := fs.Arg(0)

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	deleted, err := db.RemoveMCPUpstream(name)
	if err != nil {
		return fmt.Errorf("remove upstream: %w", err)
	}
	if !deleted {
		return fmt.Errorf("no upstream named %q", name)
	}
	fmt.Printf("removed MCP upstream %q\n", name)
	fmt.Println("NOTE: if the MCP gateway is running, restart sluice for the removal to take effect")
	return nil
}
