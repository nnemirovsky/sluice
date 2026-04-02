package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/mcp"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/telegram"
)

// mcpConfig holds MCP-specific sections parsed from the policy TOML file.
type mcpConfig struct {
	MCPUpstreams []mcp.UpstreamConfig `toml:"mcp_upstream"`
}

func handleMCPCommand(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	policyPath := fs.String("policy", "policy.toml", "path to policy TOML file")
	auditPath := fs.String("audit", "", "path to audit log file (optional)")
	telegramToken := fs.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := fs.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	fs.Parse(args)

	// Track which flags were explicitly set on the command line so we can
	// distinguish "user passed --telegram-token X" from "flag has the
	// default value read from TELEGRAM_BOT_TOKEN env".
	explicitFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	policyData, err := os.ReadFile(*policyPath)
	if err != nil {
		log.Fatalf("read policy file: %v", err)
	}

	eng, err := policy.LoadFromBytes(policyData)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	// If the policy file specifies custom env var names for Telegram, use
	// those instead of the hardcoded defaults (but only when the flag was
	// not explicitly provided on the command line).
	if eng.Telegram.BotTokenEnv != "" && !explicitFlags["telegram-token"] {
		*telegramToken = os.Getenv(eng.Telegram.BotTokenEnv)
	}
	if eng.Telegram.ChatIDEnv != "" && !explicitFlags["telegram-chat-id"] {
		*telegramChatIDStr = os.Getenv(eng.Telegram.ChatIDEnv)
	}

	// Parse MCP upstream config from the already-read TOML bytes.
	var mcpCfg mcpConfig
	if err := toml.Unmarshal(policyData, &mcpCfg); err != nil {
		log.Fatalf("parse MCP config: %v", err)
	}

	// Build tool policy from engine's tool rules.
	toolRules := eng.ToolRules()
	toolPolicy, err := mcp.NewToolPolicy(toolRules, eng.Default)
	if err != nil {
		log.Fatalf("compile tool policy: %v", err)
	}
	log.Printf("MCP tool policy: %d rules (default: %s)", len(toolRules), eng.Default)

	// Optional audit logger.
	var logger *audit.FileLogger
	if *auditPath != "" {
		logger, err = audit.NewFileLogger(*auditPath)
		if err != nil {
			log.Fatalf("open audit log: %v", err)
		}
		defer logger.Close()
	}

	// Optional Telegram approval broker.
	var broker *telegram.ApprovalBroker
	if *telegramToken != "" && *telegramChatIDStr != "" {
		chatID, parseErr := strconv.ParseInt(*telegramChatIDStr, 10, 64)
		if parseErr != nil {
			log.Fatalf("invalid telegram-chat-id: %v", parseErr)
		}
		if chatID != 0 {
			broker = telegram.NewApprovalBroker()
			var enginePtr atomic.Pointer[policy.Engine]
			enginePtr.Store(eng)
			var reloadMu sync.Mutex
			bot, botErr := telegram.NewBot(telegram.BotConfig{
				Token:     *telegramToken,
				ChatID:    chatID,
				EnginePtr: &enginePtr,
				ReloadMu:  &reloadMu,
				AuditPath: *auditPath,
			}, broker)
			if botErr != nil {
				log.Fatalf("telegram bot: %v", botErr)
			}
			go bot.Run()
			defer bot.Stop()
			log.Printf("telegram approval bot started for MCP gateway")
		}
	}

	// Optional content inspector for argument blocking and response redaction.
	var inspector *mcp.ContentInspector
	if len(eng.InspectBlockRules) > 0 || len(eng.InspectRedactRules) > 0 {
		inspector, err = mcp.NewContentInspector(eng.InspectBlockRules, eng.InspectRedactRules)
		if err != nil {
			log.Fatalf("create content inspector: %v", err)
		}
		log.Printf("content inspector: %d block rules, %d redact rules",
			len(eng.InspectBlockRules), len(eng.InspectRedactRules))
	}

	gw, err := mcp.NewGateway(mcp.GatewayConfig{
		Upstreams:  mcpCfg.MCPUpstreams,
		ToolPolicy: toolPolicy,
		Inspector:  inspector,
		Audit:      logger,
		Broker:     broker,
		TimeoutSec: eng.TimeoutSec,
	})
	if err != nil {
		log.Fatalf("start MCP gateway: %v", err)
	}
	defer gw.Stop()

	log.Printf("MCP gateway ready: %d tools from %d upstreams", len(gw.Tools()), len(mcpCfg.MCPUpstreams))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- gw.RunStdio()
	}()

	select {
	case <-sigCh:
		log.Println("MCP gateway shutting down...")
	case err := <-errCh:
		if err != nil {
			log.Printf("MCP gateway error: %v", err)
			return err
		}
		log.Println("MCP gateway stdin closed, exiting")
	}
	return nil
}
