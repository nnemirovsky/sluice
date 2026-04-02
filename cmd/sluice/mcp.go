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

func handleMCPCommand(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	policyPath := fs.String("policy", "policy.toml", "path to policy TOML file")
	auditPath := fs.String("audit", "", "path to audit log file (optional)")
	telegramToken := fs.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := fs.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	fs.Parse(args)

	eng, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	// If policy file specifies custom env var names for Telegram, use them.
	if eng.Telegram.BotTokenEnv != "" {
		*telegramToken = os.Getenv(eng.Telegram.BotTokenEnv)
	}
	if eng.Telegram.ChatIDEnv != "" {
		*telegramChatIDStr = os.Getenv(eng.Telegram.ChatIDEnv)
	}

	// Parse MCP upstream config from the same TOML file.
	var mcpCfg mcpConfig
	if _, decodeErr := toml.DecodeFile(*policyPath, &mcpCfg); decodeErr != nil {
		log.Fatalf("parse MCP config: %v", decodeErr)
	}

	// Build tool policy from engine's tool rules.
	toolRules := eng.ToolRules()
	toolPolicy := mcp.NewToolPolicy(toolRules, eng.Default)
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
			log.Fatalf("MCP gateway error: %v", err)
		}
		log.Println("MCP gateway stdin closed, exiting")
	}
}
