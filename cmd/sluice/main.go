package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/telegram"
	"github.com/nemirovsky/sluice/internal/vault"
)

// sluiceConfig holds the vault and binding sections from the policy TOML file.
// Parsed separately from the policy engine to avoid circular dependencies
// (vault imports policy).
type sluiceConfig struct {
	Vault    vault.VaultConfig `toml:"vault"`
	Bindings []vault.Binding   `toml:"binding"`
}

func main() {
	// Handle subcommands before flag parsing.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "cred":
			handleCredCommand(os.Args[2:])
			return
		case "mcp":
			handleMCPCommand(os.Args[2:])
			return
		}
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	policyPath := flag.String("policy", "policy.toml", "path to policy TOML file")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := flag.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	flag.Parse()

	// Track which flags were explicitly set on the command line so we can
	// distinguish "user passed --telegram-token X" from "flag has the
	// default value read from TELEGRAM_BOT_TOKEN env".
	explicitFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})
	// Whether explicit flags were provided for Telegram settings.
	// Captured once so the SIGHUP handler can detect config drift.
	telegramTokenExplicit := explicitFlags["telegram-token"]
	telegramChatIDExplicit := explicitFlags["telegram-chat-id"]

	eng, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	log.Printf("loaded policy: %d allow, %d deny, %d ask rules (default: %s)",
		len(eng.AllowRules), len(eng.DenyRules), len(eng.AskRules), eng.Default)

	// If the policy file specifies custom env var names for the Telegram bot,
	// use those instead of the hardcoded defaults (but only when the flag was
	// not explicitly provided on the command line).
	if eng.Telegram.BotTokenEnv != "" && !explicitFlags["telegram-token"] {
		*telegramToken = os.Getenv(eng.Telegram.BotTokenEnv)
	}
	if eng.Telegram.ChatIDEnv != "" && !explicitFlags["telegram-chat-id"] {
		*telegramChatIDStr = os.Getenv(eng.Telegram.ChatIDEnv)
	}

	logger, err := audit.NewFileLogger(*auditPath)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()

	// Parse Telegram chat ID early so we can pass the broker to the proxy.
	var broker *telegram.ApprovalBroker
	var telegramChatID int64
	telegramEnabled := false

	if *telegramToken != "" && *telegramChatIDStr != "" {
		var parseErr error
		telegramChatID, parseErr = strconv.ParseInt(*telegramChatIDStr, 10, 64)
		if parseErr != nil {
			log.Fatalf("invalid telegram-chat-id: %v", parseErr)
		}
		if telegramChatID == 0 {
			log.Printf("telegram chat ID is zero, telegram disabled (ask rules will auto-deny)")
		} else {
			broker = telegram.NewApprovalBroker()
			telegramEnabled = true
		}
	} else {
		log.Printf("telegram not configured (ask rules will auto-deny)")
	}

	// Parse vault config and credential bindings from the same TOML file.
	// These are optional: if no [[binding]] entries exist, credential
	// injection is disabled and the proxy runs in pass-through mode.
	// Decode errors are fatal because they indicate a real config mistake
	// (type mismatches in [vault] or [[binding]] sections). TOML syntax
	// errors would already be caught by policy.LoadFromFile above.
	var slCfg sluiceConfig
	if _, decodeErr := toml.DecodeFile(*policyPath, &slCfg); decodeErr != nil {
		log.Fatalf("parse vault/binding config: %v", decodeErr)
	}

	var provider vault.Provider
	var bindingResolver *vault.BindingResolver
	if len(slCfg.Bindings) > 0 {
		provider, err = vault.NewProviderFromConfig(slCfg.Vault)
		if err != nil {
			log.Fatalf("create vault provider: %v", err)
		}
		bindingResolver, err = vault.NewBindingResolver(slCfg.Bindings)
		if err != nil {
			log.Fatalf("create binding resolver: %v", err)
		}
		log.Printf("credential injection enabled: %d bindings, provider=%s",
			len(slCfg.Bindings), provider.Name())
	}

	// Create the proxy first so the bot can share its engine pointer and
	// reload mutex. This eliminates split-brain windows during SIGHUP
	// reloads: both components see engine swaps and policy mutations
	// through the same atomic pointer, serialized by the same mutex.
	srv, err := proxy.New(proxy.Config{
		ListenAddr: *listenAddr,
		Policy:     eng,
		Audit:      logger,
		Broker:     broker,
		Provider:   provider,
		Resolver:   bindingResolver,
		VaultDir:   slCfg.Vault.Dir,
	})
	if err != nil {
		log.Fatalf("start proxy: %v", err)
	}

	var bot *telegram.Bot
	if telegramEnabled {
		var botErr error
		bot, botErr = telegram.NewBot(telegram.BotConfig{
			Token:     *telegramToken,
			ChatID:    telegramChatID,
			EnginePtr: srv.EnginePtr(),
			ReloadMu:  srv.ReloadMu(),
			AuditPath: *auditPath,
		}, broker)
		if botErr != nil {
			log.Fatalf("telegram bot: %v", botErr)
		}
		go bot.Run()
		defer bot.Stop()
		log.Printf("telegram approval bot started")
	}

	log.Printf("sluice SOCKS5 proxy listening on %s", srv.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

	// Save the startup Telegram and vault/binding config so the SIGHUP
	// handler can detect config drift (these runtimes are not hot-reloadable).
	startupTelegram := eng.Telegram
	startupSlCfg := slCfg

	go func() {
		for range sighupCh {
			newEng, err := policy.LoadFromFile(*policyPath)
			if err != nil {
				log.Printf("reload policy failed: %v", err)
				continue
			}
			log.Printf("reloaded policy: %d allow, %d deny, %d ask rules (default: %s)",
				len(newEng.AllowRules), len(newEng.DenyRules), len(newEng.AskRules), newEng.Default)
			// ReloadPolicy swaps the shared engine pointer under the shared
			// mutex. The bot's command handler reads the same pointer, so
			// it sees the new engine immediately with no separate update step.
			srv.ReloadPolicy(newEng)

			// Warn if the reloaded policy's Telegram config changed.
			// The Telegram runtime (broker, bot, chat ID) is wired once
			// at startup and cannot be hot-reloaded. Env var names or
			// enable/disable changes require a full restart.
			if newEng.Telegram != startupTelegram {
				log.Printf("WARNING: [telegram] config changed in policy file but Telegram runtime is not hot-reloadable; restart required")
			}

			// Warn if the reloaded policy has ask rules but no approval
			// broker is running. This can happen when Telegram was not
			// configured at startup and ask rules were added later.
			if broker == nil && (len(newEng.AskRules) > 0 || newEng.Default == policy.Ask) {
				log.Printf("WARNING: policy has ask rules but no Telegram approval broker is running; ask verdicts will auto-deny")
			}

			// Warn if env var names changed and CLI flags were not used.
			// The operator may expect the new env var names to take effect.
			if newEng.Telegram.BotTokenEnv != startupTelegram.BotTokenEnv && !telegramTokenExplicit {
				log.Printf("WARNING: bot_token_env changed from %q to %q but env vars are only read at startup; restart required",
					startupTelegram.BotTokenEnv, newEng.Telegram.BotTokenEnv)
			}
			if newEng.Telegram.ChatIDEnv != startupTelegram.ChatIDEnv && !telegramChatIDExplicit {
				log.Printf("WARNING: chat_id_env changed from %q to %q but env vars are only read at startup; restart required",
					startupTelegram.ChatIDEnv, newEng.Telegram.ChatIDEnv)
			}

			// Warn if vault or binding config changed. The credential
			// injection pipeline (provider, resolver, injector, SSH jump
			// host, mail proxy) is wired once at startup and cannot be
			// hot-reloaded. Binding or provider changes require a restart.
			var newSlCfg sluiceConfig
			if _, decodeErr := toml.DecodeFile(*policyPath, &newSlCfg); decodeErr == nil {
				if !reflect.DeepEqual(newSlCfg.Vault, startupSlCfg.Vault) ||
					!reflect.DeepEqual(newSlCfg.Bindings, startupSlCfg.Bindings) {
					log.Printf("WARNING: [vault] or [[binding]] config changed but credential injection runtime is not hot-reloadable; restart required")
				}
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-sigCh:
		log.Println("shutting down...")
		srv.Close()
	case err := <-errCh:
		log.Fatalf("proxy failed: %v", err)
	}
}
