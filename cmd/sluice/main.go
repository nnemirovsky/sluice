package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/telegram"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	policyPath := flag.String("policy", "policy.toml", "path to policy TOML file")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := flag.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	flag.Parse()

	eng, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	log.Printf("loaded policy: %d allow, %d deny, %d ask rules (default: %s)",
		len(eng.AllowRules), len(eng.DenyRules), len(eng.AskRules), eng.Default)

	logger, err := audit.NewFileLogger(*auditPath)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()

	var broker *telegram.ApprovalBroker

	var telegramChatID int64
	if *telegramChatIDStr != "" {
		telegramChatID, err = strconv.ParseInt(*telegramChatIDStr, 10, 64)
		if err != nil {
			log.Fatalf("invalid telegram-chat-id: %v", err)
		}
	}

	if *telegramToken != "" && telegramChatID != 0 {
		broker = telegram.NewApprovalBroker()
		bot, err := telegram.NewBot(telegram.BotConfig{
			Token:     *telegramToken,
			ChatID:    telegramChatID,
			Engine:    eng,
			AuditPath: *auditPath,
		}, broker)
		if err != nil {
			log.Fatalf("telegram bot: %v", err)
		}
		go bot.Run()
		defer bot.Stop()
		log.Printf("telegram approval bot started")
	} else {
		log.Printf("telegram not configured (ask rules will auto-deny)")
	}

	srv, err := proxy.New(proxy.Config{
		ListenAddr: *listenAddr,
		Policy:     eng,
		Audit:      logger,
		Broker:     broker,
	})
	if err != nil {
		log.Fatalf("start proxy: %v", err)
	}

	log.Printf("sluice SOCKS5 proxy listening on %s", srv.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

	go func() {
		for range sighupCh {
			newEng, err := policy.LoadFromFile(*policyPath)
			if err != nil {
				log.Printf("reload policy failed: %v", err)
				continue
			}
			srv.ReloadPolicy(newEng)
			log.Printf("reloaded policy: %d allow, %d deny, %d ask rules (default: %s)",
				len(newEng.AllowRules), len(newEng.DenyRules), len(newEng.AskRules), newEng.Default)
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
