package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/docker"
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
		case "cert":
			handleCertCommand(os.Args[2:])
			return
		case "mcp":
			if err := handleMCPCommand(os.Args[2:]); err != nil {
				log.Fatalf("mcp: %v", err)
			}
			return
		case "audit":
			handleAuditCommand(os.Args[2:])
			return
		}
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	policyPath := flag.String("policy", "policy.toml", "path to policy TOML file")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := flag.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	healthAddr := flag.String("health-addr", ":3000", "health check HTTP listen address (serves /healthz)")
	shutdownTimeout := flag.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout for draining in-flight connections")
	dockerSocket := flag.String("docker-socket", "", "Docker socket path (auto-detects from DOCKER_HOST or /var/run/docker.sock)")
	dockerContainer := flag.String("docker-container", envDefault("SLUICE_AGENT_CONTAINER", "openclaw"), "Docker container name for auto-restart on credential changes")
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

	// Extract the vault.Store from the provider (if age backend) so
	// Telegram /cred commands can add/remove/rotate credentials.
	var vaultStore *vault.Store
	if provider != nil {
		vaultStore, _ = provider.(*vault.Store)
	}

	// Docker container manager for auto-restart on credential changes.
	var dockerMgr *docker.Manager
	if vaultStore != nil {
		sock, sockErr := resolveDockerSocket(*dockerSocket)
		if sockErr != nil {
			log.Printf("WARNING: %v; container auto-restart disabled", sockErr)
		} else if sock != "" {
			if fi, statErr := os.Stat(sock); statErr == nil && fi.Mode().Type() == os.ModeSocket {
				client := docker.NewSocketClient(sock)
				dockerMgr = docker.NewManager(client, *dockerContainer)
				log.Printf("docker manager enabled: socket=%s, container=%s", sock, *dockerContainer)
			} else if *dockerSocket != "" {
				log.Printf("WARNING: --docker-socket %q not found or not a socket; container auto-restart disabled", *dockerSocket)
			}
		}
	}

	// Start health check HTTP server on :3000 (or --health-addr).
	healthLn, healthSrv := startHealthServer(*healthAddr, srv)
	if healthLn != nil {
		defer healthSrv.Close()
		log.Printf("health check server listening on %s", healthLn.Addr())
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
			Vault:     vaultStore,
			DockerMgr: dockerMgr,
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
			srv.ReloadMu().Lock()

			newEng, loadErr := policy.LoadFromFile(*policyPath)
			if loadErr != nil {
				srv.ReloadMu().Unlock()
				log.Printf("reload policy failed: %v", loadErr)
				drainSignals(sighupCh)
				continue
			}

			// Validate the new engine before swapping to catch
			// corrupted or incomplete compilation results.
			if valErr := newEng.Validate(); valErr != nil {
				srv.ReloadMu().Unlock()
				log.Printf("reload policy validation failed: %v", valErr)
				drainSignals(sighupCh)
				continue
			}

			log.Printf("reloaded policy: %d allow, %d deny, %d ask rules (default: %s)",
				len(newEng.AllowRules), len(newEng.DenyRules), len(newEng.AskRules), newEng.Default)
			// StoreEngine swaps the engine pointer without acquiring
			// reloadMu (we already hold it for the entire reload).
			srv.StoreEngine(newEng)

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

			// Drain duplicate SIGHUPs that queued during reload to
			// avoid redundant reload cycles. Done before Unlock so
			// only signals queued while the lock was held are drained.
			drainSignals(sighupCh)

			srv.ReloadMu().Unlock()
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-sigCh:
		log.Println("shutting down...")
		// Cancel pending Telegram approval requests so proxy goroutines
		// blocked on approval can complete and connections can drain.
		if broker != nil {
			broker.CancelAll()
		}
		if err := srv.GracefulShutdown(*shutdownTimeout); err != nil {
			log.Printf("WARNING: %v", err)
		}
		// Audit logger is closed via defer after all connections drain.
	case err := <-errCh:
		log.Fatalf("proxy failed: %v", err)
	}
}

// envDefault returns the environment variable value if set, otherwise the fallback.
func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// drainSignals discards any pending signals on ch so that duplicate
// deliveries during a reload do not trigger redundant reload cycles.
func drainSignals(ch <-chan os.Signal) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// resolveDockerSocket returns the Docker socket path to use. If explicit is
// non-empty it is returned as-is. Otherwise it checks DOCKER_HOST env and
// falls back to the default /var/run/docker.sock. Returns an error string
// (empty on success) when a non-unix scheme is detected.
func resolveDockerSocket(explicit string) (string, error) {
	raw := explicit
	if raw == "" {
		raw = os.Getenv("DOCKER_HOST")
	}
	if raw == "" {
		return "/var/run/docker.sock", nil
	}
	// Reject non-unix schemes. Docker supports tcp://, ssh://, etc. but
	// Sluice only supports local unix sockets for security. The Docker
	// socket gives full container control so it must not traverse the
	// network.
	if strings.Contains(raw, "://") {
		scheme := strings.SplitN(raw, "://", 2)[0]
		if scheme != "unix" {
			return "", fmt.Errorf("unsupported Docker socket scheme %q (only unix:// is supported)", scheme)
		}
		return strings.TrimPrefix(raw, "unix://"), nil
	}
	return raw, nil
}

// startHealthServer starts a minimal HTTP server serving /healthz.
// Returns the listener and server for deferred cleanup, or nil if the
// address is empty or the listener fails.
func startHealthServer(addr string, srv *proxy.Server) (net.Listener, *http.Server) {
	if addr == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("WARNING: failed to start health server on %s: %v", addr, err)
		return nil, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if srv.IsListening() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready"))
		}
	})
	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go httpSrv.Serve(ln) //nolint:errcheck
	return ln, httpSrv
}
