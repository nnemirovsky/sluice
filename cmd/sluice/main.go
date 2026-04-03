package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/docker"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/telegram"
	"github.com/nemirovsky/sluice/internal/vault"
)

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
		case "policy":
			handlePolicyCommand(os.Args[2:])
			return
		case "audit":
			handleAuditCommand(os.Args[2:])
			return
		}
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	dbPath := flag.String("db", "sluice.db", "path to SQLite database")
	policyPath := flag.String("policy", "", "path to policy TOML file (seeds DB on first run if DB is empty)")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := flag.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	healthAddr := flag.String("health-addr", "127.0.0.1:3000", "health check HTTP listen address (serves /healthz)")
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

	// Open the SQLite store.
	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	// If --policy is specified and the DB is empty, auto-import the TOML file as seed.
	if *policyPath != "" {
		empty, err := db.IsEmpty()
		if err != nil {
			log.Fatalf("check store: %v", err)
		}
		if empty {
			data, err := os.ReadFile(*policyPath)
			if err != nil {
				log.Fatalf("read policy seed file: %v", err)
			}
			result, err := db.ImportTOML(data)
			if err != nil {
				log.Fatalf("import policy seed: %v", err)
			}
			log.Printf("seeded DB from %s: %d rules, %d tool rules, %d bindings, %d upstreams, %d config",
				*policyPath, result.RulesInserted, result.ToolRulesInserted,
				result.BindingsInserted, result.UpstreamsInserted, result.ConfigSet)
		}
	}

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	log.Printf("loaded policy: %d allow, %d deny, %d ask rules (default: %s)",
		len(eng.AllowRules), len(eng.DenyRules), len(eng.AskRules), eng.Default)

	// If the store specifies custom env var names for the Telegram bot,
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

	// Read vault config and credential bindings from the store.
	vaultCfg, err := readVaultConfig(db)
	if err != nil {
		log.Fatalf("read vault config: %v", err)
	}
	bindings, err := readBindings(db)
	if err != nil {
		log.Fatalf("read bindings: %v", err)
	}

	var provider vault.Provider
	var bindingResolver *vault.BindingResolver
	if len(bindings) > 0 {
		provider, err = vault.NewProviderFromConfig(vaultCfg)
		if err != nil {
			log.Fatalf("create vault provider: %v", err)
		}
		bindingResolver, err = vault.NewBindingResolver(bindings)
		if err != nil {
			log.Fatalf("create binding resolver: %v", err)
		}
		log.Printf("credential injection enabled: %d bindings, provider=%s",
			len(bindings), provider.Name())
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
		VaultDir:   vaultCfg.Dir,
		Store:      db,
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
			Store:     db,
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

	// Save the startup Telegram config so the SIGHUP handler can detect drift.
	startupTelegram := eng.Telegram

	go func() {
		for range sighupCh {
			srv.ReloadMu().Lock()

			newEng, loadErr := policy.LoadFromStore(db)
			if loadErr != nil {
				log.Printf("reload policy failed: %v", loadErr)
				drainSignals(sighupCh)
				srv.ReloadMu().Unlock()
				continue
			}

			// Validate the new engine before swapping to catch
			// corrupted or incomplete compilation results.
			if valErr := newEng.Validate(); valErr != nil {
				log.Printf("reload policy validation failed: %v", valErr)
				drainSignals(sighupCh)
				srv.ReloadMu().Unlock()
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
				log.Printf("WARNING: telegram config changed in store but Telegram runtime is not hot-reloadable; restart required")
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

// readVaultConfig reconstructs a vault.VaultConfig from the store's config table.
func readVaultConfig(db *store.Store) (vault.VaultConfig, error) {
	cfg := vault.VaultConfig{}

	provider, err := db.GetConfig("vault_provider")
	if err != nil {
		return cfg, err
	}
	cfg.Provider = provider

	dir, err := db.GetConfig("vault_dir")
	if err != nil {
		return cfg, err
	}
	cfg.Dir = dir

	// If no dir in config, use default.
	if cfg.Dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			cfg.Dir = filepath.Join(home, ".sluice")
		}
	}

	providersJSON, err := db.GetConfig("vault_providers")
	if err != nil {
		return cfg, err
	}
	if providersJSON != "" {
		if err := json.Unmarshal([]byte(providersJSON), &cfg.Providers); err != nil {
			return cfg, fmt.Errorf("unmarshal vault_providers: %w", err)
		}
	}

	// HashiCorp config.
	hcKeys := []struct {
		key  string
		dest *string
	}{
		{"vault_hashicorp_addr", &cfg.HashiCorp.Addr},
		{"vault_hashicorp_mount", &cfg.HashiCorp.Mount},
		{"vault_hashicorp_prefix", &cfg.HashiCorp.Prefix},
		{"vault_hashicorp_auth", &cfg.HashiCorp.Auth},
		{"vault_hashicorp_token", &cfg.HashiCorp.Token},
		{"vault_hashicorp_role_id", &cfg.HashiCorp.RoleID},
		{"vault_hashicorp_secret_id", &cfg.HashiCorp.SecretID},
		{"vault_hashicorp_role_id_env", &cfg.HashiCorp.RoleIDEnv},
		{"vault_hashicorp_secret_id_env", &cfg.HashiCorp.SecretIDEnv},
	}
	for _, kv := range hcKeys {
		v, err := db.GetConfig(kv.key)
		if err != nil {
			return cfg, err
		}
		*kv.dest = v
	}

	return cfg, nil
}

// readBindings reads credential bindings from the store and converts them
// to vault.Binding for use with vault.NewBindingResolver.
func readBindings(db *store.Store) ([]vault.Binding, error) {
	rows, err := db.ListBindings()
	if err != nil {
		return nil, err
	}
	bindings := make([]vault.Binding, len(rows))
	for i, r := range rows {
		bindings[i] = vault.Binding{
			Destination:  r.Destination,
			Ports:        r.Ports,
			Credential:   r.Credential,
			InjectHeader: r.InjectHeader,
			Template:     r.Template,
			Protocol:     r.Protocol,
		}
	}
	return bindings, nil
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
// non-empty it is validated and used. Otherwise it checks DOCKER_HOST env and
// falls back to the default /var/run/docker.sock. A unix:// prefix is stripped.
// Returns an error when a non-unix scheme is detected.
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
