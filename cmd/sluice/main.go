package main

import (
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

	"github.com/nemirovsky/sluice/internal/api"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	httpchannel "github.com/nemirovsky/sluice/internal/channel/http"
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
		case "channel":
			handleChannelCommand(os.Args[2:])
			return
		}
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	dbPath := flag.String("db", "sluice.db", "path to SQLite database")
	configPath := flag.String("config", "", "path to config TOML file (seeds DB on first run if DB is empty)")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := flag.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	healthAddr := flag.String("health-addr", "127.0.0.1:3000", "health check HTTP listen address (serves /healthz)")
	shutdownTimeout := flag.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout for draining in-flight connections")
	dockerSocket := flag.String("docker-socket", "", "Docker socket path (auto-detects from DOCKER_HOST or /var/run/docker.sock)")
	dockerContainer := flag.String("docker-container", envDefault("SLUICE_AGENT_CONTAINER", "openclaw"), "Docker container name for auto-restart on credential changes")
	phantomDir := flag.String("phantom-dir", "", "shared volume path for phantom token files (enables hot-reload)")
	flag.Parse()

	// Open the SQLite store.
	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	// If --config is specified and the DB is empty, auto-import the TOML file as seed.
	if *configPath != "" {
		empty, err := db.IsEmpty()
		if err != nil {
			log.Fatalf("check store: %v", err)
		}
		if empty {
			data, err := os.ReadFile(*configPath)
			if err != nil {
				if os.IsNotExist(err) {
					log.Printf("config seed file %s not found, starting with empty DB", *configPath)
				} else {
					log.Fatalf("read config seed file: %v", err)
				}
			}
			if data != nil {
				result, err := db.ImportTOML(data)
				if err != nil {
					log.Fatalf("import config seed: %v", err)
				}
				log.Printf("seeded DB from %s: %d rules, %d bindings, %d upstreams, %d config",
					*configPath, result.RulesInserted,
					result.BindingsInserted, result.UpstreamsInserted, result.ConfigSet)
			}
		}
	}

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	log.Printf("loaded policy: %d allow, %d deny, %d ask rules (default: %s)",
		len(eng.AllowRules), len(eng.DenyRules), len(eng.AskRules), eng.Default)

	logger, err := audit.NewFileLogger(*auditPath)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Read all channels from the store and prepare for instantiation.
	var broker *channel.Broker
	var tgChannel *telegram.TelegramChannel

	storeChannels, chListErr := db.ListChannels()
	if chListErr != nil {
		log.Printf("WARNING: failed to read channels from store: %v", chListErr)
	}

	// Check Telegram channel state in store.
	var telegramChatID int64
	telegramEnabled := false
	telegramStoreDisabled := false
	for _, sCh := range storeChannels {
		if sCh.Type == int(channel.ChannelTelegram) && !sCh.Enabled {
			telegramStoreDisabled = true
			break
		}
	}

	if telegramStoreDisabled {
		log.Printf("telegram channel disabled in store (ask rules will auto-deny)")
	} else if *telegramToken != "" && *telegramChatIDStr != "" {
		var parseErr error
		telegramChatID, parseErr = strconv.ParseInt(*telegramChatIDStr, 10, 64)
		if parseErr != nil {
			log.Fatalf("invalid telegram-chat-id: %v", parseErr)
		}
		if telegramChatID == 0 {
			log.Printf("telegram chat ID is zero, telegram disabled (ask rules will auto-deny)")
		} else {
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

	// Create the vault provider so injection handlers exist even when the
	// DB starts with zero bindings. Bindings added later via CLI or
	// Telegram + SIGHUP will work without a full restart.
	provider, err := vault.NewProviderFromConfig(vaultCfg)
	if err != nil {
		if len(bindings) > 0 {
			log.Fatalf("create vault provider: %v", err)
		}
		log.Printf("vault provider unavailable (credential injection disabled): %v", err)
		provider = nil
	}

	var bindingResolver *vault.BindingResolver
	if len(bindings) > 0 {
		bindingResolver, err = vault.NewBindingResolver(bindings)
		if err != nil {
			log.Fatalf("create binding resolver: %v", err)
		}
		log.Printf("credential injection enabled: %d bindings, provider=%s",
			len(bindings), provider.Name())
	} else if provider != nil {
		log.Printf("vault provider ready (%s), no bindings yet", provider.Name())
	} else {
		log.Printf("no bindings and no vault provider; credential injection disabled")
	}

	// Extract the vault.Store from the provider (if age backend) so
	// Telegram /cred commands can add/remove/rotate credentials.
	var vaultStore *vault.Store
	if provider != nil {
		switch p := provider.(type) {
		case *vault.Store:
			vaultStore = p
		case *vault.ChainProvider:
			for _, inner := range p.Providers() {
				if s, ok := inner.(*vault.Store); ok {
					vaultStore = s
					break
				}
			}
		}
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

	// Create the proxy first so the bot can share its engine pointer and
	// reload mutex.
	srv, err := proxy.New(proxy.Config{
		ListenAddr: *listenAddr,
		Policy:     eng,
		Audit:      logger,
		Broker:     broker, // nil until channel setup below
		Provider:   provider,
		Resolver:   bindingResolver,
		VaultDir:   vaultCfg.Dir,
		Store:      db,
	})
	if err != nil {
		log.Fatalf("start proxy: %v", err)
	}

	// Instantiate all enabled channels (Telegram and/or HTTP).
	var allChannels []channel.Channel

	if telegramEnabled {
		var channelErr error
		tgChannel, channelErr = telegram.NewTelegramChannel(telegram.ChannelConfig{
			Token:       *telegramToken,
			ChatID:      telegramChatID,
			EnginePtr:   srv.EnginePtr(),
			ResolverPtr: srv.ResolverPtr(),
			ReloadMu:    srv.ReloadMu(),
			AuditPath:   *auditPath,
			Vault:       vaultStore,
			DockerMgr:   dockerMgr,
			Store:       db,
			PhantomDir:  *phantomDir,
		})
		if channelErr != nil {
			log.Fatalf("telegram channel: %v", channelErr)
		}
		allChannels = append(allChannels, tgChannel)
	}

	// Instantiate HTTP channels from the store.
	var httpChannels []*httpchannel.HTTPChannel
	for _, sCh := range storeChannels {
		if sCh.Type != int(channel.ChannelHTTP) || !sCh.Enabled {
			continue
		}
		if sCh.WebhookURL == "" {
			log.Printf("WARNING: HTTP channel [%d] has no webhook_url, skipping", sCh.ID)
			continue
		}
		hc, hcErr := httpchannel.NewHTTPChannel(httpchannel.Config{
			WebhookURL:    sCh.WebhookURL,
			WebhookSecret: sCh.WebhookSecret,
		})
		if hcErr != nil {
			log.Printf("WARNING: HTTP channel [%d]: %v, skipping", sCh.ID, hcErr)
			continue
		}
		httpChannels = append(httpChannels, hc)
		allChannels = append(allChannels, hc)
		log.Printf("HTTP webhook channel [%d] configured: %s", sCh.ID, sCh.WebhookURL)
	}

	if len(allChannels) > 0 {
		broker = channel.NewBroker(allChannels)

		// Wire broker references.
		if tgChannel != nil {
			tgChannel.SetBroker(broker)
		}
		for _, hc := range httpChannels {
			hc.SetBroker(broker)
		}

		// Update the proxy's broker reference now that it's created.
		srv.SetBroker(broker)

		// Start all channels.
		if tgChannel != nil {
			if err := tgChannel.Start(); err != nil {
				log.Fatalf("start telegram channel: %v", err)
			}
			defer tgChannel.Stop()
			log.Printf("telegram approval channel started")
		}
		for _, hc := range httpChannels {
			if err := hc.Start(); err != nil {
				log.Printf("WARNING: failed to start HTTP channel: %v", err)
			}
			defer hc.Stop()
		}
	} else {
		log.Printf("no approval channels configured (ask rules will auto-deny)")
	}

	// Start HTTP server with health check and REST API on :3000 (or --health-addr).
	apiServer := api.NewServer(db, broker, srv, *auditPath)
	apiServer.SetEnginePtr(srv.EnginePtr(), srv.ReloadMu())
	if vaultStore != nil {
		apiServer.SetVault(vaultStore)
	}
	healthLn, healthSrv := startAPIServer(*healthAddr, apiServer, db)
	if healthLn != nil {
		defer func() { _ = healthSrv.Close() }()
		log.Printf("HTTP API server listening on %s", healthLn.Addr())
	}

	log.Printf("sluice SOCKS5 proxy listening on %s", srv.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

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
			srv.StoreEngine(newEng)

			// Rebuild binding resolver so credential injection picks up
			// bindings added via CLI or Telegram since last reload.
			newBindings, bindErr := readBindings(db)
			if bindErr != nil {
				log.Printf("reload bindings failed: %v", bindErr)
			} else if len(newBindings) > 0 {
				newResolver, resolveErr := vault.NewBindingResolver(newBindings)
				if resolveErr != nil {
					log.Printf("rebuild binding resolver failed: %v", resolveErr)
				} else {
					srv.StoreResolver(newResolver)
					log.Printf("reloaded bindings: %d", len(newBindings))
				}
			} else if len(newBindings) == 0 {
				srv.StoreResolver(nil)
			}

			// Warn if the reloaded policy has ask rules but no approval
			// broker is running.
			if broker == nil && (len(newEng.AskRules) > 0 || newEng.Default == policy.Ask) {
				log.Printf("WARNING: policy has ask rules but no approval broker is running; ask verdicts will auto-deny")
			}

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
		// Cancel pending approval requests so proxy goroutines
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
	cfg, err := db.GetConfig()
	if err != nil {
		return vault.VaultConfig{}, err
	}

	vc := vault.VaultConfig{
		Provider: cfg.VaultProvider,
		Dir:      cfg.VaultDir,
	}

	// If no dir in config, use default.
	if vc.Dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			vc.Dir = filepath.Join(home, ".sluice")
		}
	}

	vc.Providers = cfg.VaultProviders

	vc.HashiCorp.Addr = cfg.VaultHashicorpAddr
	vc.HashiCorp.Mount = cfg.VaultHashicorpMount
	vc.HashiCorp.Prefix = cfg.VaultHashicorpPrefix
	vc.HashiCorp.Auth = cfg.VaultHashicorpAuth
	vc.HashiCorp.Token = cfg.VaultHashicorpToken
	vc.HashiCorp.RoleID = cfg.VaultHashicorpRoleID
	vc.HashiCorp.SecretID = cfg.VaultHashicorpSecretID
	vc.HashiCorp.RoleIDEnv = cfg.VaultHashicorpRoleIDEnv
	vc.HashiCorp.SecretIDEnv = cfg.VaultHashicorpSecretIDEnv

	return vc, nil
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
			Header: r.Header,
			Template:     r.Template,
			Protocols:    r.Protocols,
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
	if strings.Contains(raw, "://") {
		scheme := strings.SplitN(raw, "://", 2)[0]
		if scheme != "unix" {
			return "", fmt.Errorf("unsupported Docker socket scheme %q (only unix:// is supported)", scheme)
		}
		return strings.TrimPrefix(raw, "unix://"), nil
	}
	return raw, nil
}

// startAPIServer starts the HTTP server with the generated chi router.
// It serves both /healthz (no auth) and /api/* (bearer auth + channel gate).
func startAPIServer(addr string, apiSrv *api.Server, st *store.Store) (net.Listener, *http.Server) {
	if addr == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("WARNING: failed to start API server on %s: %v", addr, err)
		return nil, nil
	}
	// oapi-codegen wraps handlers bottom-up: last middleware in the slice
	// becomes the outermost layer. List channel gate first, then auth, so
	// the request hits auth before the channel gate. This ensures bad tokens
	// get 401 before the channel gate reveals whether HTTP channel is enabled.
	handler := api.HandlerWithOptions(apiSrv, api.ChiServerOptions{
		Middlewares: []api.MiddlewareFunc{
			api.ChannelGateMiddleware(st),
			api.BearerAuthMiddleware,
		},
	})
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go httpSrv.Serve(ln) //nolint:errcheck
	return ln, httpSrv
}
