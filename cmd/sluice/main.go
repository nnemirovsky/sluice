// Package main implements the sluice CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nemirovsky/sluice/internal/api"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	httpchannel "github.com/nemirovsky/sluice/internal/channel/http"
	"github.com/nemirovsky/sluice/internal/container"
	"github.com/nemirovsky/sluice/internal/mcp"
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
			if err := handleCredCommand(os.Args[2:]); err != nil {
				log.Fatalf("cred: %v", err)
			}
			return
		case "cert":
			if err := handleCertCommand(os.Args[2:]); err != nil {
				log.Fatalf("cert: %v", err)
			}
			return
		case "mcp":
			if err := handleMCPCommand(os.Args[2:]); err != nil {
				log.Fatalf("mcp: %v", err)
			}
			return
		case "policy":
			if err := handlePolicyCommand(os.Args[2:]); err != nil {
				log.Fatalf("policy: %v", err)
			}
			return
		case "audit":
			if err := handleAuditCommand(os.Args[2:]); err != nil {
				log.Fatalf("audit: %v", err)
			}
			return
		case "binding":
			if err := handleBindingCommand(os.Args[2:]); err != nil {
				log.Fatalf("binding: %v", err)
			}
			return
		case "channel":
			if err := handleChannelCommand(os.Args[2:]); err != nil {
				log.Fatalf("channel: %v", err)
			}
			return
		}
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	dbPath := flag.String("db", "data/sluice.db", "path to SQLite database")
	configPath := flag.String("config", "", "path to config TOML file (seeds DB on first run if DB is empty)")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
	telegramChatIDStr := flag.String("telegram-chat-id", os.Getenv("TELEGRAM_CHAT_ID"), "Telegram chat ID for approvals")
	healthAddr := flag.String("health-addr", "127.0.0.1:3000", "health check HTTP listen address (serves /healthz)")
	shutdownTimeout := flag.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout for draining in-flight connections")
	runtimeFlag := flag.String("runtime", "auto", "container runtime: docker, apple, macos, none, auto")
	vmImage := flag.String("vm-image", "", "OCI image for tart macOS VM (e.g. ghcr.io/cirruslabs/macos-sequoia-base:latest)")
	dockerSocket := flag.String("docker-socket", "", "Docker socket path (auto-detects from DOCKER_HOST or /var/run/docker.sock)")
	containerName := flag.String("container-name", envDefault("SLUICE_AGENT_CONTAINER", "openclaw"), "agent container/VM name")
	certDir := flag.String("cert-dir", "", "shared volume path for CA certificate (enables MITM trust injection into guest)")
	dnsResolver := flag.String("dns-resolver", "", "upstream DNS resolver address for DNS interception (default: 8.8.8.8:53)")
	mcpBaseURL := flag.String("mcp-base-url", "", "external base URL the agent uses to reach sluice's MCP gateway (e.g. http://sluice:3000); added to SelfBypass so sluice does not policy-check its own MCP traffic")
	flag.Parse()

	// Validate --runtime flag early.
	switch *runtimeFlag {
	case "auto", "docker", "apple", "macos", "none":
	default:
		log.Fatalf("unknown --runtime value %q (valid: docker, apple, macos, none, auto)", *runtimeFlag)
	}
	if *runtimeFlag == "apple" && goruntime.GOOS != "darwin" {
		log.Fatalf("--runtime apple requires macOS (current OS: %s)", goruntime.GOOS)
	}
	if *runtimeFlag == "macos" && goruntime.GOOS != "darwin" {
		log.Fatalf("--runtime macos requires macOS (current OS: %s)", goruntime.GOOS)
	}
	if *runtimeFlag == "macos" && *vmImage == "" {
		log.Fatalf("--runtime macos requires --vm-image (e.g. ghcr.io/cirruslabs/macos-sequoia-base:latest)")
	}

	// Open the SQLite store.
	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	// If --config is specified and the DB is empty, auto-import the TOML file as seed.
	if *configPath != "" {
		if seedErr := seedStoreFromConfig(db, *configPath); seedErr != nil {
			log.Fatalf("seed store: %v", seedErr)
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

	// Container manager for credential hot-reload and lifecycle management.
	var containerMgr container.ContainerManager
	selectedRuntime := *runtimeFlag
	if selectedRuntime == "auto" {
		selectedRuntime = detectRuntime(
			isDockerSocketAvailable(*dockerSocket),
			isAppleCLIAvailable(),
			isTartCLIAvailable(),
			goruntime.GOOS,
		)
	}
	// tartMgr and tartRouter are set when --runtime macos is active. They
	// are used during shutdown to stop the VM and tear down pf rules.
	// tartVMOwned tracks whether sluice started the VM (vs. attaching to
	// a pre-existing one). Only owned VMs are stopped on shutdown.
	var tartMgr *container.TartManager
	var tartRouter *container.NetworkRouter
	var tartVMOwned bool

	switch selectedRuntime {
	case "docker":
		sock, sockErr := resolveDockerSocket(*dockerSocket)
		if sockErr != nil {
			log.Printf("WARNING: %v; Docker container management disabled", sockErr)
		} else {
			if fi, statErr := os.Stat(sock); statErr == nil && fi.Mode().Type() == os.ModeSocket {
				client := container.NewSocketClient(sock)
				containerMgr = container.NewDockerManager(client, *containerName)
				log.Printf("docker manager enabled: socket=%s, container=%s", sock, *containerName)
			} else if *runtimeFlag == "docker" {
				log.Fatalf("--runtime docker: socket %q not found or not a socket", sock)
			} else {
				log.Printf("WARNING: Docker socket %q not available; container management disabled", sock)
			}
		}
	case "apple":
		cli, cliErr := container.NewAppleCLI(nil)
		if cliErr != nil {
			if *runtimeFlag == "apple" {
				log.Fatalf("--runtime apple: container CLI not available: %v", cliErr)
			}
			log.Printf("WARNING: Apple Container CLI not available: %v; container management disabled", cliErr)
		} else {
			containerMgr = container.NewAppleManager(container.AppleManagerConfig{
				CLI:           cli,
				ContainerName: *containerName,
			})
			log.Printf("apple container manager enabled: container=%s", *containerName)
		}
	case "macos":
		tartMgr, tartRouter, containerMgr, tartVMOwned = startMacOSVM(*vmImage, *containerName, *certDir)
	case "none":
		log.Printf("standalone mode: no container runtime (configure ALL_PROXY=socks5://%s manually)", *listenAddr)
	case "":
		log.Printf("no container runtime detected; container management disabled")
	}

	// Build self-bypass addresses so the agent's MCP HTTP connection to
	// sluice is auto-allowed without policy evaluation. This applies
	// whenever a health address is configured; if no agent exists, the
	// bypass list has no effect.
	var selfBypass []string
	if *healthAddr != "" {
		selfBypass = buildSelfBypass(*healthAddr)
		// When --mcp-base-url is set, also bypass the external hostname
		// (e.g. "sluice:3000" in Docker Compose) that the agent uses to
		// reach us, in case the connection is routed through the SOCKS5
		// proxy instead of directly on the Docker network.
		if *mcpBaseURL != "" {
			if extra := selfBypassFromURL(*mcpBaseURL, *healthAddr); extra != "" {
				selfBypass = append(selfBypass, extra)
			}
		}
	}

	// Create the proxy first so the bot can share its engine pointer and
	// reload mutex.
	wsBlockRules, wsRedactRules, quicBlockRules, quicRedactRules := buildInspectRuleConfigs(eng)

	srv, err := proxy.New(proxy.Config{
		ListenAddr:      *listenAddr,
		Policy:          eng,
		Audit:           logger,
		Broker:          broker, // nil until channel setup below
		Provider:        provider,
		Resolver:        bindingResolver,
		VaultDir:        vaultCfg.Dir,
		Store:           db,
		DNSResolver:     *dnsResolver,
		WSBlockRules:    wsBlockRules,
		WSRedactRules:   wsRedactRules,
		QUICBlockRules:  quicBlockRules,
		QUICRedactRules: quicRedactRules,
		SelfBypass:      selfBypass,
	})
	if err != nil {
		log.Fatalf("start proxy: %v", err)
	}

	// Populate the initial OAuth token URL index at startup so response
	// interception works for credentials added before the first SIGHUP.
	if db != nil {
		if metas, metaErr := db.ListCredentialMeta(); metaErr == nil && len(metas) > 0 {
			srv.UpdateOAuthIndex(metas)
			log.Printf("oauth index initialized: %d entries", len(metas))
		}
	}

	// Configure the OAuth refresh callback so that after a token refresh
	// is persisted, the updated phantom env vars are re-injected into the
	// agent container.
	if containerMgr != nil && db != nil {
		srv.SetOnOAuthRefresh(func(credName string) {
			if injectErr := injectEnvVarsFromStore(db, containerMgr); injectErr != nil {
				log.Printf("[INJECT-OAUTH] env injection after refresh for %q failed: %v", credName, injectErr)
			} else {
				log.Printf("[INJECT-OAUTH] env vars re-injected after refresh for %q", credName)
			}
		})
	}

	// Inject the MITM CA certificate into the agent container/VM so TLS
	// interception is trusted. The CA cert is created by proxy.New above.
	// Docker handles this via compose volumes so InjectCACert is a no-op.
	// Apple Container and macOS VM update the guest trust store.
	if containerMgr != nil && *certDir != "" {
		hostCertPath := filepath.Join(vaultCfg.Dir, "ca-cert.pem")
		if _, statErr := os.Stat(hostCertPath); statErr == nil {
			ctx := context.Background()
			if injectErr := containerMgr.InjectCACert(ctx, hostCertPath, *certDir); injectErr != nil {
				log.Printf("WARNING: CA cert injection failed: %v", injectErr)
			} else {
				log.Printf("CA cert injected into agent via %s", containerMgr.Runtime())
			}
		} else {
			log.Printf("WARNING: CA cert not found at %s, skipping injection", hostCertPath)
		}
	}

	// Instantiate all enabled channels (Telegram and/or HTTP).
	var allChannels []channel.Channel

	if telegramEnabled {
		var channelErr error
		tgChannel, channelErr = telegram.NewTelegramChannel(telegram.ChannelConfig{
			Token:        *telegramToken,
			ChatID:       telegramChatID,
			EnginePtr:    srv.EnginePtr(),
			ResolverPtr:  srv.ResolverPtr(),
			ReloadMu:     srv.ReloadMu(),
			AuditPath:    *auditPath,
			Vault:        vaultStore,
			ContainerMgr: containerMgr,
			Store:        db,
			MCPURL:       deriveMCPBaseURL(*mcpBaseURL, *healthAddr),
			OnEngineSwap: srv.UpdateInspectRules,
			OnOAuthIndexRebuild: func() {
				if db == nil {
					return
				}
				metas, err := db.ListCredentialMeta()
				if err != nil {
					log.Printf("[WARN] list credential meta for OAuth index rebuild: %v", err)
					return
				}
				srv.UpdateOAuthIndex(metas)
			},
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

	// MCP gateway: if upstreams are configured, start the gateway and
	// serve it via HTTP on /mcp alongside the API. The mcpHandler local
	// is consumed by the startup goroutine below and by the HTTP API
	// server that exposes /mcp.
	var mcpHandler http.Handler
	upstreamRows, mcpListErr := db.ListMCPUpstreams()
	if mcpListErr != nil {
		log.Printf("WARNING: failed to list MCP upstreams: %v", mcpListErr)
	} else if len(upstreamRows) > 0 {
		mcpUpstreams := make([]mcp.UpstreamConfig, len(upstreamRows))
		for i, r := range upstreamRows {
			mcpUpstreams[i] = mcp.UpstreamConfig{
				Name:       r.Name,
				Command:    r.Command,
				Args:       r.Args,
				Env:        r.Env,
				Headers:    r.Headers,
				TimeoutSec: r.TimeoutSec,
				Transport:  r.Transport,
			}
		}

		toolRules := eng.ToolRules()
		toolPolicy, tpErr := mcp.NewToolPolicy(toolRules, eng.Default)
		if tpErr != nil {
			log.Fatalf("compile MCP tool policy: %v", tpErr)
		}

		var mcpInspector *mcp.ContentInspector
		if len(eng.InspectBlockRules) > 0 || len(eng.InspectRedactRules) > 0 {
			mcpInspector, err = mcp.NewContentInspector(eng.InspectBlockRules, eng.InspectRedactRules)
			if err != nil {
				log.Fatalf("create MCP content inspector: %v", err)
			}
		}

		// Wire the exec argument inspector with default tool name patterns
		// (*exec*, *shell*, *run_command*, *terminal*). Blocks trampoline
		// patterns, dangerous commands, and GIT_SSH_COMMAND-style env
		// overrides before the tool call reaches the upstream.
		execInspector, execErr := mcp.NewExecInspector(nil)
		if execErr != nil {
			log.Fatalf("create MCP exec inspector: %v", execErr)
		}

		var credResolver mcp.CredentialResolver
		if provider != nil {
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

		mcpGW, gwErr := mcp.NewGateway(mcp.GatewayConfig{
			Upstreams:          mcpUpstreams,
			ToolPolicy:         toolPolicy,
			Inspector:          mcpInspector,
			ExecInspector:      execInspector,
			Audit:              logger,
			Broker:             broker,
			TimeoutSec:         eng.TimeoutSec,
			Store:              db,
			CredentialResolver: credResolver,
		})
		if gwErr != nil {
			log.Fatalf("start MCP gateway: %v", gwErr)
		}
		defer mcpGW.Stop()

		mcpHandler = mcp.NewMCPHTTPHandler(mcpGW)
		log.Printf("MCP gateway on /mcp: %d tools from %d upstreams", len(mcpGW.Tools()), len(mcpUpstreams))
	}

	// Startup agent container setup: env var injection, secrets reload,
	// and MCP gateway wiring. All phases retry with backoff because the
	// agent container may still be starting (compose healthcheck ordering
	// ensures sluice starts first). Runs in a goroutine so sluice's HTTP
	// API and SOCKS5 listeners come up immediately. All phases are no-ops
	// outside a container runtime setup.
	if containerMgr != nil && db != nil {
		hasMCPGateway := mcpHandler != nil
		go func() {
			// Phase 1: write .env file into the agent container with
			// phantom tokens from bindings that declare env_var.
			backoff := []time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}
			injected := false
			for i, delay := range backoff {
				if delay > 0 {
					time.Sleep(delay)
				}
				if err := injectEnvVarsFromStore(db, containerMgr); err != nil {
					if i < len(backoff)-1 {
						log.Printf("startup env injection attempt %d/%d failed: %v (retrying)", i+1, len(backoff), err)
						continue
					}
					log.Printf("WARNING: startup env injection failed after %d attempts: %v", len(backoff), err)
				} else {
					log.Printf("startup env injection succeeded (attempt %d/%d)", i+1, len(backoff))
					injected = true
					break
				}
			}
			if !injected {
				return
			}
			// Phase 2: signal the agent to reload secrets. The gateway
			// takes longer to start than the container itself, so retry
			// with a longer backoff.
			reloadBackoff := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 60 * time.Second}
			reloadedSecrets := false
			for i, delay := range reloadBackoff {
				time.Sleep(delay)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := containerMgr.ReloadSecrets(ctx); err != nil {
					cancel()
					if i < len(reloadBackoff)-1 {
						log.Printf("startup secrets reload attempt %d/%d failed: %v (retrying)", i+1, len(reloadBackoff), err)
						continue
					}
					log.Printf("WARNING: startup secrets reload failed after %d attempts: %v", len(reloadBackoff), err)
				} else {
					cancel()
					log.Printf("startup secrets reload succeeded (attempt %d/%d)", i+1, len(reloadBackoff))
					reloadedSecrets = true
					break
				}
			}
			if !reloadedSecrets || !hasMCPGateway {
				return
			}
			// Phase 3: wire sluice's MCP gateway URL into the agent's
			// openclaw.json config via WebSocket RPC. Idempotent.
			// deriveMCPBaseURL already returns a URL ending in /mcp.
			mcpURL := deriveMCPBaseURL(*mcpBaseURL, *healthAddr)
			wireCtx, wireCancel := context.WithTimeout(context.Background(), 15*time.Second)
			if wireErr := containerMgr.WireMCPGateway(wireCtx, "sluice", mcpURL); wireErr != nil {
				log.Printf("WARNING: failed to wire MCP gateway into agent config: %v", wireErr)
			} else {
				log.Printf("MCP gateway wired into agent config: mcp.servers.sluice.url=%s", mcpURL)
			}
			wireCancel()
		}()
	}

	// Start HTTP server with health check and REST API on :3000 (or --health-addr).
	apiServer := api.NewServer(db, broker, srv, *auditPath)
	apiServer.SetEnginePtr(srv.EnginePtr(), srv.ReloadMu())
	apiServer.SetResolverPtr(srv.ResolverPtr())
	if vaultStore != nil {
		apiServer.SetVault(vaultStore)
	}
	if containerMgr != nil {
		apiServer.SetContainerManager(containerMgr)
	}
	healthLn, healthSrv := startAPIServer(*healthAddr, apiServer, db, mcpHandler)
	if healthLn != nil {
		defer func() { _ = healthSrv.Close() }()
		log.Printf("HTTP API server listening on %s", healthLn.Addr())
	}

	log.Printf("sluice SOCKS5 proxy listening on %s", srv.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// reloadAll reloads policy, bindings, and OAuth index from the database.
	// Called by both SIGHUP handler and the SQLite data_version watcher.
	reloadAll := func() {
		srv.ReloadMu().Lock()
		defer srv.ReloadMu().Unlock()

		newEng, loadErr := policy.LoadFromStore(db)
		if loadErr != nil {
			log.Printf("reload policy failed: %v", loadErr)
			return
		}

		if valErr := newEng.Validate(); valErr != nil {
			log.Printf("reload policy validation failed: %v", valErr)
			return
		}

		log.Printf("reloaded policy: %d allow, %d deny, %d ask rules (default: %s)",
			len(newEng.AllowRules), len(newEng.DenyRules), len(newEng.AskRules), newEng.Default)
		srv.StoreEngine(newEng)
		srv.UpdateInspectRules(newEng)

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

		if metas, metaErr := db.ListCredentialMeta(); metaErr == nil {
			srv.UpdateOAuthIndex(metas)
		} else {
			log.Printf("reload oauth index failed: %v", metaErr)
		}

		// Re-inject env vars into the agent container after binding changes.
		if containerMgr != nil {
			if injectErr := injectEnvVarsFromStore(db, containerMgr); injectErr != nil {
				log.Printf("reload env injection failed: %v", injectErr)
			}
		}

		if broker == nil && (len(newEng.AskRules) > 0 || newEng.Default == policy.Ask) {
			log.Printf("WARNING: policy has ask rules but no approval broker is running; ask verdicts will auto-deny")
		}
	}

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

	go func() {
		for range sighupCh {
			reloadAll()
			drainSignals(sighupCh)
		}
	}()

	// Watch for database changes from external connections (CLI commands).
	// Triggers the same reload as SIGHUP without requiring manual signals.
	dbWatcher := store.NewWatcher(db.DB(), reloadAll)
	dbWatcher.Start()
	defer dbWatcher.Stop()

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
		// Stop macOS VM and tear down pf rules if active.
		if tartMgr != nil {
			shutdownMacOSVM(tartMgr, tartRouter, tartVMOwned)
		}
		// Audit logger is closed via defer after all connections drain.
	case err := <-errCh:
		// Clean up macOS VM and pf rules before exiting on proxy failure.
		if tartMgr != nil {
			shutdownMacOSVM(tartMgr, tartRouter, tartVMOwned)
		}
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

	vc.OnePassword.Token = cfg.Vault1PasswordToken
	vc.OnePassword.Vault = cfg.Vault1PasswordVault
	vc.OnePassword.Field = cfg.Vault1PasswordField

	vc.Bitwarden.Token = cfg.VaultBitwardenToken
	vc.Bitwarden.OrgID = cfg.VaultBitwardenOrgID

	vc.KeePass.Path = cfg.VaultKeePassPath
	vc.KeePass.KeyFilePath = cfg.VaultKeePassKeyFile

	vc.Gopass.StorePath = cfg.VaultGopassStore

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
			Destination: r.Destination,
			Ports:       r.Ports,
			Credential:  r.Credential,
			Header:      r.Header,
			Template:    r.Template,
			Protocols:   r.Protocols,
		}
	}
	return bindings, nil
}

// injectEnvVarsFromStore reads bindings with env_var set from the store,
// generates phantom tokens for each, and injects them into the agent
// container via the container manager. This is called at startup and after
// credential/binding changes (reload).
func injectEnvVarsFromStore(db *store.Store, mgr container.ContainerManager) error {
	envBindings, err := db.ListBindingsWithEnvVar()
	if err != nil {
		return fmt.Errorf("list bindings with env_var: %w", err)
	}
	envMap := make(map[string]string, len(envBindings))
	for _, b := range envBindings {
		// Use the MITM-compatible phantom format (SLUICE_PHANTOM:<credname>)
		// so the proxy's byte-level find-and-replace works when the agent
		// passes the env var value in HTTP headers or request body.
		envMap[b.EnvVar] = proxy.PhantomToken(b.Credential)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := mgr.InjectEnvVars(ctx, envMap, true); err != nil {
		return fmt.Errorf("inject env vars: %w", err)
	}
	log.Printf("injected %d env vars into agent container", len(envMap))
	return nil
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

// detectRuntime returns which container runtime to use based on availability.
// Returns "docker", "apple", or "" (no runtime found).
// On macOS, prefers Apple Container if both are available.
// tartAvailable is accepted but tart (macOS VM) is never auto-selected because
// macOS VMs are heavyweight (2-4s boot, 1.5GB+ RAM). Use --runtime macos explicitly.
func detectRuntime(dockerAvailable, appleAvailable, tartAvailable bool, goos string) string {
	if goos == "darwin" && appleAvailable {
		return "apple"
	}
	if dockerAvailable {
		return "docker"
	}
	// tartAvailable is intentionally not used for auto-detection.
	// Log a hint when tart is available but no lighter runtime was found.
	if goos == "darwin" && tartAvailable {
		log.Printf("tart CLI found but not auto-selected (macOS VMs are heavyweight); use --runtime macos to enable")
	}
	return ""
}

// isDockerSocketAvailable checks whether a Docker socket exists and is a Unix
// socket. socketFlag is the value of --docker-socket (empty for auto-detect).
func isDockerSocketAvailable(socketFlag string) bool {
	sock, err := resolveDockerSocket(socketFlag)
	if err != nil || sock == "" {
		return false
	}
	fi, err := os.Stat(sock)
	return err == nil && fi.Mode().Type() == os.ModeSocket
}

// isAppleCLIAvailable checks whether the Apple Container `container` binary
// is in PATH.
func isAppleCLIAvailable() bool {
	_, err := exec.LookPath("container")
	return err == nil
}

// isTartCLIAvailable checks whether the tart CLI binary is in PATH.
func isTartCLIAvailable() bool {
	_, err := exec.LookPath("tart")
	return err == nil
}

// startAPIServer starts the HTTP server with the generated chi router.
// It serves /healthz (no auth), /api/* (bearer auth), and optionally
// /mcp (MCP Streamable HTTP, no auth) when mcpHandler is non-nil.
func startAPIServer(addr string, apiSrv *api.Server, _ *store.Store, mcpHandler http.Handler) (net.Listener, *http.Server) {
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
	// Bearer token auth protects all /api/* routes. The API is accessible
	// whenever SLUICE_API_TOKEN is set, regardless of which channels are enabled.
	apiHandler := api.HandlerWithOptions(apiSrv, api.ChiServerOptions{
		Middlewares: []api.MiddlewareFunc{
			api.BearerAuthMiddleware,
		},
	})

	var handler http.Handler
	if mcpHandler != nil {
		mux := http.NewServeMux()
		mux.Handle("/mcp", mcpHandler)
		mux.Handle("/", apiHandler)
		handler = mux
	} else {
		handler = apiHandler
	}

	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go httpSrv.Serve(ln) //nolint:errcheck
	return ln, httpSrv
}

// buildSelfBypass expands a health-addr listen address into all concrete
// host:port strings that should bypass SOCKS5 policy. When the address
// binds to 0.0.0.0 or [::], it expands to 127.0.0.1:port and [::1]:port
// so connections from the agent container to sluice's loopback addresses
// are also auto-allowed.
func buildSelfBypass(healthAddr string) []string {
	host, port, err := net.SplitHostPort(healthAddr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname (e.g. "sluice"). Include as-is.
		return []string{healthAddr}
	}
	if ip.IsUnspecified() {
		// Listening on all interfaces. Bypass loopback addresses.
		return []string{
			net.JoinHostPort("127.0.0.1", port),
			net.JoinHostPort("::1", port),
		}
	}
	return []string{healthAddr}
}

// selfBypassFromURL extracts a host:port from the given base URL that should
// be added to the self-bypass set. If the URL host differs from the listen
// address (e.g. "sluice" vs "0.0.0.0"), it returns the URL's host:port so
// Docker DNS names are also bypassed. Returns "" when redundant.
func selfBypassFromURL(baseURL, healthAddr string) string {
	// Strip scheme.
	hostport := strings.TrimPrefix(baseURL, "https://")
	hostport = strings.TrimPrefix(hostport, "http://")
	// Strip path.
	if idx := strings.Index(hostport, "/"); idx >= 0 {
		hostport = hostport[:idx]
	}
	// Ensure port is present; default to the health-addr port.
	if _, _, splitErr := net.SplitHostPort(hostport); splitErr != nil {
		_, port, _ := net.SplitHostPort(healthAddr)
		if port == "" {
			port = "3000"
		}
		hostport = net.JoinHostPort(hostport, port)
	}
	return hostport
}

// deriveMCPBaseURL returns the full MCP endpoint URL for auto-injection.
// If mcpBaseURL is set, it appends /mcp (if not already present).
// Otherwise it derives the URL from the health-addr listen address.
func deriveMCPBaseURL(mcpBaseURL, healthAddr string) string {
	if mcpBaseURL != "" {
		u := strings.TrimRight(mcpBaseURL, "/")
		if !strings.HasSuffix(u, "/mcp") {
			u += "/mcp"
		}
		return u
	}
	// Derive from health-addr. Replace 0.0.0.0 with 127.0.0.1 for local access.
	host, port, err := net.SplitHostPort(healthAddr)
	if err != nil {
		return "http://127.0.0.1:3000/mcp"
	}
	if host == "0.0.0.0" || host == "" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/mcp", net.JoinHostPort(host, port))
}

// seedStoreFromConfig imports a TOML config file into the store if the store
// is empty. Returns nil if the store is not empty or if the config file does
// not exist (logged as a warning). Returns an error for other failures.
func seedStoreFromConfig(db *store.Store, configPath string) error {
	empty, err := db.IsEmpty()
	if err != nil {
		return fmt.Errorf("check store: %w", err)
	}
	if !empty {
		return nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("config seed file %s not found, starting with empty DB", configPath)
			return nil
		}
		return fmt.Errorf("read config seed file: %w", err)
	}

	result, err := db.ImportTOML(data)
	if err != nil {
		return fmt.Errorf("import config seed: %w", err)
	}
	log.Printf("seeded DB from %s: %d rules, %d bindings, %d upstreams, %d config",
		configPath, result.RulesInserted,
		result.BindingsInserted, result.UpstreamsInserted, result.ConfigSet)
	return nil
}

// startMacOSVM handles the full macOS VM startup sequence for --runtime macos:
// (1) create TartCLI, (2) check if VM exists, (3) clone from image if needed,
// (4) start VM in background goroutine, (5) wait for VM IP, (6) set up pf
// routing. Returns the TartManager, NetworkRouter (for shutdown cleanup),
// the ContainerManager interface, and a boolean indicating whether sluice
// started the VM. Calls log.Fatalf on unrecoverable errors.
func startMacOSVM(vmImage, vmName, certDir string) (*container.TartManager, *container.NetworkRouter, container.ContainerManager, bool) {
	cli, cliErr := container.NewTartCLI(nil)
	if cliErr != nil {
		log.Fatalf("--runtime macos: tart CLI not available: %v", cliErr)
	}

	mgr, router, owned, err := setupMacOSVM(cli, vmImage, vmName, certDir)
	if err != nil {
		log.Fatalf("--runtime macos: %v", err)
	}
	return mgr, router, mgr, owned
}

// buildTartRunConfig creates the TartRunConfig with VirtioFS mounts.
func buildTartRunConfig(vmName, certDir string) container.TartRunConfig {
	var dirMounts []container.TartDirMount
	if certDir != "" {
		dirMounts = append(dirMounts, container.TartDirMount{
			Name: "ca", HostPath: certDir, ReadOnly: true,
		})
	}
	return container.TartRunConfig{
		Name:       vmName,
		DirMounts:  dirMounts,
		NoGraphics: true,
	}
}

// VM IP polling parameters.
const (
	vmIPPollMaxAttempts = 30
	vmIPPollBaseDelay   = 500 * time.Millisecond
	vmIPPollIncrement   = 200 * time.Millisecond
)

// waitForVMIP polls for the VM's IP address with linear backoff. Returns the
// IP or an error if the VM does not acquire one within the polling budget.
func waitForVMIP(ctx context.Context, cli *container.TartCLI, vmName string) (string, error) {
	for attempt := 0; attempt < vmIPPollMaxAttempts; attempt++ {
		ip, ipErr := cli.IP(ctx, vmName)
		if ipErr == nil && ip != "" {
			return ip, nil
		}
		time.Sleep(vmIPPollBaseDelay + time.Duration(attempt)*vmIPPollIncrement)
	}
	return "", fmt.Errorf("VM %q did not get an IP address within timeout", vmName)
}

// setupMacOSVM performs the macOS VM startup sequence using the provided
// TartCLI. It returns an error instead of calling log.Fatalf, making it
// testable. The startCmd callback launches `tart run` in a background
// process. When nil, the default uses os/exec. The returned boolean
// indicates whether sluice started the VM (true) or attached to an
// already-running VM (false). Only VMs started by sluice should be
// stopped on shutdown.
func setupMacOSVM(cli *container.TartCLI, vmImage, vmName, certDir string) (*container.TartManager, *container.NetworkRouter, bool, error) {
	ctx := context.Background()

	// Check if VM already exists.
	exists, err := cli.VMExists(ctx, vmName)
	if err != nil {
		return nil, nil, false, fmt.Errorf("check VM existence: %w", err)
	}

	if !exists {
		log.Printf("cloning macOS VM %q from %q (this may take several minutes for macOS images)...", vmName, vmImage)
		if cloneErr := cli.Clone(ctx, vmImage, vmName); cloneErr != nil {
			return nil, nil, false, fmt.Errorf("clone VM: %w", cloneErr)
		}
		log.Printf("macOS VM %q cloned successfully", vmName)
	}

	// Check if VM is already running.
	state, stateErr := cli.VMState(ctx, vmName)
	if stateErr != nil {
		return nil, nil, false, fmt.Errorf("check VM state: %w", stateErr)
	}

	runCfg := buildTartRunConfig(vmName, certDir)

	// Track whether sluice started the VM so we only stop it on shutdown
	// if we own it. Attaching to a pre-existing VM and then killing it on
	// exit would be surprising and disruptive.
	vmStartedBySluice := false

	// Start the VM in a background goroutine if not already running.
	// Uses cli.StartVM() which calls cmd.Start() internally, avoiding the
	// blocking cli.Run() path that would hang forever.
	if !strings.EqualFold(state, "running") {
		tartCmd, startErr := cli.StartVM(runCfg)
		if startErr != nil {
			return nil, nil, false, fmt.Errorf("start VM: %w", startErr)
		}
		vmStartedBySluice = true
		// Monitor the background process. If it exits unexpectedly, log the error.
		go func() {
			if waitErr := tartCmd.Wait(); waitErr != nil {
				log.Printf("WARNING: macOS VM %q exited: %v", vmName, waitErr)
			}
		}()
		log.Printf("macOS VM %q starting in background (pid=%d)...", vmName, tartCmd.Process.Pid)
	} else {
		log.Printf("macOS VM %q is already running (attaching without ownership)", vmName)
	}

	// cleanupVM stops the VM if sluice started it. Used as a safety net when
	// later setup steps fail, preventing an orphaned VM with ungoverned
	// network access.
	cleanupVM := func(reason string) {
		if !vmStartedBySluice {
			return
		}
		log.Printf("stopping macOS VM %q after setup failure: %s", vmName, reason)
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		if stopErr := cli.Stop(stopCtx, vmName); stopErr != nil {
			log.Printf("WARNING: failed to stop orphaned VM %q: %v", vmName, stopErr)
		}
	}

	vmIP, ipErr := waitForVMIP(ctx, cli, vmName)
	if ipErr != nil {
		cleanupVM("wait for VM IP failed")
		return nil, nil, false, fmt.Errorf("wait for VM IP: %w", ipErr)
	}
	log.Printf("macOS VM %q IP: %s", vmName, vmIP)

	// Create TartManager with the run config for potential restarts.
	mgr := container.NewTartManager(container.TartManagerConfig{
		CLI:       cli,
		VMName:    vmName,
		RunConfig: runCfg,
	})

	// Set up pf routing to redirect VM traffic through tun2proxy to SOCKS5.
	// Routing failure is fatal because without it the VM has a direct network
	// path that bypasses sluice policy enforcement.
	router := container.NewNetworkRouter(container.NetworkRouterConfig{})
	routeCtx, routeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer routeCancel()
	if routeErr := mgr.SetupNetworkRouting(routeCtx, router, ""); routeErr != nil {
		cleanupVM("pf routing setup failed")
		return nil, nil, false, fmt.Errorf("pf routing setup failed (VM traffic would bypass sluice): %w", routeErr)
	}
	log.Printf("pf routing configured for macOS VM %q", vmName)

	log.Printf("macOS VM manager enabled: vm=%s, image=%s", vmName, vmImage)
	return mgr, router, vmStartedBySluice, nil
}

// shutdownMacOSVM tears down pf routing rules and optionally stops the VM.
// The VM is only stopped when ownedBySluice is true, meaning sluice started
// it. When sluice attached to a pre-existing VM, pf rules are still cleaned
// up but the VM is left running.
func shutdownMacOSVM(mgr *container.TartManager, router *container.NetworkRouter, ownedBySluice bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if router != nil {
		if err := mgr.TeardownNetworkRouting(ctx, router); err != nil {
			log.Printf("WARNING: pf teardown failed: %v", err)
		} else {
			log.Printf("pf routing rules removed")
		}
	}

	if !ownedBySluice {
		log.Printf("macOS VM was not started by sluice, leaving it running")
		return
	}

	if err := mgr.Stop(ctx); err != nil {
		log.Printf("WARNING: failed to stop macOS VM: %v", err)
	} else {
		log.Printf("macOS VM stopped")
	}
}

// buildInspectRuleConfigs converts policy engine inspect rules into
// protocol-specific config structs for WebSocket and QUIC content inspection.
func buildInspectRuleConfigs(eng *policy.Engine) (
	wsBlock []proxy.WSBlockRuleConfig,
	wsRedact []proxy.WSRedactRuleConfig,
	quicBlock []proxy.QUICBlockRuleConfig,
	quicRedact []proxy.QUICRedactRuleConfig,
) {
	for _, r := range eng.InspectBlockRules {
		wsBlock = append(wsBlock, proxy.WSBlockRuleConfig{Pattern: r.Pattern, Name: r.Name})
		quicBlock = append(quicBlock, proxy.QUICBlockRuleConfig{Pattern: r.Pattern, Name: r.Name})
	}
	for _, r := range eng.InspectRedactRules {
		wsRedact = append(wsRedact, proxy.WSRedactRuleConfig{Pattern: r.Pattern, Replacement: r.Replacement, Name: r.Name})
		quicRedact = append(quicRedact, proxy.QUICRedactRuleConfig{Pattern: r.Pattern, Replacement: r.Replacement, Name: r.Name})
	}
	return
}
