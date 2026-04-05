package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/api"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/store"
)

// TestReloadPolicyConcurrent verifies that rapid concurrent policy reloads
// do not cause data races or panics. Run with -race to detect races.
func TestReloadPolicyConcurrent(t *testing.T) {
	// Create an in-memory store with two different policy states.
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Seed with initial policy.
	dv := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load initial policy: %v", err)
	}

	srv, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Simulate rapid concurrent SIGHUP-style reloads. Each goroutine
	// modifies the store and recompiles the engine.
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			// Alternate between adding/removing a rule to vary state.
			if n%2 == 0 {
				vd := "deny"
				_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &vd})
			} else {
				va := "allow"
				_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &va})
			}
			newEng, loadErr := policy.LoadFromStore(db)
			if loadErr != nil {
				t.Errorf("load policy: %v", loadErr)
				return
			}
			if valErr := newEng.Validate(); valErr != nil {
				t.Errorf("validate policy: %v", valErr)
				return
			}
			srv.ReloadMu().Lock()
			srv.StoreEngine(newEng)
			srv.ReloadMu().Unlock()
		}(i)
	}
	wg.Wait()

	// Verify the engine is still functional after all the swaps.
	finalEng := srv.EnginePtr().Load()
	if finalEng == nil {
		t.Fatal("engine pointer is nil after concurrent reloads")
	}
	// Smoke test: evaluation should not panic.
	_ = finalEng.Evaluate("api.example.com", 443)
}

// TestReloadPolicyValidation verifies that a malformed store state does not
// crash the reload and that the existing engine is preserved on load failure.
func TestReloadPolicyValidation(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dvVal := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvVal})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load good policy: %v", err)
	}

	srv, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Set an invalid default verdict in the store. With typed config, the
	// CHECK constraint rejects the invalid value at the DB level.
	invalidVal := "invalid_verdict"
	setErr := db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &invalidVal})
	if setErr == nil {
		t.Fatal("expected error setting invalid default verdict (CHECK constraint)")
	}
	// LoadFromStore should still succeed with the original valid config.
	_, loadErr := policy.LoadFromStore(db)
	if loadErr != nil {
		t.Fatalf("unexpected error loading policy after rejected UpdateConfig: %v", loadErr)
	}

	// Engine should still be the original.
	currentEng := srv.EnginePtr().Load()
	if currentEng != eng {
		t.Error("engine was replaced despite load failure")
	}
	// Verify original engine still works.
	v := currentEng.Evaluate("api.example.com", 443)
	if v != policy.Allow {
		t.Errorf("expected Allow for api.example.com:443, got %s", v)
	}
}

// TestDrainSignals verifies that drainSignals empties buffered signals.
func TestDrainSignals(t *testing.T) {
	ch := make(chan os.Signal, 5)

	// Buffer several signals.
	for i := 0; i < 5; i++ {
		ch <- os.Interrupt
	}
	if len(ch) != 5 {
		t.Fatalf("expected 5 buffered signals, got %d", len(ch))
	}

	drainSignals(ch)

	if len(ch) != 0 {
		t.Errorf("expected 0 buffered signals after drain, got %d", len(ch))
	}
}

// TestDrainSignalsEmpty verifies drainSignals is a no-op on empty channel.
func TestDrainSignalsEmpty(t *testing.T) {
	ch := make(chan os.Signal, 5)
	drainSignals(ch) // should not block
}

// TestEngineValidate verifies the Validate method on policy.Engine.
func TestEngineValidate(t *testing.T) {
	// A properly loaded engine should pass validation.
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dvEV := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvEV})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "example.com"})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := eng.Validate(); err != nil {
		t.Errorf("expected valid engine, got: %v", err)
	}

	// A nil engine should fail validation.
	var nilEng *policy.Engine
	if err := nilEng.Validate(); err == nil {
		t.Error("expected error for nil engine")
	}
}

// TestHealthzEndpoint verifies that /healthz returns 200 when the proxy is up
// and 503 after the proxy is closed.
func TestHealthzEndpoint(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dvHealth := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvHealth})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	srv, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	apiSrv := api.NewServer(db, nil, srv, "")
	healthLn, healthSrv := startAPIServer("127.0.0.1:0", apiSrv, db, nil)
	if healthLn == nil {
		t.Fatal("health server listener is nil")
	}
	defer func() { _ = healthSrv.Close() }()

	healthURL := "http://" + healthLn.Addr().String() + "/healthz"

	// Give the HTTP server a moment to start accepting.
	time.Sleep(10 * time.Millisecond)

	// Proxy created but not yet serving, should get 503.
	resp0, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz before serve: %v", err)
	}
	_ = resp0.Body.Close()
	if resp0.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 before proxy is serving, got %d", resp0.StatusCode)
	}

	// Start serving in background.
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(10 * time.Millisecond)

	// Proxy is serving, should get 200.
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 while proxy is up, got %d", resp.StatusCode)
	}

	// Close the proxy.
	_ = srv.Close()

	// Should get 503 now.
	resp2, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz after close: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 after proxy close, got %d", resp2.StatusCode)
	}
}

// TestResolveDockerSocket verifies the Docker socket resolution logic.
func TestResolveDockerSocket(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		envHost  string
		want     string
		wantErr  bool
	}{
		{
			name: "default path when nothing set",
			want: "/var/run/docker.sock",
		},
		{
			name:     "explicit path",
			explicit: "/custom/docker.sock",
			want:     "/custom/docker.sock",
		},
		{
			name:    "unix scheme from env",
			envHost: "unix:///var/run/docker.sock",
			want:    "/var/run/docker.sock",
		},
		{
			name:    "tcp scheme rejected",
			envHost: "tcp://192.168.1.1:2375",
			wantErr: true,
		},
		{
			name:    "ssh scheme rejected",
			envHost: "ssh://user@remote",
			wantErr: true,
		},
		{
			name:     "explicit tcp path rejected",
			explicit: "tcp://192.168.1.1:2375",
			wantErr:  true,
		},
		{
			name:    "bare path from env",
			envHost: "/tmp/docker.sock",
			want:    "/tmp/docker.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DOCKER_HOST", tt.envHost)

			got, err := resolveDockerSocket(tt.explicit)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got path %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestStartupWithTOMLSeed verifies that starting with an empty DB and a TOML
// policy file seeds the database and produces a working engine.
func TestStartupWithTOMLSeed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	tomlPath := filepath.Join(dir, "seed.toml")

	tomlData := `[policy]
default = "deny"
timeout_sec = 60

[[allow]]
destination = "api.example.com"
ports = [443]

[[deny]]
destination = "evil.example.com"

[[binding]]
destination = "api.example.com"
ports = [443]
credential = "example_key"
header = "Authorization"
template = "Bearer {value}"
`
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}

	// Open store and seed from TOML.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	empty, err := db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Fatal("expected empty store")
	}

	data, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ImportTOML(data)
	if err != nil {
		t.Fatalf("import TOML: %v", err)
	}
	if result.RulesInserted != 2 {
		t.Errorf("expected 2 rules inserted, got %d", result.RulesInserted)
	}
	if result.BindingsInserted != 1 {
		t.Errorf("expected 1 binding inserted, got %d", result.BindingsInserted)
	}

	// Build engine from store.
	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if eng.Default != policy.Deny {
		t.Errorf("expected default Deny, got %s", eng.Default)
	}
	if eng.TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", eng.TimeoutSec)
	}
	if v := eng.Evaluate("api.example.com", 443); v != policy.Allow {
		t.Errorf("expected Allow for api.example.com:443, got %s", v)
	}
	if v := eng.Evaluate("evil.example.com", 443); v != policy.Deny {
		t.Errorf("expected Deny for evil.example.com:443, got %s", v)
	}

	// Verify store is not empty anymore.
	empty, err = db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("expected non-empty store after import")
	}

	// Second import should skip duplicates.
	result2, err := db.ImportTOML(data)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if result2.RulesInserted != 0 {
		t.Errorf("expected 0 rules inserted on second import, got %d", result2.RulesInserted)
	}

	// Read bindings from store.
	bindings, err := readBindings(db)
	if err != nil {
		t.Fatalf("read bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Credential != "example_key" {
		t.Errorf("expected credential example_key, got %q", bindings[0].Credential)
	}
	if bindings[0].Template != "Bearer {value}" {
		t.Errorf("expected template 'Bearer {value}', got %q", bindings[0].Template)
	}
}

// TestSIGHUPRecompileFromStore verifies that the SIGHUP reload path
// recompiles the engine from the store rather than from a file.
func TestSIGHUPRecompileFromStore(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Initial state: deny everything.
	dvSIG := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvSIG})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	srv, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Verify initial state.
	v := srv.EnginePtr().Load().Evaluate("api.example.com", 443)
	if v != policy.Deny {
		t.Fatalf("expected initial Deny, got %s", v)
	}

	// Add a rule to the store (as would happen via CLI or Telegram).
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Source: "manual"})

	// Simulate SIGHUP reload: recompile from store and swap.
	srv.ReloadMu().Lock()
	newEng, err := policy.LoadFromStore(db)
	if err != nil {
		srv.ReloadMu().Unlock()
		t.Fatalf("reload: %v", err)
	}
	if err := newEng.Validate(); err != nil {
		srv.ReloadMu().Unlock()
		t.Fatalf("validate: %v", err)
	}
	srv.StoreEngine(newEng)
	srv.ReloadMu().Unlock()

	// Verify the new engine picks up the store change.
	v = srv.EnginePtr().Load().Evaluate("api.example.com", 443)
	if v != policy.Allow {
		t.Errorf("expected Allow after reload, got %s", v)
	}
}

// TestReadVaultConfig verifies that vault config is correctly read from the store.
func TestReadVaultConfig(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// No vault config set explicitly. Typed config has "age" as default.
	cfg, err := readVaultConfig(db)
	if err != nil {
		t.Fatalf("read default vault config: %v", err)
	}
	if cfg.Provider != "age" {
		t.Errorf("expected default provider 'age', got %q", cfg.Provider)
	}

	// Set some vault config.
	vprov := "hashicorp"
	vaddr := "https://vault.example.com:8200"
	vmount := "secret"
	_ = db.UpdateConfig(store.ConfigUpdate{
		VaultProvider:      &vprov,
		VaultHashicorpAddr: &vaddr,
		VaultHashicorpMount: &vmount,
	})

	cfg, err = readVaultConfig(db)
	if err != nil {
		t.Fatalf("read vault config: %v", err)
	}
	if cfg.Provider != "hashicorp" {
		t.Errorf("expected provider hashicorp, got %q", cfg.Provider)
	}
	if cfg.HashiCorp.Addr != "https://vault.example.com:8200" {
		t.Errorf("expected addr https://vault.example.com:8200, got %q", cfg.HashiCorp.Addr)
	}
	if cfg.HashiCorp.Mount != "secret" {
		t.Errorf("expected mount secret, got %q", cfg.HashiCorp.Mount)
	}
}

// TestReadBindings verifies that bindings from the store are correctly
// converted to vault.Binding.
func TestReadBindings(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Empty store should return empty bindings.
	bindings, err := readBindings(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("expected 0 bindings, got %d", len(bindings))
	}

	// Add bindings.
	_, _ = db.AddBinding("api.example.com", "my_key", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})
	_, _ = db.AddBinding("github.com", "gh_key", store.BindingOpts{
		Ports:     []int{22},
		Protocols: []string{"ssh"},
	})

	bindings, err = readBindings(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
	if bindings[0].Destination != "api.example.com" {
		t.Errorf("expected destination api.example.com, got %q", bindings[0].Destination)
	}
	if bindings[0].Template != "Bearer {value}" {
		t.Errorf("expected template 'Bearer {value}', got %q", bindings[0].Template)
	}
	if len(bindings[1].Protocols) != 1 || bindings[1].Protocols[0] != "ssh" {
		t.Errorf("expected protocols [ssh], got %v", bindings[1].Protocols)
	}
}

// TestStoreIsEmpty verifies the IsEmpty method works correctly.
func TestStoreIsEmpty(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	empty, err := db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Error("expected empty store")
	}

	// Config changes don't affect emptiness (typed singleton always exists).
	// Adding a rule makes it non-empty.
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "example.com"})

	empty, err = db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("expected non-empty store after adding rule")
	}
}

// TestDetectRuntime verifies runtime auto-detection logic.
func TestDetectRuntime(t *testing.T) {
	tests := []struct {
		name            string
		dockerAvailable bool
		appleAvailable  bool
		tartAvailable   bool
		goos            string
		want            string
	}{
		{
			name: "no runtimes available",
			goos: "linux",
			want: "",
		},
		{
			name:            "docker only on linux",
			dockerAvailable: true,
			goos:            "linux",
			want:            "docker",
		},
		{
			name:            "docker only on darwin",
			dockerAvailable: true,
			goos:            "darwin",
			want:            "docker",
		},
		{
			name:           "apple only on darwin",
			appleAvailable: true,
			goos:           "darwin",
			want:           "apple",
		},
		{
			name:            "both on darwin prefers apple",
			dockerAvailable: true,
			appleAvailable:  true,
			goos:            "darwin",
			want:            "apple",
		},
		{
			name:           "apple binary on linux ignored",
			appleAvailable: true,
			goos:           "linux",
			want:           "",
		},
		{
			name:            "both on linux uses docker",
			dockerAvailable: true,
			appleAvailable:  true,
			goos:            "linux",
			want:            "docker",
		},
		{
			name: "no runtimes on darwin",
			goos: "darwin",
			want: "",
		},
		{
			name:          "tart only on darwin not auto-selected",
			tartAvailable: true,
			goos:          "darwin",
			want:          "",
		},
		{
			name:            "tart with docker on darwin uses docker",
			tartAvailable:   true,
			dockerAvailable: true,
			goos:            "darwin",
			want:            "docker",
		},
		{
			name:           "tart with apple on darwin uses apple",
			tartAvailable:  true,
			appleAvailable: true,
			goos:           "darwin",
			want:           "apple",
		},
		{
			name:            "all three on darwin prefers apple",
			tartAvailable:   true,
			dockerAvailable: true,
			appleAvailable:  true,
			goos:            "darwin",
			want:            "apple",
		},
		{
			name:          "tart on linux ignored",
			tartAvailable: true,
			goos:          "linux",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectRuntime(tt.dockerAvailable, tt.appleAvailable, tt.tartAvailable, tt.goos)
			if got != tt.want {
				t.Errorf("detectRuntime(%v, %v, %v, %q) = %q, want %q",
					tt.dockerAvailable, tt.appleAvailable, tt.tartAvailable, tt.goos, got, tt.want)
			}
		})
	}
}

// TestIsDockerSocketAvailable verifies Docker socket detection.
func TestIsDockerSocketAvailable(t *testing.T) {
	dir := t.TempDir()

	// Create a real Unix socket.
	sockPath := filepath.Join(dir, "test.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if !isDockerSocketAvailable(sockPath) {
		t.Error("expected true for real Unix socket")
	}

	// Non-existent path.
	if isDockerSocketAvailable(filepath.Join(dir, "nope.sock")) {
		t.Error("expected false for non-existent path")
	}

	// Regular file is not a socket.
	regularPath := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(regularPath, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if isDockerSocketAvailable(regularPath) {
		t.Error("expected false for regular file")
	}
}

// TestIsAppleCLIAvailable verifies the function returns without panicking.
func TestIsAppleCLIAvailable(t *testing.T) {
	// The container binary is typically not installed in test environments.
	// Just verify the function doesn't panic.
	got := isAppleCLIAvailable()
	if got {
		t.Log("container binary found in PATH (unexpected in most test envs)")
	}
}

// TestIsTartCLIAvailable verifies the function returns without panicking.
func TestIsTartCLIAvailable(t *testing.T) {
	// Just verify the function doesn't panic. tart may or may not be installed.
	_ = isTartCLIAvailable()
}

// TestStandaloneModeStartup verifies that --runtime none produces a working
// proxy and MCP gateway without any container manager. The proxy should accept
// SOCKS5 connections and the health endpoint should respond, but containerMgr
// remains nil.
func TestStandaloneModeStartup(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dv := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "example.com", Ports: []int{443}})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	// In standalone mode, containerMgr is nil. The proxy should still work.
	srv, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Health endpoint should work without a container manager.
	apiSrv := api.NewServer(db, nil, srv, "")
	apiSrv.SetEnginePtr(srv.EnginePtr(), srv.ReloadMu())
	healthLn, healthSrv := startAPIServer("127.0.0.1:0", apiSrv, db, nil)
	if healthLn == nil {
		t.Fatal("health server listener is nil")
	}
	defer func() { _ = healthSrv.Close() }()

	// Start proxy.
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(10 * time.Millisecond)

	// Health should report 200 with proxy running.
	healthURL := "http://" + healthLn.Addr().String() + "/healthz"
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 in standalone mode, got %d", resp.StatusCode)
	}

	// Policy engine still evaluates correctly.
	v := srv.EnginePtr().Load().Evaluate("example.com", 443)
	if v != policy.Allow {
		t.Errorf("expected Allow for example.com:443, got %s", v)
	}
	v = srv.EnginePtr().Load().Evaluate("unknown.com", 443)
	if v != policy.Deny {
		t.Errorf("expected Deny for unknown.com:443, got %s", v)
	}
}


// TestBuildSelfBypass verifies the self-bypass address expansion.
func TestBuildSelfBypass(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		want      []string
	}{
		{
			name: "specific IP",
			addr: "127.0.0.1:3000",
			want: []string{"127.0.0.1:3000"},
		},
		{
			name: "unspecified IPv4 expands to loopbacks",
			addr: "0.0.0.0:3000",
			want: []string{"127.0.0.1:3000", "[::1]:3000"},
		},
		{
			name: "unspecified IPv6 expands to loopbacks",
			addr: "[::]:3000",
			want: []string{"127.0.0.1:3000", "[::1]:3000"},
		},
		{
			name: "hostname preserved",
			addr: "sluice:3000",
			want: []string{"sluice:3000"},
		},
		{
			name: "invalid addr returns nil",
			addr: "invalid",
			want: nil,
		},
		{
			name: "specific IPv6",
			addr: "[::1]:3000",
			want: []string{"[::1]:3000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSelfBypass(tt.addr)
			if len(got) != len(tt.want) {
				t.Fatalf("buildSelfBypass(%q) = %v, want %v", tt.addr, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("buildSelfBypass(%q)[%d] = %q, want %q", tt.addr, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestSelfBypassFromURL verifies URL-to-bypass-entry extraction.
func TestSelfBypassFromURL(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		healthAddr string
		want       string
	}{
		{
			name:       "docker service name with port",
			baseURL:    "http://sluice:3000",
			healthAddr: "0.0.0.0:3000",
			want:       "sluice:3000",
		},
		{
			name:       "docker service name without port uses health port",
			baseURL:    "http://sluice",
			healthAddr: "0.0.0.0:3000",
			want:       "sluice:3000",
		},
		{
			name:       "URL with path stripped",
			baseURL:    "http://sluice:3000/mcp",
			healthAddr: "0.0.0.0:3000",
			want:       "sluice:3000",
		},
		{
			name:       "https scheme",
			baseURL:    "https://sluice:3000",
			healthAddr: "0.0.0.0:3000",
			want:       "sluice:3000",
		},
		{
			name:       "IP with port",
			baseURL:    "http://192.168.1.5:3000",
			healthAddr: "0.0.0.0:3000",
			want:       "192.168.1.5:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selfBypassFromURL(tt.baseURL, tt.healthAddr)
			if got != tt.want {
				t.Errorf("selfBypassFromURL(%q, %q) = %q, want %q", tt.baseURL, tt.healthAddr, got, tt.want)
			}
		})
	}
}

// TestEnvDefault verifies the envDefault helper function.
func TestEnvDefault(t *testing.T) {
	// With no env var set, should return fallback.
	got := envDefault("TEST_ENVDEFAULT_NOTSET_XYZ", "fallback")
	if got != "fallback" {
		t.Errorf("envDefault with unset var: got %q, want %q", got, "fallback")
	}

	// With env var set, should return env value.
	t.Setenv("TEST_ENVDEFAULT_SET_XYZ", "from-env")
	got = envDefault("TEST_ENVDEFAULT_SET_XYZ", "fallback")
	if got != "from-env" {
		t.Errorf("envDefault with set var: got %q, want %q", got, "from-env")
	}

	// Empty env var should return fallback (empty string is falsy).
	t.Setenv("TEST_ENVDEFAULT_EMPTY_XYZ", "")
	got = envDefault("TEST_ENVDEFAULT_EMPTY_XYZ", "fallback")
	if got != "fallback" {
		t.Errorf("envDefault with empty var: got %q, want %q", got, "fallback")
	}
}

// TestStartupFlagCombinations verifies that flag parsing accepts the expected
// flags. We cannot run full main() (it blocks on signal), but we can test
// the supporting functions that process flag values.
func TestStartupFlagCombinations(t *testing.T) {
	// Test that various helper functions work with flag-like inputs.

	// buildSelfBypass with various health-addr formats.
	bypass := buildSelfBypass("0.0.0.0:3000")
	if len(bypass) != 2 {
		t.Errorf("expected 2 bypass entries for 0.0.0.0, got %d", len(bypass))
	}

	bypass = buildSelfBypass("127.0.0.1:3000")
	if len(bypass) != 1 || bypass[0] != "127.0.0.1:3000" {
		t.Errorf("expected [127.0.0.1:3000], got %v", bypass)
	}

	// selfBypassFromURL with custom base URL.
	hp := selfBypassFromURL("http://sluice:3000/mcp", "0.0.0.0:3000")
	if hp != "sluice:3000" {
		t.Errorf("expected sluice:3000, got %q", hp)
	}
}

// TestAutoSeedOnEmptyDB verifies that when a DB is empty and a config path
// is provided, the TOML is imported as seed data.
func TestAutoSeedOnEmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "seed-test.db")
	tomlPath := filepath.Join(dir, "seed.toml")

	tomlData := `[policy]
default = "deny"

[[allow]]
destination = "seeded.example.com"
ports = [443]

[[binding]]
destination = "seeded.example.com"
ports = [443]
credential = "seeded_key"
header = "Authorization"
`
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}

	// Open store and seed from TOML (mirrors main() auto-seed logic).
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	empty, err := db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Fatal("expected empty store")
	}

	data, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ImportTOML(data)
	if err != nil {
		t.Fatalf("import TOML: %v", err)
	}
	if result.RulesInserted != 1 {
		t.Errorf("expected 1 rule, got %d", result.RulesInserted)
	}
	if result.BindingsInserted != 1 {
		t.Errorf("expected 1 binding, got %d", result.BindingsInserted)
	}

	// Build engine to verify policy works after seeding.
	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if eng.Default != policy.Deny {
		t.Errorf("expected default Deny, got %s", eng.Default)
	}
	v := eng.Evaluate("seeded.example.com", 443)
	if v != policy.Allow {
		t.Errorf("expected Allow for seeded.example.com:443, got %s", v)
	}

	// Verify non-empty now.
	empty, err = db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("expected non-empty store after import")
	}
}

// TestAutoSeedSkipsNonEmptyDB verifies that auto-seed does not run
// when the DB already has data.
func TestAutoSeedSkipsNonEmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "nonempty.db")

	// Create a non-empty DB.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "existing.example.com"})
	_ = db.Close()

	// Re-open and check IsEmpty.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	empty, err := db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("expected non-empty store")
	}

	// Auto-seed logic should not run since DB is not empty.
	// Verify existing rule is preserved.
	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 1 || rules[0].Destination != "existing.example.com" {
		t.Errorf("existing rule should be preserved, got: %v", rules)
	}
}

// TestAutoSeedMissingConfigFile verifies that a missing config file
// does not cause an error (it's logged as a warning).
func TestAutoSeedMissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	empty, _ := db.IsEmpty()
	if !empty {
		t.Fatal("expected empty store")
	}

	// Attempting to read a non-existent config file.
	_, readErr := os.ReadFile(filepath.Join(dir, "nonexistent.toml"))
	if readErr == nil {
		t.Fatal("expected error for missing file")
	}
	// Main() logic: if os.IsNotExist(err) -> log and continue, don't fatal.
	if !os.IsNotExist(readErr) {
		t.Errorf("expected IsNotExist, got: %v", readErr)
	}
}

// TestSeedStoreFromConfig verifies the extracted seed helper function.
func TestSeedStoreFromConfig(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "seed.toml")

	tomlData := `[policy]
default = "deny"

[[allow]]
destination = "seeded.example.com"
ports = [443]
`
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}

	// Test: seed empty store.
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if err := seedStoreFromConfig(db, tomlPath); err != nil {
		t.Fatalf("seedStoreFromConfig: %v", err)
	}

	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after seed, got %d", len(rules))
	}
	if rules[0].Destination != "seeded.example.com" {
		t.Errorf("destination = %q, want seeded.example.com", rules[0].Destination)
	}

	// Test: non-empty store skips seed.
	if err := seedStoreFromConfig(db, tomlPath); err != nil {
		t.Fatalf("seedStoreFromConfig on non-empty: %v", err)
	}
	rules, _ = db.ListRules(store.RuleFilter{})
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (no re-seed), got %d", len(rules))
	}
}

func TestSeedStoreFromConfigMissing(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Missing file should not return error (just logs).
	if err := seedStoreFromConfig(db, "/nonexistent/seed.toml"); err != nil {
		t.Fatalf("expected nil for missing file, got: %v", err)
	}
}

func TestSeedStoreFromConfigMalformed(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(tomlPath, []byte("not valid toml [[["), 0644); err != nil {
		t.Fatal(err)
	}

	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if err := seedStoreFromConfig(db, tomlPath); err == nil {
		t.Fatal("expected error for malformed TOML")
	}
}

// TestBuildInspectRuleConfigs verifies the inspect rule conversion helper.
func TestBuildInspectRuleConfigs(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dv := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv})
	_, _ = db.AddRule("deny", store.RuleOpts{Pattern: "(?i)secret", Name: "block secrets"})
	_, _ = db.AddRule("redact", store.RuleOpts{Pattern: "(?i)token", Replacement: "[REDACTED]", Name: "redact tokens"})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	wsBlock, wsRedact, quicBlock, quicRedact := buildInspectRuleConfigs(eng)

	if len(wsBlock) != 1 {
		t.Errorf("expected 1 ws block rule, got %d", len(wsBlock))
	} else if wsBlock[0].Pattern != "(?i)secret" {
		t.Errorf("ws block pattern = %q", wsBlock[0].Pattern)
	}

	if len(wsRedact) != 1 {
		t.Errorf("expected 1 ws redact rule, got %d", len(wsRedact))
	} else if wsRedact[0].Replacement != "[REDACTED]" {
		t.Errorf("ws redact replacement = %q", wsRedact[0].Replacement)
	}

	if len(quicBlock) != 1 {
		t.Errorf("expected 1 quic block rule, got %d", len(quicBlock))
	}
	if len(quicRedact) != 1 {
		t.Errorf("expected 1 quic redact rule, got %d", len(quicRedact))
	}
}

func TestBuildInspectRuleConfigsEmpty(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dv := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv})

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	wsBlock, wsRedact, quicBlock, quicRedact := buildInspectRuleConfigs(eng)
	if len(wsBlock) != 0 || len(wsRedact) != 0 || len(quicBlock) != 0 || len(quicRedact) != 0 {
		t.Error("expected all empty for engine without inspect rules")
	}
}

// TestStandaloneModeCredentialInjection verifies that credential injection
// (vault + binding resolver) works without a container manager, since the
// MITM proxy handles injection independently.
func TestStandaloneModeCredentialInjection(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dv := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}})

	// Add a binding. In standalone mode, credential injection still works
	// because the MITM proxy handles it, not the container manager.
	_, _ = db.AddBinding("api.example.com", "my_api_key", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})

	bindings, err := readBindings(db)
	if err != nil {
		t.Fatalf("read bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Credential != "my_api_key" {
		t.Errorf("expected credential my_api_key, got %q", bindings[0].Credential)
	}

	eng, err := policy.LoadFromStore(db)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	// Proxy works without a container manager (standalone mode).
	srv, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Engine evaluates correctly.
	v := srv.EnginePtr().Load().Evaluate("api.example.com", 443)
	if v != policy.Allow {
		t.Errorf("expected Allow, got %s", v)
	}
}
