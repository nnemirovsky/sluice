package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
	defer db.Close()

	// Seed with initial policy.
	db.SetConfig("default_verdict", "deny")
	db.AddRule("allow", "api.example.com", []int{443}, store.RuleOpts{})

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
	defer srv.Close()

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
				db.SetConfig("default_verdict", "deny")
			} else {
				db.SetConfig("default_verdict", "allow")
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
	defer db.Close()

	db.SetConfig("default_verdict", "deny")
	db.AddRule("allow", "api.example.com", []int{443}, store.RuleOpts{})

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
	defer srv.Close()

	// Set an invalid default verdict in the store. With typed config, the
	// CHECK constraint rejects the invalid value at the DB level.
	setErr := db.SetConfig("default_verdict", "invalid_verdict")
	if setErr == nil {
		t.Fatal("expected error setting invalid default verdict (CHECK constraint)")
	}
	// LoadFromStore should still succeed with the original valid config.
	_, loadErr := policy.LoadFromStore(db)
	if loadErr != nil {
		t.Fatalf("unexpected error loading policy after rejected SetConfig: %v", loadErr)
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
	defer db.Close()

	db.SetConfig("default_verdict", "deny")
	db.AddRule("allow", "example.com", nil, store.RuleOpts{})

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
	defer db.Close()

	db.SetConfig("default_verdict", "deny")

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

	healthLn, healthSrv := startHealthServer("127.0.0.1:0", srv)
	if healthLn == nil {
		t.Fatal("health server listener is nil")
	}
	defer healthSrv.Close()

	healthURL := "http://" + healthLn.Addr().String() + "/healthz"

	// Give the HTTP server a moment to start accepting.
	time.Sleep(10 * time.Millisecond)

	// Proxy created but not yet serving, should get 503.
	resp0, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz before serve: %v", err)
	}
	resp0.Body.Close()
	if resp0.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 before proxy is serving, got %d", resp0.StatusCode)
	}

	// Start serving in background.
	go srv.ListenAndServe()
	time.Sleep(10 * time.Millisecond)

	// Proxy is serving, should get 200.
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 while proxy is up, got %d", resp.StatusCode)
	}

	// Close the proxy.
	srv.Close()

	// Should get 503 now.
	resp2, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz after close: %v", err)
	}
	resp2.Body.Close()
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

[telegram]
bot_token_env = "MY_BOT_TOKEN"

[[allow]]
destination = "api.example.com"
ports = [443]

[[deny]]
destination = "evil.example.com"

[[binding]]
destination = "api.example.com"
ports = [443]
credential = "example_key"
inject_header = "Authorization"
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
	defer db.Close()

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
	// Telegram env var names are now hardcoded, not stored in config.
	if eng.Telegram.BotTokenEnv != "" {
		t.Errorf("expected empty bot_token_env (hardcoded), got %q", eng.Telegram.BotTokenEnv)
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
	defer db.Close()

	// Initial state: deny everything.
	db.SetConfig("default_verdict", "deny")

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
	defer srv.Close()

	// Verify initial state.
	v := srv.EnginePtr().Load().Evaluate("api.example.com", 443)
	if v != policy.Deny {
		t.Fatalf("expected initial Deny, got %s", v)
	}

	// Add a rule to the store (as would happen via CLI or Telegram).
	db.AddRule("allow", "api.example.com", []int{443}, store.RuleOpts{Source: "manual"})

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
	defer db.Close()

	// No vault config set explicitly. Typed config has "age" as default.
	cfg, err := readVaultConfig(db)
	if err != nil {
		t.Fatalf("read default vault config: %v", err)
	}
	if cfg.Provider != "age" {
		t.Errorf("expected default provider 'age', got %q", cfg.Provider)
	}

	// Set some vault config.
	db.SetConfig("vault_provider", "hashicorp")
	db.SetConfig("vault_hashicorp_addr", "https://vault.example.com:8200")
	db.SetConfig("vault_hashicorp_mount", "secret")

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
	defer db.Close()

	// Empty store should return empty bindings.
	bindings, err := readBindings(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("expected 0 bindings, got %d", len(bindings))
	}

	// Add bindings.
	db.AddBinding("api.example.com", "my_key", store.BindingOpts{
		Ports:        []int{443},
		InjectHeader: "Authorization",
		Template:     "Bearer {value}",
	})
	db.AddBinding("github.com", "gh_key", store.BindingOpts{
		Ports:    []int{22},
		Protocol: "ssh",
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
	if bindings[1].Protocol != "ssh" {
		t.Errorf("expected protocol ssh, got %q", bindings[1].Protocol)
	}
}

// TestStoreIsEmpty verifies the IsEmpty method works correctly.
func TestStoreIsEmpty(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	empty, err := db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Error("expected empty store")
	}

	// Config changes don't affect emptiness (typed singleton always exists).
	// Adding a rule makes it non-empty.
	db.AddRule("allow", "example.com", nil, store.RuleOpts{})

	empty, err = db.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("expected non-empty store after adding rule")
	}
}
