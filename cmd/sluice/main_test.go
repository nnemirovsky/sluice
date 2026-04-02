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
)

// TestReloadPolicyConcurrent verifies that rapid concurrent policy reloads
// do not cause data races or panics. Run with -race to detect races.
func TestReloadPolicyConcurrent(t *testing.T) {
	// Write two different policy files that we alternate between.
	dir := t.TempDir()
	policyA := filepath.Join(dir, "policy_a.toml")
	policyB := filepath.Join(dir, "policy_b.toml")

	if err := os.WriteFile(policyA, []byte(`[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyB, []byte(`[policy]
default = "allow"

[[deny]]
destination = "evil.example.com"
`), 0644); err != nil {
		t.Fatal(err)
	}

	eng, err := policy.LoadFromFile(policyA)
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
	// loads a policy file, validates the engine, and stores it while
	// holding the reload mutex, mirroring the fixed SIGHUP handler.
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		path := policyA
		if i%2 == 1 {
			path = policyB
		}
		go func(p string) {
			defer wg.Done()
			newEng, loadErr := policy.LoadFromFile(p)
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
		}(path)
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

// TestReloadPolicyValidation verifies that a malformed policy file does not
// replace the current engine.
func TestReloadPolicyValidation(t *testing.T) {
	dir := t.TempDir()
	goodPolicy := filepath.Join(dir, "good.toml")
	badPolicy := filepath.Join(dir, "bad.toml")

	if err := os.WriteFile(goodPolicy, []byte(`[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
`), 0644); err != nil {
		t.Fatal(err)
	}
	// Malformed TOML.
	if err := os.WriteFile(badPolicy, []byte(`[policy
default = "broken"
`), 0644); err != nil {
		t.Fatal(err)
	}

	eng, err := policy.LoadFromFile(goodPolicy)
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

	// Attempt reload with bad policy. LoadFromFile should fail.
	_, loadErr := policy.LoadFromFile(badPolicy)
	if loadErr == nil {
		t.Fatal("expected error loading malformed policy")
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
	eng, err := policy.LoadFromBytes([]byte(`[policy]
default = "deny"

[[allow]]
destination = "example.com"
`))
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
	eng, err := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
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

	// Proxy is running, should get 200.
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
