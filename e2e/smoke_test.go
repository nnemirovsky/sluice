//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

func TestSmoke_HealthzReturns200(t *testing.T) {
	proc := startSluice(t, SluiceOpts{})

	resp, err := http.Get(proc.HealthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSmoke_SOCKS5Listening(t *testing.T) {
	proc := startSluice(t, SluiceOpts{})

	// Verify we can establish a SOCKS5 connection to the proxy port.
	dialer := connectSOCKS5(t, proc.ProxyAddr)
	if dialer == nil {
		t.Fatal("SOCKS5 dialer is nil")
	}
}

func TestSmoke_WithConfigSeed(t *testing.T) {
	configTOML := `
[policy]
default = "deny"

[[allow]]
destination = "example.com"
ports = [443]
name = "test allow"
`
	proc := startSluice(t, SluiceOpts{ConfigTOML: configTOML})

	resp, err := http.Get(proc.HealthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after config seed, got %d", resp.StatusCode)
	}
}
