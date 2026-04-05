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

	// Verify we can actually dial through the SOCKS5 proxy to the health endpoint.
	dialer := connectSOCKS5(t, proc.ProxyAddr)
	_, port := mustSplitAddr(t, proc.HealthURL)
	conn, err := dialer.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("dial through SOCKS5 proxy: %v", err)
	}
	conn.Close()
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
