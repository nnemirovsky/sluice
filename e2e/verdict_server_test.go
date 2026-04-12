//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestVerdictServer_ReturnsVerdictsInOrder verifies that the verdict server
// returns each configured verdict in sequence and defaults to "deny" once
// the sequence is exhausted.
func TestVerdictServer_ReturnsVerdictsInOrder(t *testing.T) {
	srv, vs := startVerdictServer(t, "allow_once", "always_allow", "deny")

	verdicts := []string{"allow_once", "always_allow", "deny", "deny", "deny"}
	for i, want := range verdicts {
		resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"id":"req-1","type":"approval","destination":"example.com","port":443}`))
		if err != nil {
			t.Fatalf("call %d: POST failed: %v", i, err)
		}
		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("call %d: decode response: %v", i, err)
		}
		_ = resp.Body.Close()

		if got := result["verdict"]; got != want {
			t.Errorf("call %d: verdict = %q, want %q", i, got, want)
		}
	}

	if got := vs.Calls(); got != 5 {
		t.Errorf("calls = %d, want 5", got)
	}
}

// TestVerdictServer_RecordsRequests verifies that the verdict server records
// every incoming request body for later inspection.
func TestVerdictServer_RecordsRequests(t *testing.T) {
	srv, vs := startVerdictServer(t, "allow_once")

	body := `{"id":"abc-123","type":"approval","destination":"api.github.com","port":443,"protocol":"https"}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	_ = resp.Body.Close()

	reqs := vs.Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests count = %d, want 1", len(reqs))
	}

	req := reqs[0]
	if dest, ok := req["destination"].(string); !ok || dest != "api.github.com" {
		t.Errorf("destination = %v, want %q", req["destination"], "api.github.com")
	}
	if port, ok := req["port"].(float64); !ok || port != 443 {
		t.Errorf("port = %v, want 443", req["port"])
	}
}

// TestVerdictServer_DefaultsDenyWhenEmpty verifies that a verdict server
// with no configured verdicts always returns "deny".
func TestVerdictServer_DefaultsDenyWhenEmpty(t *testing.T) {
	srv, vs := startVerdictServer(t)

	for i := 0; i < 3; i++ {
		resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"id":"x","type":"approval","destination":"evil.com","port":80}`))
		if err != nil {
			t.Fatalf("call %d: POST failed: %v", i, err)
		}
		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("call %d: decode: %v", i, err)
		}
		_ = resp.Body.Close()

		if got := result["verdict"]; got != "deny" {
			t.Errorf("call %d: verdict = %q, want %q", i, got, "deny")
		}
	}

	if got := vs.Calls(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

// TestVerdictServer_RejectsNonPOST verifies that GET and other methods are
// rejected with 405 Method Not Allowed.
func TestVerdictServer_RejectsNonPOST(t *testing.T) {
	srv, vs := startVerdictServer(t, "allow_once")

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	// Should not count as a call.
	if got := vs.Calls(); got != 0 {
		t.Errorf("calls = %d, want 0", got)
	}
}
