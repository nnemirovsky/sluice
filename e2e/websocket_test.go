//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// wsEchoHandler returns an http.Handler that accepts WebSocket upgrades on
// /ws, sends a greeting containing the request headers, then echoes text
// messages back prefixed with "echo: ".
func wsEchoHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, acceptErr := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if acceptErr != nil {
			http.Error(w, acceptErr.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.CloseNow()

		// Send a greeting that includes request headers so tests can
		// verify credential injection in the WS upgrade handshake.
		var hdrs []string
		for name, vals := range r.Header {
			for _, v := range vals {
				hdrs = append(hdrs, name+": "+v)
			}
		}
		greeting := "headers: " + strings.Join(hdrs, "; ")
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(greeting))

		for {
			typ, msg, readErr := conn.Read(r.Context())
			if readErr != nil {
				return
			}
			if typ == websocket.MessageText {
				reply := "echo: " + string(msg)
				if writeErr := conn.Write(r.Context(), websocket.MessageText, []byte(reply)); writeErr != nil {
					return
				}
			}
		}
	})
	return mux
}

// startWSEchoServer starts a WebSocket echo server on a free port. It accepts
// WebSocket upgrade requests, reads text messages, and echoes them back
// prefixed with "echo: ". The server also copies incoming request headers into
// the first echo response so credential injection can be verified.
func startWSEchoServer(t *testing.T) (addr string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: wsEchoHandler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

// startTLSWSEchoServer starts a TLS WebSocket echo server backed by the test
// CA. It behaves identically to startWSEchoServer but over TLS.
func startTLSWSEchoServer(t *testing.T, ca *testCA) (addr string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverKey, keyErr := generateServerTLSCert(t, ca, "127.0.0.1")
	if keyErr != nil {
		t.Fatal(keyErr)
	}

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{serverKey},
	})

	srv := &http.Server{Handler: wsEchoHandler()}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

// TestWebSocket_AllowRulePermitsUpgradeAndEcho verifies that a WebSocket
// connection through sluice SOCKS5 works when an allow rule is configured.
// The test connects via SOCKS5, upgrades to WebSocket, sends a text message,
// and verifies the echo response.
func TestWebSocket_AllowRulePermitsUpgradeAndEcho(t *testing.T) {
	wsAddr := startWSEchoServer(t)
	host, port := splitHostPort(t, wsAddr)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow ws echo"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, "ws://"+wsAddr+"/ws", &websocket.DialOptions{
		HTTPClient: httpClientViaSOCKS5(t, proc.ProxyAddr),
	})
	if err != nil {
		t.Fatalf("websocket dial via SOCKS5: %v", err)
	}
	defer conn.CloseNow()

	// Read the greeting (headers).
	_, greeting, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	t.Logf("greeting: %s", greeting)

	// Send a message and verify echo.
	msg := "hello from e2e test"
	if err := conn.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
		t.Fatalf("write message: %v", err)
	}

	typ, reply, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("expected text message, got type %d", typ)
	}
	if string(reply) != "echo: "+msg {
		t.Fatalf("expected echo reply %q, got %q", "echo: "+msg, string(reply))
	}

	conn.Close(websocket.StatusNormalClosure, "done")

	// Verify audit log recorded the connection.
	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, host) {
		t.Error("audit log should contain entry for WebSocket connection")
	}
}

// TestWebSocket_DenyRuleBlocksHandshake verifies that a deny rule prevents
// the WebSocket handshake from completing.
func TestWebSocket_DenyRuleBlocksHandshake(t *testing.T) {
	wsAddr := startWSEchoServer(t)
	host, port := splitHostPort(t, wsAddr)

	config := fmt.Sprintf(`
[policy]
default = "allow"

[[deny]]
destination = "%s"
ports = [%s]
name = "block ws echo"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := websocket.Dial(ctx, "ws://"+wsAddr+"/ws", &websocket.DialOptions{
		HTTPClient: httpClientViaSOCKS5(t, proc.ProxyAddr),
	})
	if err == nil {
		t.Fatal("expected WebSocket dial to fail with deny rule, but it succeeded")
	}

	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, `"verdict":"deny"`) {
		t.Error("audit log should contain deny verdict for blocked WebSocket")
	}
}

// TestWebSocket_CredentialInjectionInUpgradeHeaders verifies that phantom
// tokens in WebSocket upgrade request headers are replaced with real
// credentials by the MITM proxy.
func TestWebSocket_CredentialInjectionInUpgradeHeaders(t *testing.T) {
	setup := startCredTestSluice(t, "")
	wsAddr := startTLSWSEchoServer(t, setup.CA)
	_, port := splitHostPort(t, wsAddr)

	// Add credential bound to the WS echo server.
	runCredAdd(t, setup.Proc, "ws_api_key", "ws-real-secret-789",
		"--destination", "127.0.0.1",
		"--ports", port,
		"--header", "X-Ws-Key",
	)
	sendSIGHUP(t, setup.Proc)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, "wss://127.0.0.1:"+port+"/ws", &websocket.DialOptions{
		HTTPClient: httpClientViaSOCKS5WithTLS(t, setup.Proc.ProxyAddr),
	})
	if err != nil {
		t.Fatalf("websocket dial via SOCKS5: %v", err)
	}
	defer conn.CloseNow()

	// Read the greeting which includes request headers.
	_, greeting, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	greetingStr := string(greeting)
	t.Logf("greeting: %s", greetingStr)

	// The upstream should have received the real credential in the header.
	if !strings.Contains(greetingStr, "ws-real-secret-789") {
		t.Errorf("upstream did not receive injected credential in WS upgrade\ngreeting: %s", greetingStr)
	}

	// Phantom token should not appear in the upstream headers.
	if strings.Contains(greetingStr, "SLUICE_PHANTOM") {
		t.Errorf("phantom token leaked to upstream in WS upgrade\ngreeting: %s", greetingStr)
	}

	conn.Close(websocket.StatusNormalClosure, "done")
}

// splitHostPort splits a host:port string. Unlike mustSplitAddr it does not
// strip URL scheme prefixes.
func splitHostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return host, port
}

// httpClientViaSOCKS5 returns an http.Client that routes all traffic through
// the given SOCKS5 proxy address.
func httpClientViaSOCKS5(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// httpClientViaSOCKS5WithTLS returns an http.Client that routes through SOCKS5
// and skips TLS verification (for MITM proxy connections).
func httpClientViaSOCKS5WithTLS(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}
}
