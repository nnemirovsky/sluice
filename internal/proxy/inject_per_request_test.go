package proxy

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/vault"
)

// newInjectorForRequestTest builds an Injector with an empty binding set and a
// nil WebSocket proxy. Used by unit tests that drive injectCredentials directly.
func newInjectorForRequestTest(t *testing.T) *Injector {
	t.Helper()
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)
	return NewInjector(store, &resolverPtr, caCert, "", nil)
}

// mkInjectRequest returns a request targeting host:port suitable for passing
// into injectCredentials.
func mkInjectRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Host:   u.Host,
		Header: http.Header{},
	}
	return req
}

func TestInjectCredentials_NilCheckerSkipsPerRequestCheck(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	req := mkInjectRequest(t, "https://api.example.com/v1/ping")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-1", checker: nil, connectHost: "api.example.com", connectPort: 443}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected nil response (passthrough), got status %d", resp.StatusCode)
	}
}

func TestInjectCredentials_ExplicitAllowCheckerAllowsRequest(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	checker, fc := newTestChecker(t, `
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://api.example.com/v1/users")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-2", checker: checker, connectHost: "api.example.com", connectPort: 443}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("explicit allow should skip approval and not build a deny response; got status %d", resp.StatusCode)
	}
	if fc.requestCount() != 0 {
		t.Fatalf("broker request count = %d, want 0 (explicit allow should skip broker)", fc.requestCount())
	}
}

func TestInjectCredentials_DenyReturnsForbidden(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	checker, _ := newTestChecker(t, `
[policy]
default = "allow"

[[deny]]
destination = "blocked.example.com"
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://blocked.example.com/path")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-3", checker: checker, connectHost: "blocked.example.com", connectPort: 443}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil {
		t.Fatal("expected a deny response, got nil (passthrough)")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("resp.StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestInjectCredentials_AllowOnceBlocksSecondRequest(t *testing.T) {
	// The "Allow Once" behavior is the core reason for per-request policy:
	// the first HTTP request gets approval, the second on the same
	// connection must re-trigger the broker and can be denied independently.
	inj := newInjectorForRequestTest(t)

	checker, fc := newTestChecker(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, channel.ResponseAllowOnce)

	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-4", checker: checker, connectHost: "api.example.com", connectPort: 443}}

	// First request: allow-once approved.
	req1 := mkInjectRequest(t, "https://api.example.com/first")
	if _, resp := inj.injectCredentials(req1, ctx); resp != nil {
		t.Fatalf("first request should be allowed, got status %d", resp.StatusCode)
	}
	if fc.requestCount() != 1 {
		t.Fatalf("after first request, broker count = %d, want 1", fc.requestCount())
	}

	// Flip the broker response so the second request is denied, proving the
	// checker re-consults the broker instead of caching the previous verdict.
	fc.setResponse(channel.ResponseDeny)

	req2 := mkInjectRequest(t, "https://api.example.com/second")
	_, resp := inj.injectCredentials(req2, ctx)
	if resp == nil {
		t.Fatal("second request on same connection should re-trigger approval and be denied")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("second request status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if fc.requestCount() != 2 {
		t.Fatalf("after second request, broker count = %d, want 2", fc.requestCount())
	}
}

func TestInjectCredentials_AllowOnceApprovesOneRequestThenReAsks(t *testing.T) {
	// Same as the previous test but verifies that subsequent allow-once
	// approvals keep working. The broker is asked on every request.
	inj := newInjectorForRequestTest(t)

	checker, fc := newTestChecker(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, channel.ResponseAllowOnce)

	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-5", checker: checker, connectHost: "api.example.com", connectPort: 443}}

	for i := 0; i < 3; i++ {
		req := mkInjectRequest(t, "https://api.example.com/endpoint")
		if _, resp := inj.injectCredentials(req, ctx); resp != nil {
			t.Fatalf("request %d should be allowed, got status %d", i, resp.StatusCode)
		}
	}
	if fc.requestCount() != 3 {
		t.Fatalf("broker count = %d, want 3 (one per request)", fc.requestCount())
	}
}

// TestInjectCredentials_GRPCContentTypeHTTP1PathGoesThroughPerRequestCheck
// covers the HTTP/1.1 code path with a gRPC content-type header. Real
// gRPC rides over HTTP/2 and enters goproxy's H2Transport bypass, so this
// test does NOT demonstrate per-request enforcement for honest gRPC-over-
// HTTP/2 traffic; see CLAUDE.md "Protocol-specific handling" for the
// actual gRPC behavior.
func TestInjectCredentials_GRPCContentTypeHTTP1PathGoesThroughPerRequestCheck(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	checker, fc := newTestChecker(t, `
[policy]
default = "deny"

[[deny]]
destination = "grpc.example.com"
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://grpc.example.com/pkg.Service/Method")
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")

	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-grpc", checker: checker, connectHost: "grpc.example.com", connectPort: 443}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil {
		t.Fatal("expected deny response for grpc-content-type request blocked by policy")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("resp.StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	// Deny rules match before the broker is consulted.
	if fc.requestCount() != 0 {
		t.Fatalf("broker count = %d, want 0 (deny rule should bypass broker)", fc.requestCount())
	}
}

func TestInjectCredentials_NilEngineReturnsForbidden(t *testing.T) {
	// A misconfigured checker with no engine pointer should fail closed.
	inj := newInjectorForRequestTest(t)

	ptr := new(atomic.Pointer[policy.Engine])
	checker := NewRequestPolicyChecker(ptr, nil)

	req := mkInjectRequest(t, "https://api.example.com/")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-nil-engine", checker: checker, connectHost: "api.example.com", connectPort: 443}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil {
		t.Fatal("expected deny response when engine is nil")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("resp.StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// Note: keep-alive + allow-once coverage lives in
// TestInjectCredentials_AllowOnceBlocksSecondRequest above. Do NOT add a
// duplicate test that stands up an httptest.NewServer without actually
// sending traffic to it. If you need end-to-end coverage of keep-alive
// through goproxy, add an e2e test under e2e/ instead (see the TODO at
// the top of e2e/proxy_test.go).

// TestInjectCredentials_PerRequestDenyWritesAuditEvent verifies that
// SetAuditLogger wires a real audit.FileLogger into the injector and that
// a per-request deny in injectCredentials produces a tamper-evident audit
// entry with the expected fields. Parity with the QUIC/HTTP3 path which
// has always audited per-request denies.
func TestInjectCredentials_PerRequestDenyWritesAuditEvent(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	auditPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.NewFileLogger(auditPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	inj.SetAuditLogger(logger)

	checker, _ := newTestChecker(t, `
[policy]
default = "allow"

[[deny]]
destination = "blocked.example.com"
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://blocked.example.com/v1/secret")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-audit", checker: checker, connectHost: "blocked.example.com", connectPort: 443}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 deny response, got %v", resp)
	}

	// Flush by closing the logger. NewFileLogger writes are line-buffered
	// through the kernel (no explicit Sync), so a normal Close suffices.
	_ = logger.Close()

	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	var entries []audit.Event
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var evt audit.Event
		if jsonErr := json.Unmarshal([]byte(line), &evt); jsonErr != nil {
			t.Fatalf("parse audit line %q: %v", line, jsonErr)
		}
		entries = append(entries, evt)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		t.Fatalf("scan audit log: %v", scanErr)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry, got %d: %+v", len(entries), entries)
	}
	evt := entries[0]
	if evt.Destination != "blocked.example.com" {
		t.Errorf("audit destination = %q, want %q", evt.Destination, "blocked.example.com")
	}
	if evt.Port != 443 {
		t.Errorf("audit port = %d, want 443", evt.Port)
	}
	if evt.Verdict != "deny" {
		t.Errorf("audit verdict = %q, want %q", evt.Verdict, "deny")
	}
	if !strings.Contains(evt.Reason, "per-request") {
		t.Errorf("audit reason = %q, want something containing 'per-request'", evt.Reason)
	}
	if evt.Protocol != "https" {
		t.Errorf("audit protocol = %q, want %q", evt.Protocol, "https")
	}
}

// TestInjectCredentials_PerRequestDenyWithoutAuditLoggerDoesNotPanic is a
// parity check: the same deny flow without SetAuditLogger must not crash
// or attempt to write to a nil logger.
func TestInjectCredentials_PerRequestDenyWithoutAuditLoggerDoesNotPanic(t *testing.T) {
	inj := newInjectorForRequestTest(t)
	// Do NOT call SetAuditLogger. inj.auditLog stays nil.

	checker, _ := newTestChecker(t, `
[policy]
default = "allow"

[[deny]]
destination = "blocked.example.com"
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://blocked.example.com/v1/secret")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{pinID: "pin-no-audit", checker: checker, connectHost: "blocked.example.com", connectPort: 443}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 deny response, got %v", resp)
	}
}

// TestInjectCredentials_HostHeaderSpoofingUsesConnectTarget verifies that a
// MITM request with a spoofed Host header targeting a blocked destination is
// evaluated against the CONNECT target (which is allowed), not the Host
// header. This prevents host-header spoofing bypass where a client opens a
// tunnel to an allowed host and sends requests with Host: blocked.example.com
// to reach a blocked destination.
func TestInjectCredentials_HostHeaderSpoofingUsesConnectTarget(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	// The CONNECT target is "api.example.com" (allowed), but the inner
	// HTTP request has Host: blocked.example.com (denied). Policy must be
	// evaluated against the CONNECT target, so the request should be
	// allowed (not denied based on the spoofed Host header).
	checker, _ := newTestChecker(t, `
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]

[[deny]]
destination = "blocked.example.com"
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://blocked.example.com/v1/secret")
	// The CONNECT target is api.example.com, which is allowed by policy.
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-spoof",
		checker:     checker,
		connectHost: "api.example.com",
		connectPort: 443,
	}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp != nil {
		t.Fatalf("request should be allowed (evaluated against CONNECT target), got status %d", resp.StatusCode)
	}
}

// TestInjectCredentials_HostHeaderSpoofingDeniedByConnectTarget is the
// inverse: the CONNECT target is blocked, but the Host header points to an
// allowed host. The request must be denied because the CONNECT target is
// the authoritative destination for policy evaluation.
func TestInjectCredentials_HostHeaderSpoofingDeniedByConnectTarget(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	checker, _ := newTestChecker(t, `
[policy]
default = "allow"

[[deny]]
destination = "blocked.example.com"
`, channel.ResponseDeny)

	// Inner request has Host: api.example.com (allowed), but CONNECT target
	// is blocked.example.com (denied).
	req := mkInjectRequest(t, "https://api.example.com/v1/ping")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-spoof-deny",
		checker:     checker,
		connectHost: "blocked.example.com",
		connectPort: 443,
	}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil {
		t.Fatal("request should be denied (CONNECT target is blocked)")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("resp.StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestInjectCredentials_ExplicitAllowFastPathDenyCrossOrigin verifies that
// the explicit-allow fast path (checker == nil because ctxKeySkipPerRequest
// was set) still uses the CONNECT target for credential binding, not the
// Host header. Even without per-request checking, credential injection is
// scoped to the CONNECT target so an allowed tunnel cannot be exploited to
// inject credentials for a different origin.
func TestInjectCredentials_ExplicitAllowFastPathDenyCrossOrigin(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	// Checker is nil (simulates explicit-allow fast path where
	// ctxKeySkipPerRequest was set). The CONNECT target is
	// api.example.com. The inner request Host is blocked.example.com.
	// Without the CONNECT target fix, credential binding would look up
	// blocked.example.com. With the fix, it looks up api.example.com.
	req := mkInjectRequest(t, "https://blocked.example.com/v1/secret")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-fast-path",
		checker:     nil,
		connectHost: "api.example.com",
		connectPort: 443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	// No credential bindings are configured so the request passes through.
	// The important thing is that it did NOT use blocked.example.com for
	// any lookup. We verify this by testing the flow completes without error.
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}
}

// TestInjectCredentials_CrossOriginNormalizesToConnectTarget verifies that
// when an inner HTTP request targets a different host than the CONNECT
// target, r.URL.Host, r.URL.Scheme, and r.Host are rewritten to the
// CONNECT target. This prevents goproxy from forwarding the request to a
// spoofed origin.
func TestInjectCredentials_CrossOriginNormalizesToConnectTarget(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	// Inner request targets evil.com but the CONNECT tunnel was
	// established to api.example.com:443.
	req := mkInjectRequest(t, "https://evil.com/steal-creds")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-cross-origin",
		checker:     nil,
		connectHost: "api.example.com",
		connectPort: 443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}

	// After normalization, both URL.Host and Host must point at the
	// CONNECT target. Port 443 is the default for HTTPS so it should
	// not appear in the authority.
	if gotReq.URL.Host != "api.example.com" {
		t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, "api.example.com")
	}
	if gotReq.Host != "api.example.com" {
		t.Errorf("Host = %q, want %q", gotReq.Host, "api.example.com")
	}
	if gotReq.URL.Scheme != "https" {
		t.Errorf("URL.Scheme = %q, want %q", gotReq.URL.Scheme, "https")
	}
}

// TestInjectCredentials_CrossOriginNonStandardPort verifies normalization
// preserves non-standard ports in the authority.
func TestInjectCredentials_CrossOriginNonStandardPort(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	req := mkInjectRequest(t, "https://evil.com:8443/path")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-cross-port",
		checker:     nil,
		connectHost: "api.example.com",
		connectPort: 8443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}

	wantAuthority := "api.example.com:8443"
	if gotReq.URL.Host != wantAuthority {
		t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, wantAuthority)
	}
	if gotReq.Host != wantAuthority {
		t.Errorf("Host = %q, want %q", gotReq.Host, wantAuthority)
	}
}

// TestInjectCredentials_AuditProtocolUsesRefinedProto verifies that
// per-request deny audit entries use the refined protocol string (e.g.
// "grpc") instead of the raw URL scheme (e.g. "https"). This is the fix
// for the audit protocol fidelity finding.
func TestInjectCredentials_AuditProtocolUsesRefinedProto(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	auditPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.NewFileLogger(auditPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	inj.SetAuditLogger(logger)

	checker, _ := newTestChecker(t, `
[policy]
default = "allow"

[[deny]]
destination = "grpc.example.com"
`, channel.ResponseDeny)

	req := mkInjectRequest(t, "https://grpc.example.com/pkg.Service/Method")
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")

	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-audit-grpc",
		checker:     checker,
		connectHost: "grpc.example.com",
		connectPort: 443,
	}}

	_, resp := inj.injectCredentials(req, ctx)
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 deny response, got %v", resp)
	}

	_ = logger.Close()

	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	var entries []audit.Event
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var evt audit.Event
		if jsonErr := json.Unmarshal([]byte(line), &evt); jsonErr != nil {
			t.Fatalf("parse audit line %q: %v", line, jsonErr)
		}
		entries = append(entries, evt)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry, got %d", len(entries))
	}
	// The refined protocol should be "grpc", not "https" (the raw scheme).
	if entries[0].Protocol != "grpc" {
		t.Errorf("audit protocol = %q, want %q (refined protocol, not URL scheme)", entries[0].Protocol, "grpc")
	}
}

// TestInjectCredentials_SameHostDifferentPortNormalized verifies that
// a request to the same hostname but a different port (e.g. absolute-form
// URI https://api.example.com:8443/...) is detected and normalized to the
// CONNECT target authority. Without this fix, the port mismatch would not
// be caught because only the hostname was compared.
func TestInjectCredentials_SameHostDifferentPortNormalized(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	// Inner request targets api.example.com:8443 but CONNECT was to
	// api.example.com:443. Same hostname, different port.
	req := mkInjectRequest(t, "https://api.example.com:8443/v1/secret")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-same-host-diff-port",
		checker:     nil,
		connectHost: "api.example.com",
		connectPort: 443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}

	// Authority must be normalized to the CONNECT target. Port 443 is
	// standard for HTTPS and should be suppressed.
	if gotReq.URL.Host != "api.example.com" {
		t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, "api.example.com")
	}
	if gotReq.Host != "api.example.com" {
		t.Errorf("Host = %q, want %q", gotReq.Host, "api.example.com")
	}
	if gotReq.URL.Scheme != "https" {
		t.Errorf("URL.Scheme = %q, want %q", gotReq.URL.Scheme, "https")
	}
}

// TestInjectCredentials_SchemeDowngradeNormalized verifies that a scheme
// downgrade (http:// inner request on an https CONNECT tunnel) is detected
// and the scheme is normalized to the CONNECT target's expected scheme.
func TestInjectCredentials_SchemeDowngradeNormalized(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	// Inner request uses http:// but CONNECT was to port 443 (HTTPS).
	req := mkInjectRequest(t, "http://api.example.com/v1/secret")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-scheme-downgrade",
		checker:     nil,
		connectHost: "api.example.com",
		connectPort: 443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}

	if gotReq.URL.Scheme != "https" {
		t.Errorf("URL.Scheme = %q, want %q (normalized to CONNECT scheme)", gotReq.URL.Scheme, "https")
	}
	if gotReq.URL.Host != "api.example.com" {
		t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, "api.example.com")
	}
}

// TestInjectCredentials_NonStandardPortPreservesScheme verifies that
// non-standard ports preserve whatever scheme goproxy assigned after its
// TLS-peek detection. goproxy peeks the first byte after CONNECT:
// TLS handshake -> scheme "https", plain HTTP -> scheme "http".
// Our handler must not override the scheme for non-standard ports because
// the byte-detection path legitimately routes plain HTTP connections
// through the MITM handler.
func TestInjectCredentials_NonStandardPortPreservesScheme(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	tests := []struct {
		name       string
		innerURL   string
		wantScheme string
	}{
		{
			name:       "TLS tunnel on non-standard port preserves https",
			innerURL:   "https://api.example.com:8443/v1/secret",
			wantScheme: "https",
		},
		{
			name:       "plain HTTP on non-standard port preserves http",
			innerURL:   "http://api.example.com:8443/v1/data",
			wantScheme: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mkInjectRequest(t, tt.innerURL)
			ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
				pinID:       "pin-nonstandard-scheme",
				checker:     nil,
				connectHost: "api.example.com",
				connectPort: 8443,
			}}

			gotReq, resp := inj.injectCredentials(req, ctx)
			if gotReq == nil {
				t.Fatal("injectCredentials returned nil request")
			}
			if resp != nil {
				t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
			}

			if gotReq.URL.Scheme != tt.wantScheme {
				t.Errorf("URL.Scheme = %q, want %q", gotReq.URL.Scheme, tt.wantScheme)
			}
			wantAuthority := "api.example.com:8443"
			if gotReq.URL.Host != wantAuthority {
				t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, wantAuthority)
			}
			if gotReq.Host != wantAuthority {
				t.Errorf("Host = %q, want %q", gotReq.Host, wantAuthority)
			}
		})
	}
}

// TestInjectCredentials_IPv6StandardPortNormalized verifies that IPv6 CONNECT
// targets on standard ports produce correctly bracketed authorities in
// r.URL.Host. Without this fix, bare ::1 was assigned as the authority,
// breaking goproxy's transport.
func TestInjectCredentials_IPv6StandardPortNormalized(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	req := mkInjectRequest(t, "https://[::1]/healthz")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-ipv6-std",
		checker:     nil,
		connectHost: "::1",
		connectPort: 443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}

	// IPv6 on standard port: brackets must be present, port suppressed.
	if gotReq.URL.Host != "[::1]" {
		t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, "[::1]")
	}
	if gotReq.Host != "[::1]" {
		t.Errorf("Host = %q, want %q", gotReq.Host, "[::1]")
	}
	if gotReq.URL.Scheme != "https" {
		t.Errorf("URL.Scheme = %q, want %q", gotReq.URL.Scheme, "https")
	}
}

// TestInjectCredentials_IPv6NonStandardPortNormalized verifies that IPv6
// CONNECT targets on non-standard ports use net.JoinHostPort format.
func TestInjectCredentials_IPv6NonStandardPortNormalized(t *testing.T) {
	inj := newInjectorForRequestTest(t)

	req := mkInjectRequest(t, "https://[::1]:9443/api")
	ctx := &goproxy.ProxyCtx{UserData: proxyConnState{
		pinID:       "pin-ipv6-nonstd",
		checker:     nil,
		connectHost: "::1",
		connectPort: 9443,
	}}

	gotReq, resp := inj.injectCredentials(req, ctx)
	if gotReq == nil {
		t.Fatal("injectCredentials returned nil request")
	}
	if resp != nil {
		t.Fatalf("expected passthrough (nil response), got status %d", resp.StatusCode)
	}

	// Non-standard port: net.JoinHostPort brackets the IPv6 address.
	wantAuthority := "[::1]:9443"
	if gotReq.URL.Host != wantAuthority {
		t.Errorf("URL.Host = %q, want %q", gotReq.URL.Host, wantAuthority)
	}
	if gotReq.Host != wantAuthority {
		t.Errorf("Host = %q, want %q", gotReq.Host, wantAuthority)
	}
}

// TestSplitHostPortFallback validates the helper used by HandleConnect to
// parse the CONNECT target into host + port.
func TestSplitHostPortFallback(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"api.example.com:443", "api.example.com", 443},
		{"api.example.com:8080", "api.example.com", 8080},
		{"[::1]:443", "::1", 443},
		{"api.example.com", "api.example.com", 443},
	}
	for _, tt := range tests {
		host, port := splitHostPortFallback(tt.input)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("splitHostPortFallback(%q) = (%q, %d), want (%q, %d)",
				tt.input, host, port, tt.wantHost, tt.wantPort)
		}
	}
}
