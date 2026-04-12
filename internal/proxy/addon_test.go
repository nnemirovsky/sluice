package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	uuid "github.com/satori/go.uuid"
)

// testOAuthTokenURL is the token endpoint used across all OAuth test helpers.
const testOAuthTokenURL = "https://auth.example.com/oauth/token"

// newTestClientConn creates a minimal ClientConn with a random UUID for
// testing addon lifecycle methods.
func newTestClientConn() *mitmproxy.ClientConn {
	return &mitmproxy.ClientConn{
		Id:   uuid.NewV4(),
		Conn: &net.TCPConn{},
	}
}

// newTestConnContext creates a ConnContext with the given ClientConn and a
// ServerConn whose Address is set to addr. The ConnContext fields that
// require an internal proxy reference are left nil because the addon
// lifecycle methods only read ClientConn and ServerConn.
func newTestConnContext(client *mitmproxy.ClientConn, addr string) *mitmproxy.ConnContext {
	return &mitmproxy.ConnContext{
		ClientConn: client,
		ServerConn: &mitmproxy.ServerConn{
			Id:      uuid.NewV4(),
			Address: addr,
		},
	}
}

func TestSluiceAddon_ClientConnectedCreatesState(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)

	cs := addon.getConnState(client.Id)
	if cs == nil {
		t.Fatal("expected connState after ClientConnected, got nil")
	}
	if cs.connectHost != "" {
		t.Fatalf("connectHost = %q, want empty before ServerConnected", cs.connectHost)
	}
	if cs.connectPort != 0 {
		t.Fatalf("connectPort = %d, want 0 before ServerConnected", cs.connectPort)
	}
	if cs.checker != nil {
		t.Fatal("checker should be nil initially")
	}
	if cs.skipCheck {
		t.Fatal("skipCheck should be false initially")
	}
}

func TestSluiceAddon_ClientDisconnectedCleansUp(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)
	addon.ClientDisconnected(client)

	cs := addon.getConnState(client.Id)
	if cs != nil {
		t.Fatal("expected nil connState after ClientDisconnected")
	}
}

func TestSluiceAddon_ServerConnectedCapturesTarget(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)
	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	cs := addon.getConnState(client.Id)
	if cs == nil {
		t.Fatal("connState is nil after ServerConnected")
	}
	if cs.connectHost != "api.example.com" {
		t.Fatalf("connectHost = %q, want %q", cs.connectHost, "api.example.com")
	}
	if cs.connectPort != 443 {
		t.Fatalf("connectPort = %d, want 443", cs.connectPort)
	}
}

func TestSluiceAddon_TlsEstablishedServerCapturesTarget(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)
	ctx := newTestConnContext(client, "secure.example.com:8443")
	addon.TlsEstablishedServer(ctx)

	cs := addon.getConnState(client.Id)
	if cs == nil {
		t.Fatal("connState is nil after TlsEstablishedServer")
	}
	if cs.connectHost != "secure.example.com" {
		t.Fatalf("connectHost = %q, want %q", cs.connectHost, "secure.example.com")
	}
	if cs.connectPort != 8443 {
		t.Fatalf("connectPort = %d, want 8443", cs.connectPort)
	}
}

func TestSluiceAddon_TlsEstablishedServerOverridesServerConnected(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)

	// ServerConnected with initial address.
	ctx := newTestConnContext(client, "192.168.1.1:443")
	addon.ServerConnected(ctx)

	// TlsEstablishedServer refines the address (e.g. SNI resolution).
	ctx.ServerConn.Address = "api.example.com:443"
	addon.TlsEstablishedServer(ctx)

	cs := addon.getConnState(client.Id)
	if cs.connectHost != "api.example.com" {
		t.Fatalf("connectHost = %q, want %q (TLS should override)", cs.connectHost, "api.example.com")
	}
}

func TestSluiceAddon_ServerConnectedNilServerConn(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)
	ctx := &mitmproxy.ConnContext{
		ClientConn: client,
		ServerConn: nil,
	}
	// Should not panic.
	addon.ServerConnected(ctx)

	cs := addon.getConnState(client.Id)
	if cs.connectHost != "" {
		t.Fatalf("connectHost = %q, want empty when ServerConn is nil", cs.connectHost)
	}
}

func TestSluiceAddon_ServerConnectedEmptyAddress(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)
	ctx := newTestConnContext(client, "")
	addon.ServerConnected(ctx)

	cs := addon.getConnState(client.Id)
	if cs.connectHost != "" {
		t.Fatalf("connectHost = %q, want empty for empty address", cs.connectHost)
	}
}

func TestSluiceAddon_SetConnChecker(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)

	checker := &RequestPolicyChecker{}
	addon.SetConnChecker(client.Id, checker)

	cs := addon.getConnState(client.Id)
	if cs.checker != checker {
		t.Fatal("checker was not set on connState")
	}
}

func TestSluiceAddon_SetConnSkipCheck(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()

	addon.ClientConnected(client)
	addon.SetConnSkipCheck(client.Id)

	cs := addon.getConnState(client.Id)
	if !cs.skipCheck {
		t.Fatal("skipCheck was not set on connState")
	}
}

func TestSluiceAddon_MultipleClientsIsolated(t *testing.T) {
	addon := NewSluiceAddon()
	client1 := newTestClientConn()
	client2 := newTestClientConn()

	addon.ClientConnected(client1)
	addon.ClientConnected(client2)

	ctx1 := newTestConnContext(client1, "alpha.example.com:443")
	ctx2 := newTestConnContext(client2, "beta.example.com:8080")
	addon.ServerConnected(ctx1)
	addon.ServerConnected(ctx2)

	cs1 := addon.getConnState(client1.Id)
	cs2 := addon.getConnState(client2.Id)
	if cs1.connectHost != "alpha.example.com" {
		t.Fatalf("client1 connectHost = %q, want %q", cs1.connectHost, "alpha.example.com")
	}
	if cs2.connectHost != "beta.example.com" {
		t.Fatalf("client2 connectHost = %q, want %q", cs2.connectHost, "beta.example.com")
	}
	if cs1.connectPort != 443 {
		t.Fatalf("client1 connectPort = %d, want 443", cs1.connectPort)
	}
	if cs2.connectPort != 8080 {
		t.Fatalf("client2 connectPort = %d, want 8080", cs2.connectPort)
	}

	// Disconnect client1, client2 should be unaffected.
	addon.ClientDisconnected(client1)
	if addon.getConnState(client1.Id) != nil {
		t.Fatal("client1 state should be cleaned up")
	}
	if addon.getConnState(client2.Id) == nil {
		t.Fatal("client2 state should still exist")
	}
}

func TestSluiceAddon_SetConnCheckerNoState(_ *testing.T) {
	addon := NewSluiceAddon()
	// Should not panic when setting checker for unknown client.
	addon.SetConnChecker(uuid.NewV4(), &RequestPolicyChecker{})
}

func TestSluiceAddon_SetConnSkipCheckNoState(_ *testing.T) {
	addon := NewSluiceAddon()
	// Should not panic when setting skip-check for unknown client.
	addon.SetConnSkipCheck(uuid.NewV4())
}

// --- Requestheaders tests ---

// newTestFlow creates a Flow with a minimal Request and ConnContext pointing
// at the given client connection. The request URL is set to reqURL (parsed).
func newTestFlow(client *mitmproxy.ClientConn, method, reqURL string) *mitmproxy.Flow {
	u, _ := url.Parse(reqURL)
	return &mitmproxy.Flow{
		Id: uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{
			ClientConn: client,
		},
		Request: &mitmproxy.Request{
			Method: method,
			URL:    u,
			Header: make(http.Header),
		},
	}
}

// buildEnginePtr loads a policy engine from TOML and returns an atomic
// pointer to it.
func buildEnginePtr(t *testing.T, toml string) *atomic.Pointer[policy.Engine] {
	t.Helper()
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("failed to build engine from TOML: %v", err)
	}
	eng.TimeoutSec = 2
	ptr := &atomic.Pointer[policy.Engine]{}
	ptr.Store(eng)
	return ptr
}

// denyAllTOML is a policy TOML that denies all destinations.
const denyAllTOML = `
[policy]
default = "deny"

[[deny]]
destination = "*"
`

// allowAllTOML is a policy TOML that allows all destinations.
const allowAllTOML = `
[policy]
default = "allow"

[[allow]]
destination = "*"
`

// askAllTOML is a policy TOML where all destinations match an ask rule.
const askAllTOML = `
[policy]
default = "deny"

[[ask]]
destination = "*"
`

func TestRequestheaders_DenyReturns403(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	// Attach a checker with a deny-all engine and no broker.
	engPtr := buildEnginePtr(t, denyAllTOML)
	checker := NewRequestPolicyChecker(engPtr, nil)
	addon.SetConnChecker(client.Id, checker)

	f := newTestFlow(client, "GET", "https://api.example.com/users")

	addon.Requestheaders(f)

	if f.Response == nil {
		t.Fatal("expected 403 response, got nil")
	}
	if f.Response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", f.Response.StatusCode)
	}
}

func TestRequestheaders_SkipCheckAllowsFast(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	// Mark as skipCheck (explicit allow rule matched at connection level).
	addon.SetConnSkipCheck(client.Id)

	f := newTestFlow(client, "GET", "https://api.example.com/users")

	addon.Requestheaders(f)

	if f.Response != nil {
		t.Fatalf("expected nil response (fast path), got status %d", f.Response.StatusCode)
	}
}

func TestRequestheaders_NilCheckerPassesThrough(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	// No checker, not skipCheck. Connection resolved without needing
	// per-request checks.
	f := newTestFlow(client, "POST", "https://api.example.com/data")

	addon.Requestheaders(f)

	if f.Response != nil {
		t.Fatalf("expected nil response when checker is nil, got status %d", f.Response.StatusCode)
	}
}

func TestRequestheaders_AllowVerdictPassesThrough(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	// Checker with an allow-all engine.
	engPtr := buildEnginePtr(t, allowAllTOML)
	checker := NewRequestPolicyChecker(engPtr, nil)
	addon.SetConnChecker(client.Id, checker)

	f := newTestFlow(client, "GET", "https://api.example.com/users")

	addon.Requestheaders(f)

	if f.Response != nil {
		t.Fatalf("expected nil response for allowed request, got status %d", f.Response.StatusCode)
	}
}

func TestRequestheaders_SeedCreditAllowsThenDenies(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	// Ask engine with a seeded checker (1 prepaid credit, no broker -> ask
	// resolves to deny after seed exhausted).
	engPtr := buildEnginePtr(t, askAllTOML)
	checker := NewRequestPolicyChecker(engPtr, nil, WithSeedCredits(1))
	addon.SetConnChecker(client.Id, checker)

	// First request: seed credit consumed -> allowed.
	f1 := newTestFlow(client, "GET", "https://api.example.com/users")
	addon.Requestheaders(f1)
	if f1.Response != nil {
		t.Fatalf("first request should be allowed (seed credit), got status %d", f1.Response.StatusCode)
	}

	// Second request: seed exhausted, no broker -> ask resolves to deny.
	f2 := newTestFlow(client, "GET", "https://api.example.com/users")
	addon.Requestheaders(f2)
	if f2.Response == nil {
		t.Fatal("second request should be denied (seed exhausted, no broker)")
	}
	if f2.Response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", f2.Response.StatusCode)
	}
}

func TestRequestheaders_CrossOriginNormalized(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)

	// skipCheck so we only test normalization, not policy.
	addon.SetConnSkipCheck(client.Id)

	// Inner request targets a different host than the CONNECT target.
	f := newTestFlow(client, "GET", "https://evil.com/steal")
	f.Request.Header.Set("Host", "evil.com")

	addon.Requestheaders(f)

	if f.Response != nil {
		t.Fatalf("expected nil response (skipCheck), got status %d", f.Response.StatusCode)
	}
	// URL host should be normalized to the CONNECT target.
	if f.Request.URL.Host != "api.example.com" {
		t.Fatalf("URL.Host = %q, want %q", f.Request.URL.Host, "api.example.com")
	}
	if f.Request.Header.Get("Host") != "api.example.com" {
		t.Fatalf("Host header = %q, want %q", f.Request.Header.Get("Host"), "api.example.com")
	}
}

func TestRequestheaders_CrossOriginNormalizedNonStandardPort(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:8443")
	addon.ServerConnected(ctx)
	addon.SetConnSkipCheck(client.Id)

	// Inner request with different host on a non-standard port.
	f := newTestFlow(client, "GET", "https://other.com:8443/path")
	f.Request.Header.Set("Host", "other.com:8443")

	addon.Requestheaders(f)

	if f.Request.URL.Host != "api.example.com:8443" {
		t.Fatalf("URL.Host = %q, want %q", f.Request.URL.Host, "api.example.com:8443")
	}
}

func TestRequestheaders_CrossOriginIPv6(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	// IPv6 CONNECT target on standard port.
	ctx := newTestConnContext(client, "[::1]:443")
	addon.ServerConnected(ctx)
	addon.SetConnSkipCheck(client.Id)

	f := newTestFlow(client, "GET", "https://evil.com/steal")
	f.Request.Header.Set("Host", "evil.com")

	addon.Requestheaders(f)

	// Standard port should omit port, but IPv6 needs brackets.
	if f.Request.URL.Host != "[::1]" {
		t.Fatalf("URL.Host = %q, want %q", f.Request.URL.Host, "[::1]")
	}
}

func TestRequestheaders_SameOriginNotModified(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)
	addon.SetConnSkipCheck(client.Id)

	// Inner request matches CONNECT target.
	f := newTestFlow(client, "GET", "https://api.example.com/users")
	f.Request.Header.Set("Host", "api.example.com")

	addon.Requestheaders(f)

	if f.Request.URL.Host != "api.example.com" {
		t.Fatalf("URL.Host = %q, want %q (should be unchanged)", f.Request.URL.Host, "api.example.com")
	}
}

func TestRequestheaders_SchemeNormalized(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	// CONNECT on port 443 (HTTPS).
	ctx := newTestConnContext(client, "api.example.com:443")
	addon.ServerConnected(ctx)
	addon.SetConnSkipCheck(client.Id)

	// Inner request claims http scheme on a 443 tunnel.
	f := newTestFlow(client, "GET", "http://api.example.com/users")

	addon.Requestheaders(f)

	if f.Request.URL.Scheme != "https" {
		t.Fatalf("scheme = %q, want %q", f.Request.URL.Scheme, "https")
	}
}

// --- Credential injection tests ---

// addonTestProvider is a minimal vault.Provider for addon tests.
// Reuses the same pattern as testProvider in ws_test.go but keeps
// addon tests self-contained.
type addonTestProvider struct {
	creds map[string]string
}

func (p *addonTestProvider) Get(name string) (vault.SecureBytes, error) {
	if v, ok := p.creds[name]; ok {
		return vault.NewSecureBytes(v), nil
	}
	return vault.SecureBytes{}, fmt.Errorf("credential %q not found", name)
}

func (p *addonTestProvider) List() ([]string, error) {
	names := make([]string, 0, len(p.creds))
	for k := range p.creds {
		names = append(names, k)
	}
	return names, nil
}

func (p *addonTestProvider) Name() string { return "addon-test" }

// newTestAddonWithCreds creates a SluiceAddon wired with a vault provider
// and binding resolver for credential injection tests.
func newTestAddonWithCreds(t *testing.T, creds map[string]string, bindings []vault.Binding) *SluiceAddon {
	t.Helper()
	provider := &addonTestProvider{creds: creds}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)
	return NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
}

// setupAddonConn connects a client, sets the server address, and
// optionally marks skipCheck. Returns the client for use in test flows.
func setupAddonConn(addon *SluiceAddon, addr string) *mitmproxy.ClientConn {
	client := newTestClientConn()
	addon.ClientConnected(client)
	ctx := newTestConnContext(client, addr)
	addon.ServerConnected(ctx)
	addon.SetConnSkipCheck(client.Id)
	return client
}

func TestRequest_PhantomSwapInBody(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"api_key": "real-secret-value"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "api_key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	f.Request.Body = []byte(`{"token":"SLUICE_PHANTOM:api_key"}`)

	addon.Requestheaders(f)
	addon.Request(f)

	want := `{"token":"real-secret-value"}`
	if string(f.Request.Body) != want {
		t.Fatalf("body = %q, want %q", string(f.Request.Body), want)
	}
}

func TestRequest_PhantomSwapInHeaders(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"api_key": "real-secret-value"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "api_key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "GET", "https://api.example.com/data")
	f.Request.Header.Set("X-Token", "SLUICE_PHANTOM:api_key")

	addon.Requestheaders(f)
	addon.Request(f)

	got := f.Request.Header.Get("X-Token")
	if got != "real-secret-value" {
		t.Fatalf("X-Token header = %q, want %q", got, "real-secret-value")
	}
}

func TestRequest_HeaderInjection(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"github_token": "ghp_realtoken123"},
		[]vault.Binding{{
			Destination: "api.github.com",
			Ports:       []int{443},
			Credential:  "github_token",
			Header:      "Authorization",
			Template:    "Bearer {value}",
		}},
	)
	client := setupAddonConn(addon, "api.github.com:443")

	f := newTestFlow(client, "GET", "https://api.github.com/repos")

	addon.Requestheaders(f)

	got := f.Request.Header.Get("Authorization")
	want := "Bearer ghp_realtoken123"
	if got != want {
		t.Fatalf("Authorization header = %q, want %q", got, want)
	}
}

func TestRequest_HeaderInjectionNoTemplate(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"raw_key": "secret123"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "raw_key",
			Header:      "X-API-Key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "GET", "https://api.example.com/data")

	addon.Requestheaders(f)

	got := f.Request.Header.Get("X-API-Key")
	if got != "secret123" {
		t.Fatalf("X-API-Key = %q, want %q", got, "secret123")
	}
}

func TestRequest_StripUnboundPhantoms(t *testing.T) {
	// Credential "api_key" is bound to example.com. A phantom token for
	// "other_key" is not bound and should be stripped.
	addon := newTestAddonWithCreds(t,
		map[string]string{
			"api_key":   "real-secret",
			"other_key": "other-secret",
		},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "api_key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	f.Request.Body = []byte(`key=SLUICE_PHANTOM:api_key&unbound=SLUICE_PHANTOM:other_key`)

	addon.Requestheaders(f)
	addon.Request(f)

	body := string(f.Request.Body)
	if !strings.Contains(body, "real-secret") {
		t.Fatalf("expected bound phantom to be replaced, got %q", body)
	}
	if strings.Contains(body, "SLUICE_PHANTOM:") {
		t.Fatalf("expected unbound phantom to be stripped, got %q", body)
	}
	if strings.Contains(body, "other-secret") {
		t.Fatalf("unbound phantom should not be replaced with real credential, got %q", body)
	}
}

func TestRequest_NoBindingNoChange(t *testing.T) {
	// No bindings configured. Body without phantom tokens should pass
	// through unchanged.
	addon := newTestAddonWithCreds(t,
		map[string]string{"api_key": "secret"},
		nil,
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	original := `{"data":"hello"}`
	f.Request.Body = []byte(original)

	addon.Requestheaders(f)
	addon.Request(f)

	if string(f.Request.Body) != original {
		t.Fatalf("body should be unchanged, got %q", string(f.Request.Body))
	}
}

func TestRequest_PhantomSwapInURL(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"api_key": "real-secret"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "api_key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "GET", "https://api.example.com/data?token=SLUICE_PHANTOM:api_key")

	addon.Requestheaders(f)
	addon.Request(f)

	if strings.Contains(f.Request.URL.RawQuery, "SLUICE_PHANTOM:") {
		t.Fatalf("phantom token should be replaced in URL query, got %q", f.Request.URL.RawQuery)
	}
	if !strings.Contains(f.Request.URL.RawQuery, "real-secret") {
		t.Fatalf("expected real secret in URL query, got %q", f.Request.URL.RawQuery)
	}
}

func TestRequest_NilResolverNoOp(t *testing.T) {
	// SluiceAddon without resolver/provider should not panic.
	addon := NewSluiceAddon()
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	f.Request.Body = []byte(`SLUICE_PHANTOM:api_key`)

	addon.Requestheaders(f)
	addon.Request(f)

	// Body should be unchanged since no provider is configured.
	if string(f.Request.Body) != "SLUICE_PHANTOM:api_key" {
		t.Fatalf("body should be unchanged without resolver, got %q", string(f.Request.Body))
	}
}

func TestStreamRequestModifier_PhantomSwap(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"api_key": "real-secret-value"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "api_key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	body := `{"token":"SLUICE_PHANTOM:api_key","data":"hello"}`
	reader := addon.StreamRequestModifier(f, strings.NewReader(body))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	want := `{"token":"real-secret-value","data":"hello"}`
	if string(out) != want {
		t.Fatalf("streamed body = %q, want %q", string(out), want)
	}
}

func TestStreamRequestModifier_NilResolverPassthrough(t *testing.T) {
	addon := NewSluiceAddon()
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	original := "no phantoms here"
	reader := addon.StreamRequestModifier(f, strings.NewReader(original))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(out) != original {
		t.Fatalf("output = %q, want %q", string(out), original)
	}
}

func TestStreamRequestModifier_LargeBodySpanningReads(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{"api_key": "REPLACED"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "api_key",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	// Build a large body where the phantom token is placed in the middle
	// so it may span a read boundary.
	prefix := bytes.Repeat([]byte("A"), 16*1024)
	phantom := []byte("SLUICE_PHANTOM:api_key")
	suffix := bytes.Repeat([]byte("B"), 16*1024)
	body := make([]byte, 0, len(prefix)+len(phantom)+len(suffix))
	body = append(body, prefix...)
	body = append(body, phantom...)
	body = append(body, suffix...)

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	reader := addon.StreamRequestModifier(f, bytes.NewReader(body))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if bytes.Contains(out, []byte("SLUICE_PHANTOM:")) {
		t.Fatal("phantom token should be replaced in streamed output")
	}
	if !bytes.Contains(out, []byte("REPLACED")) {
		t.Fatal("expected real credential in streamed output")
	}
}

func TestStreamRequestModifier_StripUnbound(t *testing.T) {
	addon := newTestAddonWithCreds(t,
		map[string]string{
			"bound":   "real-secret",
			"unbound": "not-for-you",
		},
		[]vault.Binding{{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "bound",
		}},
	)
	client := setupAddonConn(addon, "api.example.com:443")

	f := newTestFlow(client, "POST", "https://api.example.com/data")
	body := "a=SLUICE_PHANTOM:bound&b=SLUICE_PHANTOM:unbound"
	reader := addon.StreamRequestModifier(f, strings.NewReader(body))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Contains(out, []byte("real-secret")) {
		t.Fatalf("expected bound phantom replaced, got %q", string(out))
	}
	if bytes.Contains(out, []byte("SLUICE_PHANTOM:")) {
		t.Fatalf("expected unbound phantom stripped, got %q", string(out))
	}
	if bytes.Contains(out, []byte("not-for-you")) {
		t.Fatalf("unbound cred should not leak, got %q", string(out))
	}
}

func TestFormatAuthority(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 443, "example.com"},
		{"example.com", 80, "example.com"},
		{"example.com", 8443, "example.com:8443"},
		{"::1", 443, "[::1]"},
		{"::1", 8080, "[::1]:8080"},
		{"127.0.0.1", 443, "127.0.0.1"},
		{"127.0.0.1", 9090, "127.0.0.1:9090"},
	}
	for _, tt := range tests {
		got := formatAuthority(tt.host, tt.port)
		if got != tt.want {
			t.Errorf("formatAuthority(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
		}
	}
}

// --- OAuth response interception tests ---

// addonWritableProvider extends addonTestProvider with Add support for
// OAuth vault persistence tests.
type addonWritableProvider struct {
	mu    sync.Mutex
	creds map[string]string
}

func (p *addonWritableProvider) Get(name string) (vault.SecureBytes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.creds[name]; ok {
		return vault.NewSecureBytes(v), nil
	}
	return vault.SecureBytes{}, fmt.Errorf("credential %q not found", name)
}

func (p *addonWritableProvider) List() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.creds))
	for k := range p.creds {
		names = append(names, k)
	}
	return names, nil
}

func (p *addonWritableProvider) Name() string { return "addon-writable-test" }

func (p *addonWritableProvider) Add(name, value string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creds[name] = value
	return []byte(value), nil
}

// newTestResponseFlow creates a Flow with both a Request and Response for
// OAuth response interception tests.
func newTestResponseFlow(client *mitmproxy.ClientConn, reqURL string, statusCode int, respBody []byte, contentType string) *mitmproxy.Flow {
	u, _ := url.Parse(reqURL)
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &mitmproxy.Flow{
		Id: uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{
			ClientConn: client,
		},
		Request: &mitmproxy.Request{
			Method: "POST",
			URL:    u,
			Header: make(http.Header),
		},
		Response: &mitmproxy.Response{
			StatusCode: statusCode,
			Header:     header,
			Body:       respBody,
		},
	}
}

// setupOAuthAddon creates a SluiceAddon with OAuth response interception
// configured. Returns the addon and the writable provider for vault
// verification.
func setupOAuthAddon(t *testing.T, credName string, oauthCred *vault.OAuthCredential) (*SluiceAddon, *addonWritableProvider) {
	t.Helper()

	data, err := oauthCred.Marshal()
	if err != nil {
		t.Fatalf("marshal oauth credential: %v", err)
	}

	provider := &addonWritableProvider{
		creds: map[string]string{credName: string(data)},
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(
		WithResolver(&resolverPtr),
		WithProvider(provider),
	)
	addon.persistDone = make(chan struct{}, 10)

	metas := []store.CredentialMeta{
		{Name: credName, CredType: "oauth", TokenURL: testOAuthTokenURL},
	}
	addon.UpdateOAuthIndex(metas)

	return addon, provider
}

// waitAddonPersist waits for the async persist goroutine to complete.
func waitAddonPersist(t *testing.T, addon *SluiceAddon) {
	t.Helper()
	select {
	case <-addon.persistDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for addon persist goroutine")
	}
}

func TestAddonResponse_OAuthPhantomSwapJSON(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenURL:     testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "test_oauth", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token":  "new-real-access-token-12345",
		"refresh_token": "new-real-refresh-token-67890",
		"expires_in":    3600,
		"token_type":    "Bearer",
	})

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, respBody, "application/json")

	addon.Response(f)

	body := string(f.Response.Body)

	// Real tokens must not appear in the response.
	if strings.Contains(body, "new-real-access-token-12345") {
		t.Error("real access token leaked in response body")
	}
	if strings.Contains(body, "new-real-refresh-token-67890") {
		t.Error("real refresh token leaked in response body")
	}

	// Phantom tokens must appear instead.
	accessPhantom := oauthPhantomAccess("test_oauth")
	refreshPhantom := oauthPhantomRefresh("test_oauth")
	if !strings.Contains(body, accessPhantom) {
		t.Errorf("expected access phantom %q in response, got %q", accessPhantom, body)
	}
	if !strings.Contains(body, refreshPhantom) {
		t.Errorf("expected refresh phantom %q in response, got %q", refreshPhantom, body)
	}

	waitAddonPersist(t, addon)
}

func TestAddonResponse_OAuthPhantomSwapFormEncoded(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "form_oauth", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := []byte("access_token=form-real-access&refresh_token=form-real-refresh&expires_in=7200&token_type=bearer")

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, respBody, "application/x-www-form-urlencoded")

	addon.Response(f)

	body := string(f.Response.Body)

	if strings.Contains(body, "form-real-access") {
		t.Error("real access token leaked in form-encoded response")
	}
	if strings.Contains(body, "form-real-refresh") {
		t.Error("real refresh token leaked in form-encoded response")
	}

	accessPhantom := oauthPhantomAccess("form_oauth")
	if !strings.Contains(body, accessPhantom) {
		t.Errorf("expected access phantom in form response, got %q", body)
	}

	waitAddonPersist(t, addon)
}

func TestAddonResponse_Non2xxPassesThrough(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "err_oauth", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	errBody := []byte(`{"error":"invalid_grant"}`)
	f := newTestResponseFlow(client, testOAuthTokenURL, 400, errBody, "application/json")

	addon.Response(f)

	// Response body should be unchanged for non-2xx.
	if string(f.Response.Body) != `{"error":"invalid_grant"}` {
		t.Errorf("non-2xx response body was modified: %q", string(f.Response.Body))
	}
}

func TestAddonResponse_NonMatchingURLPassesThrough(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "nomatch_oauth", oauthCred)
	client := setupAddonConn(addon, "api.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token": "looks-like-a-token-but-wrong-url",
		"data":         "some response",
	})
	f := newTestResponseFlow(client, "https://api.example.com/data", 200, respBody, "application/json")

	addon.Response(f)

	body := string(f.Response.Body)
	// Should pass through since URL does not match token endpoint.
	if !strings.Contains(body, "looks-like-a-token-but-wrong-url") {
		t.Error("non-matching URL response was modified when it should pass through")
	}
}

func TestAddonResponse_VaultPersistence(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken:  "original-access",
		RefreshToken: "original-refresh",
		TokenURL:     testOAuthTokenURL,
	}

	addon, provider := setupOAuthAddon(t, "persist_oauth", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token":  "updated-access-token",
		"refresh_token": "updated-refresh-token",
		"expires_in":    7200,
		"token_type":    "Bearer",
	})

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, respBody, "application/json")

	addon.Response(f)
	waitAddonPersist(t, addon)

	// Verify vault was updated with new tokens.
	provider.mu.Lock()
	stored := provider.creds["persist_oauth"]
	provider.mu.Unlock()

	cred, err := vault.ParseOAuth([]byte(stored))
	if err != nil {
		t.Fatalf("parse stored credential: %v", err)
	}
	if cred.AccessToken != "updated-access-token" {
		t.Errorf("vault access_token = %q, want %q", cred.AccessToken, "updated-access-token")
	}
	if cred.RefreshToken != "updated-refresh-token" {
		t.Errorf("vault refresh_token = %q, want %q", cred.RefreshToken, "updated-refresh-token")
	}
	if cred.ExpiresAt.IsZero() {
		t.Error("vault expires_at should be set")
	}
	if cred.TokenURL != testOAuthTokenURL {
		t.Errorf("vault token_url = %q, want %q", cred.TokenURL, testOAuthTokenURL)
	}
}

func TestAddonResponse_OnOAuthRefreshCallback(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "cb_oauth", oauthCred)

	var callbackCred string
	var callbackMu sync.Mutex
	addon.onOAuthRefresh = func(credName string) {
		callbackMu.Lock()
		callbackCred = credName
		callbackMu.Unlock()
	}

	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token": "new-access",
		"token_type":   "Bearer",
	})

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, respBody, "application/json")

	addon.Response(f)
	waitAddonPersist(t, addon)

	callbackMu.Lock()
	got := callbackCred
	callbackMu.Unlock()

	if got != "cb_oauth" {
		t.Errorf("onOAuthRefresh callback received %q, want %q", got, "cb_oauth")
	}
}

func TestAddonResponse_NilResponseNoOp(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "nil_resp", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	f := newTestFlow(client, "POST", testOAuthTokenURL)
	f.Response = nil

	// Should not panic.
	addon.Response(f)
}

func TestAddonResponse_EmptyBodyNoOp(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "empty_body", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, nil, "application/json")

	// Should not panic.
	addon.Response(f)

	if len(f.Response.Body) != 0 {
		t.Errorf("expected empty body, got %q", f.Response.Body)
	}
}

func TestAddonStreamResponseModifier_OAuthSwap(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "stream_oauth", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token":  "stream-real-access",
		"refresh_token": "stream-real-refresh",
		"expires_in":    3600,
	})

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, nil, "application/json")
	reader := addon.StreamResponseModifier(f, bytes.NewReader(respBody))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	body := string(out)

	if strings.Contains(body, "stream-real-access") {
		t.Error("real access token leaked in streamed response")
	}
	if strings.Contains(body, "stream-real-refresh") {
		t.Error("real refresh token leaked in streamed response")
	}

	accessPhantom := oauthPhantomAccess("stream_oauth")
	if !strings.Contains(body, accessPhantom) {
		t.Errorf("expected access phantom in streamed response, got %q", body)
	}

	waitAddonPersist(t, addon)
}

func TestAddonStreamResponseModifier_NonMatchingPassthrough(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "stream_nomatch", oauthCred)
	client := setupAddonConn(addon, "api.example.com:443")

	original := []byte(`{"data":"hello"}`)
	f := newTestResponseFlow(client, "https://api.example.com/other", 200, nil, "application/json")
	reader := addon.StreamResponseModifier(f, bytes.NewReader(original))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(out) != string(original) {
		t.Errorf("non-matching URL streamed output = %q, want %q", string(out), string(original))
	}
}

func TestAddonStreamResponseModifier_Non2xxPassthrough(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "stream_err", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	original := []byte(`{"error":"invalid_grant"}`)
	f := newTestResponseFlow(client, testOAuthTokenURL, 401, nil, "application/json")
	reader := addon.StreamResponseModifier(f, bytes.NewReader(original))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(out) != string(original) {
		t.Errorf("non-2xx streamed output = %q, want %q", string(out), string(original))
	}
}

func TestAddonResponse_ContentLengthUpdated(t *testing.T) {
	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    testOAuthTokenURL,
	}

	addon, _ := setupOAuthAddon(t, "cl_oauth", oauthCred)
	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token": "real-token-value",
		"token_type":   "Bearer",
	})

	f := newTestResponseFlow(client, testOAuthTokenURL, 200, respBody, "application/json")
	f.Response.Header.Set("Content-Length", fmt.Sprintf("%d", len(respBody)))

	addon.Response(f)

	// Content-Length should match the modified body length.
	cl := f.Response.Header.Get("Content-Length")
	want := fmt.Sprintf("%d", len(f.Response.Body))
	if cl != want {
		t.Errorf("Content-Length = %q, want %q", cl, want)
	}

	waitAddonPersist(t, addon)
}

func TestAddonResponse_NilOAuthIndexNoOp(t *testing.T) {
	// No OAuth index configured. Response should pass through.
	addon := NewSluiceAddon()
	client := setupAddonConn(addon, "auth.example.com:443")

	respBody := mustJSON(t, map[string]interface{}{
		"access_token": "some-token",
	})
	f := newTestResponseFlow(client, "https://auth.example.com/oauth/token", 200, respBody, "application/json")
	original := string(f.Response.Body)

	addon.Response(f)

	if string(f.Response.Body) != original {
		t.Error("response body was modified when no OAuthIndex is configured")
	}
}

// mustJSON marshals v to JSON bytes, failing the test on error.
func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func TestSluiceAddon_CancelPendingChecker(t *testing.T) {
	addon := NewSluiceAddon()
	dest := "api.example.com:443"

	// Push a checker, then cancel it.
	checker := &RequestPolicyChecker{}
	addon.PendingChecker(dest, checker, false)
	addon.CancelPendingChecker(dest)

	// Consume should return nil because the entry was cancelled.
	if pc := addon.consumePendingChecker(dest); pc != nil {
		t.Fatal("expected nil after CancelPendingChecker, got non-nil pending check")
	}
}

func TestSluiceAddon_CancelPendingCheckerLeavesOlderEntries(t *testing.T) {
	addon := NewSluiceAddon()
	dest := "api.example.com:443"

	// Push two entries.
	first := &RequestPolicyChecker{}
	second := &RequestPolicyChecker{}
	addon.PendingChecker(dest, first, false)
	addon.PendingChecker(dest, second, true)

	// Cancel removes the most recent (second).
	addon.CancelPendingChecker(dest)

	// Consuming should return the first entry.
	pc := addon.consumePendingChecker(dest)
	if pc == nil {
		t.Fatal("expected first pending check to remain after cancelling second")
	}
	if pc.checker != first {
		t.Fatal("consumed checker is not the first entry")
	}
	if pc.skip {
		t.Fatal("first entry should have skip=false")
	}
}

func TestSluiceAddon_CancelPendingCheckerNoop(_ *testing.T) {
	addon := NewSluiceAddon()

	// Cancel on empty map should not panic.
	addon.CancelPendingChecker("nonexistent:443")
}

func TestSluiceAddon_CancelPendingCheckerNotConsumedByServerConnected(t *testing.T) {
	addon := NewSluiceAddon()
	client := newTestClientConn()
	addon.ClientConnected(client)

	dest := "api.example.com:443"
	checker := &RequestPolicyChecker{}
	addon.PendingChecker(dest, checker, false)
	addon.CancelPendingChecker(dest)

	// Simulate ServerConnected. The cancelled checker should not appear
	// on the connection state.
	ctx := newTestConnContext(client, dest)
	addon.ServerConnected(ctx)

	cs := addon.getConnState(client.Id)
	if cs == nil {
		t.Fatal("expected connState after ServerConnected")
	}
	if cs.checker != nil {
		t.Fatal("cancelled checker should not be attached to connection state")
	}
	if cs.skipCheck {
		t.Fatal("skipCheck should be false when no pending checker was consumed")
	}
}
