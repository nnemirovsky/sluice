package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/sync/singleflight"
)

// maxCredNameLen is an upper bound for credential name length. Used by
// maxPhantomLen to size the holdback buffer for boundary-spanning phantom
// tokens in streaming replacement.
const maxCredNameLen = 64

// connState tracks per-connection state for the go-mitmproxy addon. Each
// client connection gets a connState entry in the SluiceAddon's sync.Map,
// keyed by the ClientConn.Id (UUID). The state carries the authoritative
// CONNECT target (host and port) captured from the ServerConn.Address when
// the upstream connection is established, an optional per-request policy
// checker, and a skipCheck flag for explicit-allow fast paths.
//
// The connectHost is the authoritative destination for all policy and
// credential-binding decisions on MITM'd requests. It is captured from the
// CONNECT target before any inner HTTP request is read, so a malicious
// client cannot spoof a different destination via the Host header.
type connState struct {
	// connectHost is the hostname from the CONNECT target (e.g.
	// "api.example.com"). Empty until ServerConnected fires.
	connectHost string

	// connectPort is the port from the CONNECT target (e.g. 443).
	// Zero until ServerConnected fires.
	connectPort int

	// checker performs per-HTTP-request policy evaluation. Nil when the
	// connection matched an explicit allow rule (skipCheck is true) or
	// when the connection-level policy resolved to allow without an ask
	// flow.
	checker *RequestPolicyChecker

	// skipCheck is true when the SOCKS5/SNI layer matched an explicit
	// allow rule and per-request policy evaluation should be skipped
	// entirely. When true, checker is always nil.
	skipCheck bool
}

// SluiceAddon implements the go-mitmproxy Addon interface for per-request
// policy evaluation and credential injection for HTTP/1.1 and HTTP/2
// interception.
//
// Each client connection is tracked in a sync.Map keyed by ClientConn.Id
// (UUID). ServerConnected / TlsEstablishedServer populate the CONNECT target
// (host:port). Requestheaders uses the CONNECT target for per-request policy
// checks. Request performs credential injection (phantom token swap).
// ClientDisconnected cleans up the state.
//
// Thread-safety: the sync.Map is safe for concurrent access. Individual
// connState values are written only during connection setup (before any
// request flows) and read-only during request handling, so no additional
// locking is needed.
type SluiceAddon struct {
	mitmproxy.BaseAddon

	// conns maps ClientConn.Id (uuid.UUID) -> *connState.
	conns sync.Map

	// resolver resolves destinations to credential bindings. Swapped
	// atomically on SIGHUP / policy mutation.
	resolver *atomic.Pointer[vault.BindingResolver]

	// provider retrieves real credential values from the vault.
	provider vault.Provider

	// oauthIndex maps OAuth token endpoint URLs to credential names.
	// Used by the Response handler to detect token responses and perform
	// phantom token replacement. Updated atomically via UpdateOAuthIndex.
	oauthIndex atomic.Pointer[OAuthIndex]

	// refreshGroup deduplicates concurrent OAuth token refresh responses
	// for the same credential. Keyed by credential name so only one
	// vault update occurs when multiple requests trigger simultaneous
	// refreshes.
	refreshGroup singleflight.Group

	// onOAuthRefresh is called after an OAuth token refresh persist
	// completes successfully. It receives the credential name so the
	// caller can re-inject updated phantom env vars into the agent
	// container. Nil means no post-refresh action.
	onOAuthRefresh func(credName string)

	// persistDone is an optional channel signaled when an async OAuth
	// token persist goroutine completes. Used by tests to avoid
	// time.Sleep-based synchronization. Nil in production.
	persistDone chan struct{}

	// auditLog, when non-nil, receives per-request deny/inject events.
	auditLog *audit.FileLogger

	// pendingMu protects pendingCheckers.
	pendingMu sync.Mutex

	// pendingCheckers maps "host:port" -> []*pendingCheck (stack). The
	// SOCKS5 dial function pushes a checker before connecting to
	// go-mitmproxy. ServerConnected pops the most recent entry so the
	// correct checker is attached to the connection state. A stack (LIFO)
	// is used instead of a single value because concurrent connections to
	// the same host:port would otherwise overwrite each other.
	pendingCheckers map[string][]*pendingCheck

	// wsProxy handles WebSocket frame-level inspection when non-nil.
	wsProxy *WSProxy
}

// NewSluiceAddon creates a SluiceAddon ready for use with go-mitmproxy.
// Pass nil for resolver/provider to disable credential injection (useful
// in tests that only exercise policy checks).
func NewSluiceAddon(opts ...SluiceAddonOption) *SluiceAddon {
	a := &SluiceAddon{
		pendingCheckers: make(map[string][]*pendingCheck),
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// SluiceAddonOption configures optional SluiceAddon fields.
type SluiceAddonOption func(*SluiceAddon)

// WithResolver sets the binding resolver for credential injection.
func WithResolver(r *atomic.Pointer[vault.BindingResolver]) SluiceAddonOption {
	return func(a *SluiceAddon) { a.resolver = r }
}

// WithProvider sets the vault provider for credential injection.
func WithProvider(p vault.Provider) SluiceAddonOption {
	return func(a *SluiceAddon) { a.provider = p }
}

// WithAuditLogger sets the audit logger for per-request events.
func WithAuditLogger(l *audit.FileLogger) SluiceAddonOption {
	return func(a *SluiceAddon) { a.auditLog = l }
}

// WithWSProxy sets the WebSocket proxy for frame-level inspection.
func WithWSProxy(wp *WSProxy) SluiceAddonOption {
	return func(a *SluiceAddon) { a.wsProxy = wp }
}

// pendingCheck holds a per-request policy checker waiting to be consumed
// by ServerConnected. Created by the SOCKS5 dial function before routing
// a connection through go-mitmproxy. The skip field corresponds to
// ctxKeySkipPerRequest (explicit allow rule matched).
type pendingCheck struct {
	checker *RequestPolicyChecker
	skip    bool
}

// PendingChecker stores a per-request policy checker for a destination so
// that ServerConnected can attach it to the connection state. The dest
// parameter is "host:port" matching the CONNECT target. If skip is true,
// per-request checking is skipped (explicit allow rule). The entry is
// consumed by ServerConnected and should not be stored indefinitely.
//
// Multiple concurrent connections to the same host:port are supported.
// Entries are pushed onto a per-destination stack and popped in LIFO order
// by consumePendingChecker.
func (a *SluiceAddon) PendingChecker(dest string, checker *RequestPolicyChecker, skip bool) {
	a.pendingMu.Lock()
	a.pendingCheckers[dest] = append(a.pendingCheckers[dest], &pendingCheck{checker: checker, skip: skip})
	a.pendingMu.Unlock()
}

// consumePendingChecker retrieves and removes the most recent pending
// checker for the given host:port key. Returns nil if no pending checker
// exists.
func (a *SluiceAddon) consumePendingChecker(dest string) *pendingCheck {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()

	stack := a.pendingCheckers[dest]
	if len(stack) == 0 {
		return nil
	}

	// Pop the last entry (LIFO).
	pc := stack[len(stack)-1]
	if len(stack) == 1 {
		delete(a.pendingCheckers, dest)
	} else {
		a.pendingCheckers[dest] = stack[:len(stack)-1]
	}

	return pc
}

// recoverPortFromPending scans the pending checker map for a key whose
// host part matches the given hostname and returns its port as a string.
// Falls back to "443" if no match is found. This handles the case where
// go-mitmproxy's TlsEstablishedServer provides a host-only address
// without the port from the original SOCKS5 CONNECT.
func (a *SluiceAddon) recoverPortFromPending(host string) string {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	for key := range a.pendingCheckers {
		h, p, err := net.SplitHostPort(key)
		if err == nil && h == host {
			return p
		}
	}
	return "443"
}

// CancelPendingChecker removes the most recent pending checker for the
// given host:port key without consuming it for a connection. This must be
// called when dialThroughMITM fails after PendingChecker was called, so the
// stale entry does not leak to a future connection to the same destination.
func (a *SluiceAddon) CancelPendingChecker(dest string) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()

	stack := a.pendingCheckers[dest]
	if len(stack) == 0 {
		return
	}

	// Pop the last entry (LIFO), same as consumePendingChecker.
	if len(stack) == 1 {
		delete(a.pendingCheckers, dest)
	} else {
		a.pendingCheckers[dest] = stack[:len(stack)-1]
	}
}

// SetOnOAuthRefresh configures the callback invoked after an OAuth token
// refresh is persisted to the vault.
func (a *SluiceAddon) SetOnOAuthRefresh(fn func(credName string)) {
	a.onOAuthRefresh = fn
}

// UpdateOAuthIndex rebuilds the OAuth token URL index from credential
// metadata. Called on startup and after credential metadata changes
// (e.g. SIGHUP hot-reload).
func (a *SluiceAddon) UpdateOAuthIndex(metas []store.CredentialMeta) {
	idx := NewOAuthIndex(metas)
	a.oauthIndex.Store(idx)
	log.Printf("[ADDON-OAUTH] updated token URL index (%d entries)", idx.Len())
}

// ClientConnected initializes per-connection state when a new client connects.
// The state is populated with the CONNECT target later in ServerConnected.
func (a *SluiceAddon) ClientConnected(client *mitmproxy.ClientConn) {
	a.conns.Store(client.Id, &connState{})
	log.Printf("[ADDON] client connected: %s", client.Id)
}

// ClientDisconnected removes per-connection state when a client disconnects.
func (a *SluiceAddon) ClientDisconnected(client *mitmproxy.ClientConn) {
	a.conns.Delete(client.Id)
	log.Printf("[ADDON] client disconnected: %s", client.Id)
}

// ServerConnected captures the CONNECT target (host:port) from the server
// connection address. This is the authoritative destination for policy and
// credential binding decisions. The address comes from the CONNECT request
// that established the tunnel.
func (a *SluiceAddon) ServerConnected(ctx *mitmproxy.ConnContext) {
	a.captureConnectTarget(ctx)
}

// TlsEstablishedServer is called after the TLS handshake with the upstream
// server completes. It re-captures the CONNECT target in case the address
// was refined during the TLS handshake (e.g. via SNI resolution).
func (a *SluiceAddon) TlsEstablishedServer(ctx *mitmproxy.ConnContext) { //nolint:revive // method name defined by go-mitmproxy Addon interface
	a.captureConnectTarget(ctx)
}

// captureConnectTarget parses host:port from the ServerConn.Address and
// stores it in the connection state.
func (a *SluiceAddon) captureConnectTarget(ctx *mitmproxy.ConnContext) {
	if ctx.ServerConn == nil {
		return
	}

	addr := ctx.ServerConn.Address
	if addr == "" {
		return
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Address is host-only without a port (common in
		// TlsEstablishedServer). Recover the port from the pending
		// checker map which was keyed on the exact host:port from
		// the SOCKS5 CONNECT.
		host = addr
		portStr = a.recoverPortFromPending(host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("[ADDON] invalid port in server address %q: %v", addr, err)
		return
	}

	a.storeConnectTarget(ctx.ClientConn.Id, host, port)
}

// storeConnectTarget updates the connState for the given client connection
// with the CONNECT target host and port. Also consumes any pending checker
// registered by the SOCKS5 dial function for this destination.
//
// Ordering dependency: go-mitmproxy guarantees that ClientConnected fires
// before ServerConnected and TlsEstablishedServer on the same connection.
// storeConnectTarget is always called from one of those two callbacks, so
// the connState created in ClientConnected is guaranteed to exist.
func (a *SluiceAddon) storeConnectTarget(clientID uuid.UUID, host string, port int) {
	v, ok := a.conns.Load(clientID)
	if !ok {
		log.Printf("[ADDON] no state for client %s during connect target capture", clientID)
		return
	}
	cs := v.(*connState)
	cs.connectHost = host
	cs.connectPort = port

	// Consume any pending checker for this destination.
	dest := net.JoinHostPort(host, strconv.Itoa(port))
	if pc := a.consumePendingChecker(dest); pc != nil {
		cs.checker = pc.checker
		cs.skipCheck = pc.skip
		if pc.skip {
			log.Printf("[ADDON] captured CONNECT target: %s:%d (client %s, skip-check)", host, port, clientID)
		} else if pc.checker != nil {
			log.Printf("[ADDON] captured CONNECT target: %s:%d (client %s, per-request checker)", host, port, clientID)
		} else {
			log.Printf("[ADDON] captured CONNECT target: %s:%d (client %s)", host, port, clientID)
		}
	} else {
		log.Printf("[ADDON] captured CONNECT target: %s:%d (client %s)", host, port, clientID)
	}
}

// getConnState returns the connState for a client connection, or nil if not
// found.
func (a *SluiceAddon) getConnState(clientID uuid.UUID) *connState {
	v, ok := a.conns.Load(clientID)
	if !ok {
		return nil
	}
	return v.(*connState)
}

// SetConnChecker attaches a per-request policy checker to an existing
// connection state. Testing only. Production code uses PendingChecker /
// consumePendingChecker which are consumed during ServerConnected.
func (a *SluiceAddon) SetConnChecker(clientID uuid.UUID, checker *RequestPolicyChecker) {
	v, ok := a.conns.Load(clientID)
	if !ok {
		log.Printf("[ADDON] no state for client %s when setting checker", clientID)
		return
	}
	cs := v.(*connState)
	cs.checker = checker
}

// SetConnSkipCheck marks a connection as exempt from per-request policy
// checks (explicit allow rule matched at the connection level). Testing
// only. Production code uses PendingChecker with skip=true.
func (a *SluiceAddon) SetConnSkipCheck(clientID uuid.UUID) {
	v, ok := a.conns.Load(clientID)
	if !ok {
		log.Printf("[ADDON] no state for client %s when setting skip-check", clientID)
		return
	}
	cs := v.(*connState)
	cs.skipCheck = true
}

// Requestheaders performs per-request policy evaluation and cross-origin
// normalization on every HTTP request (including each HTTP/2 stream).
//
// Policy check: when the connection has a RequestPolicyChecker (the
// connection-level policy resolved to Ask), CheckAndConsume is called with
// the authoritative CONNECT target, the refined protocol, and the HTTP
// method and path for the approval message. If the verdict is Deny or an
// error occurs, the request is blocked with a 403 response and the upstream
// is never contacted. When skipCheck is true (explicit allow rule at
// connection level), the check is skipped entirely.
//
// Cross-origin normalization: the CONNECT target is the authoritative
// destination. If the inner request's Host header or URL host differs from
// the CONNECT target, the request URL and Host header are rewritten to the
// CONNECT target. This prevents a malicious client from routing requests to
// an unintended destination through an already-approved tunnel.
func (a *SluiceAddon) Requestheaders(f *mitmproxy.Flow) {
	cs := a.getConnState(f.ConnContext.ClientConn.Id)
	if cs == nil {
		log.Printf("[ADDON] no state for client %s in Requestheaders", f.ConnContext.ClientConn.Id)
		return
	}

	connectHost := cs.connectHost
	connectPort := cs.connectPort

	// Cross-origin normalization: rewrite inner request authority to the
	// CONNECT target when the inner Host/URL host diverges. The CONNECT
	// target is the authoritative destination.
	if connectHost != "" {
		a.normalizeRequestAuthority(f, connectHost, connectPort)
	}

	// Skip per-request policy when the connection-level check already
	// resolved to an explicit allow rule.
	if cs.skipCheck {
		a.injectHeaders(f, connectHost, connectPort)
		return
	}

	checker := cs.checker
	if checker == nil {
		// No checker and not skipCheck means the connection resolved
		// without needing per-request checks (e.g. allow without ask).
		a.injectHeaders(f, connectHost, connectPort)
		return
	}

	// Determine the protocol from the request for protocol-scoped rules.
	proto := a.detectRequestProtocol(f, connectPort)
	protoStr := proto.String()

	httpVer := f.Request.Proto
	if httpVer == "" && f.ConnContext.ClientConn.NegotiatedProtocol == "h2" {
		httpVer = "HTTP/2"
	}
	method := f.Request.Method
	if proto == ProtoWS || proto == ProtoWSS {
		method = "UPGRADE"
		httpVer = ""
	}
	verdict, err := checker.CheckAndConsume(connectHost, connectPort,
		WithRequestInfo(method, f.Request.URL.Path),
		WithProtocol(protoStr),
		WithHTTPVersion(httpVer),
		WithSkipBrokerRateLimit(),
	)
	if err != nil {
		log.Printf("[ADDON-DENY] %s:%d per-request policy error: %v", connectHost, connectPort, err)
		f.Response = &mitmproxy.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       []byte(fmt.Sprintf("Forbidden: %v", err)),
		}
		return
	}
	if verdict != policy.Allow {
		log.Printf("[ADDON-DENY] %s:%d blocked by per-request policy", connectHost, connectPort)
		f.Response = &mitmproxy.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       []byte("Forbidden"),
		}
		return
	}

	// Header injection runs after policy allows the request, injecting
	// binding-specific credential headers before the body is read.
	a.injectHeaders(f, connectHost, connectPort)
}

// injectHeaders performs Pass 1 of credential injection: for each binding
// matching connectHost:connectPort, set the configured header (e.g.
// Authorization: Bearer <real_token>). Called from Requestheaders so headers
// are injected before the body is streamed/buffered.
func (a *SluiceAddon) injectHeaders(f *mitmproxy.Flow, host string, port int) {
	if a.resolver == nil || a.provider == nil {
		return
	}
	res := a.resolver.Load()
	if res == nil {
		return
	}

	proto := a.detectRequestProtocol(f, port)
	protoStr := proto.String()

	binding, ok := res.ResolveForProtocol(host, port, protoStr)
	if !ok {
		return
	}
	if binding.Header == "" {
		return
	}

	secret, err := a.provider.Get(binding.Credential)
	if err != nil {
		log.Printf("[ADDON-INJECT] credential %q lookup failed: %v", binding.Credential, err)
		return
	}
	defer secret.Release()

	f.Request.Header.Set(binding.Header, binding.FormatValue(secret.String()))
	log.Printf("[ADDON-INJECT] injected header %q for %s:%d (credential %q)",
		binding.Header, host, port, binding.Credential)
}

// Request performs Pass 2 (scoped phantom replacement) and Pass 3 (strip
// unbound phantoms) on the fully-buffered request body, headers, URL query,
// and URL path. Called by go-mitmproxy after the request body has been read
// into f.Request.Body (non-streaming mode). Header injection (Pass 1) was
// already done in Requestheaders.
func (a *SluiceAddon) Request(f *mitmproxy.Flow) {
	if a.resolver == nil || a.provider == nil {
		return
	}

	cs := a.getConnState(f.ConnContext.ClientConn.Id)
	if cs == nil {
		return
	}
	host := cs.connectHost
	port := cs.connectPort
	if host == "" {
		return
	}

	proto := a.detectRequestProtocol(f, port)
	protoStr := proto.String()

	pairs := a.buildPhantomPairs(host, port, protoStr)
	if len(pairs) == 0 && !a.hasPhantomPrefix(f) {
		return
	}
	defer releasePhantomPairs(pairs)

	// Pass 2+3 on headers.
	a.swapPhantomHeaders(f, pairs, host, port)

	// Pass 2+3 on body.
	if len(f.Request.Body) > 0 {
		f.Request.Body = a.swapPhantomBytes(f.Request.Body, pairs, host, port, "body")
	}

	// Pass 2+3 on URL query.
	if rawQ := f.Request.URL.RawQuery; bytes.Contains([]byte(rawQ), phantomPrefix) {
		f.Request.URL.RawQuery = string(
			a.swapPhantomBytes([]byte(rawQ), pairs, host, port, "URL query"))
	}

	// Pass 2+3 on URL path.
	if rawP := f.Request.URL.Path; bytes.Contains([]byte(rawP), phantomPrefix) {
		f.Request.URL.Path = string(
			a.swapPhantomBytes([]byte(rawP), pairs, host, port, "URL path"))
		f.Request.URL.RawPath = ""
	}
}

// StreamRequestModifier returns an io.Reader wrapper that performs phantom
// token replacement on the streaming request body. Used when f.Stream is
// true and the body is not buffered. go-mitmproxy calls this instead of
// buffering the body into f.Request.Body + calling Request.
func (a *SluiceAddon) StreamRequestModifier(f *mitmproxy.Flow, in io.Reader) io.Reader {
	if a.resolver == nil || a.provider == nil {
		return in
	}

	cs := a.getConnState(f.ConnContext.ClientConn.Id)
	if cs == nil {
		return in
	}
	host := cs.connectHost
	port := cs.connectPort
	if host == "" {
		return in
	}

	proto := a.detectRequestProtocol(f, port)
	protoStr := proto.String()

	pairs := a.buildPhantomPairs(host, port, protoStr)
	if len(pairs) == 0 {
		return in
	}

	return &phantomSwapReader{
		inner:    in,
		pairs:    pairs,
		provider: a.provider,
	}
}

// Response performs OAuth response interception on fully-buffered response
// bodies. When the response comes from a known OAuth token endpoint (matched
// via OAuthIndex), real tokens are replaced with deterministic phantom tokens
// before the response reaches the agent. The real tokens are persisted to
// the vault asynchronously.
func (a *SluiceAddon) Response(f *mitmproxy.Flow) {
	if f.Response == nil || f.Request == nil {
		return
	}

	// Only intercept successful responses.
	if f.Response.StatusCode < 200 || f.Response.StatusCode > 299 {
		return
	}

	idx := a.oauthIndex.Load()
	if idx == nil {
		return
	}

	credName, ok := idx.Match(f.Request.URL)
	if !ok {
		return
	}

	if a.provider == nil {
		return
	}

	modified, err := a.processAddonOAuthResponse(f, credName)
	if err != nil {
		log.Printf("[ADDON-OAUTH] error processing OAuth response for %q: %v", credName, err)
		return
	}
	if modified {
		log.Printf("[ADDON-OAUTH] intercepted token response for credential %q, swapped to phantoms", credName)
	}
}

// StreamResponseModifier returns an io.Reader wrapper for streaming OAuth
// token replacement on response bodies. When the response is from a known
// OAuth token endpoint, the stream is fully buffered (token responses are
// small), tokens are swapped, and the modified body is returned as a reader.
// For non-OAuth responses or when no OAuthIndex is configured, the original
// reader is returned unmodified.
func (a *SluiceAddon) StreamResponseModifier(f *mitmproxy.Flow, in io.Reader) io.Reader {
	if f.Request == nil {
		return in
	}

	if f.Response == nil || f.Response.StatusCode < 200 || f.Response.StatusCode > 299 {
		return in
	}

	idx := a.oauthIndex.Load()
	if idx == nil {
		return in
	}

	credName, ok := idx.Match(f.Request.URL)
	if !ok {
		return in
	}

	if a.provider == nil {
		return in
	}

	// Token responses are small (typically < 1 KiB). Buffer the entire
	// body so we can parse and replace tokens atomically.
	body, err := io.ReadAll(io.LimitReader(in, maxProxyBody+1))
	if err != nil {
		log.Printf("[ADDON-OAUTH] stream body read error for credential %q: %v", credName, err)
		return bytes.NewReader(nil)
	}
	if int64(len(body)) > maxProxyBody {
		log.Printf("[ADDON-OAUTH] stream response body exceeds %d bytes for credential %q, passing through", maxProxyBody, credName)
		return io.MultiReader(bytes.NewReader(body), in)
	}

	contentType := ""
	if f.Response.Header != nil {
		contentType = f.Response.Header.Get("Content-Type")
	}

	modified, err := a.swapOAuthTokens(body, contentType, credName)
	if err != nil {
		log.Printf("[ADDON-OAUTH] stream token parse error for credential %q: %v", credName, err)
		return bytes.NewReader(body)
	}

	return bytes.NewReader(modified)
}

// processAddonOAuthResponse reads the token response body from the flow,
// replaces real tokens with phantoms, updates the flow's response body,
// and schedules an async vault update. Returns true if the body was
// modified.
func (a *SluiceAddon) processAddonOAuthResponse(f *mitmproxy.Flow, credName string) (bool, error) {
	body := f.Response.Body
	if len(body) == 0 {
		return false, nil
	}

	contentType := ""
	if f.Response.Header != nil {
		contentType = f.Response.Header.Get("Content-Type")
	}

	modified, err := a.swapOAuthTokens(body, contentType, credName)
	if err != nil {
		return false, err
	}

	f.Response.Body = modified
	if f.Response.Header != nil {
		f.Response.Header.Set("Content-Length", strconv.Itoa(len(modified)))
		f.Response.Header.Del("Transfer-Encoding")
	}

	return true, nil
}

// swapOAuthTokens parses a token response body, replaces real tokens with
// deterministic phantoms, and schedules an async vault persist. Returns
// the modified body. Shared by Response (buffered) and StreamResponseModifier.
func (a *SluiceAddon) swapOAuthTokens(body []byte, contentType, credName string) ([]byte, error) {
	tr, err := parseTokenResponse(body, contentType)
	if err != nil {
		return nil, err
	}

	accessPhantom := oauthPhantomAccess(credName, tr.AccessToken)
	refreshPhantom := oauthPhantomRefresh(credName, tr.RefreshToken)

	// Replace real tokens with phantoms in the response body.
	// Replace the longer token first to prevent substring corruption when
	// one token is a prefix of the other.
	modified := body
	if tr.RefreshToken != "" {
		if len(tr.RefreshToken) >= len(tr.AccessToken) {
			modified = bytes.ReplaceAll(modified, []byte(tr.RefreshToken), []byte(refreshPhantom))
			modified = bytes.ReplaceAll(modified, []byte(tr.AccessToken), []byte(accessPhantom))
		} else {
			modified = bytes.ReplaceAll(modified, []byte(tr.AccessToken), []byte(accessPhantom))
			modified = bytes.ReplaceAll(modified, []byte(tr.RefreshToken), []byte(refreshPhantom))
		}
	} else {
		modified = bytes.ReplaceAll(modified, []byte(tr.AccessToken), []byte(accessPhantom))
	}

	// Asynchronously persist the new tokens to the vault.
	realAccess := vault.NewSecureBytes(tr.AccessToken)
	realRefresh := vault.NewSecureBytes(tr.RefreshToken)
	expiresIn := tr.ExpiresIn

	go a.persistAddonOAuthTokens(credName, realAccess, realRefresh, expiresIn)

	return modified, nil
}

// persistAddonOAuthTokens updates the vault with new real tokens from a
// token response. Called asynchronously from swapOAuthTokens. Uses
// singleflight to deduplicate concurrent vault writes for the same
// credential.
func (a *SluiceAddon) persistAddonOAuthTokens(credName string, realAccess, realRefresh vault.SecureBytes, expiresIn int) {
	defer realAccess.Release()
	defer realRefresh.Release()
	if a.persistDone != nil {
		defer func() { a.persistDone <- struct{}{} }()
	}

	// Load existing OAuth credential from vault to preserve token_url
	// and other metadata.
	existing, err := a.provider.Get(credName)
	if err != nil {
		log.Printf("[ADDON-OAUTH] vault read failed for credential %q: %v", credName, err)
		return
	}
	defer existing.Release()

	cred, err := vault.ParseOAuth(existing.Bytes())
	if err != nil {
		log.Printf("[ADDON-OAUTH] parse existing oauth credential %q failed: %v", credName, err)
		return
	}

	cred.UpdateTokens(realAccess.String(), realRefresh.String(), expiresIn)

	data, err := cred.Marshal()
	if err != nil {
		log.Printf("[ADDON-OAUTH] marshal updated oauth credential %q failed: %v", credName, err)
		return
	}

	// Use singleflight to deduplicate concurrent vault writes for the same
	// credential. Dedup is safe because the vault write is idempotent and
	// only the latest token values matter.
	_, sfErr, shared := a.refreshGroup.Do("persist:"+credName, func() (interface{}, error) {
		adder := findAdder(a.provider)
		if adder == nil {
			log.Printf("[ADDON-OAUTH] provider does not support Add for credential %q", credName)
			return nil, fmt.Errorf("provider does not support Add")
		}
		if _, err := adder.Add(credName, string(data)); err != nil {
			log.Printf("[ADDON-OAUTH] vault write failed for credential %q: %v", credName, err)
			return nil, err
		}
		return nil, nil
	})

	if sfErr != nil {
		if shared {
			log.Printf("[ADDON-OAUTH] deduplicated persist for credential %q failed: %v", credName, sfErr)
		}
		return
	}

	if shared {
		log.Printf("[ADDON-OAUTH] deduplicated concurrent persist for credential %q", credName)
	} else {
		log.Printf("[ADDON-OAUTH] persisted updated tokens for credential %q", credName)
	}

	// Notify the caller so updated phantom env vars can be re-injected
	// into the agent container.
	if a.onOAuthRefresh != nil {
		a.onOAuthRefresh(credName)
	}
}

// buildPhantomPairs builds the sorted list of phantom/secret pairs for a
// destination. The caller must call releasePhantomPairs when done.
func (a *SluiceAddon) buildPhantomPairs(host string, port int, proto string) []phantomPair {
	res := a.resolver.Load()
	if res == nil {
		return nil
	}
	boundCreds := res.CredentialsForDestination(host, port, proto)
	if len(boundCreds) == 0 {
		return nil
	}

	var pairs []phantomPair
	for _, name := range boundCreds {
		secret, err := a.provider.Get(name)
		if err != nil {
			log.Printf("[ADDON-INJECT] credential %q lookup failed: %v", name, err)
			continue
		}
		if vault.IsOAuth(secret.Bytes()) {
			oauthPairs, parseErr := buildOAuthPhantomPairs(name, secret, "ADDON-INJECT")
			if parseErr != nil {
				continue
			}
			pairs = append(pairs, oauthPairs...)
			continue
		}
		pairs = append(pairs, phantomPair{
			phantom: []byte(PhantomToken(name)),
			secret:  secret,
		})
	}

	// Sort by phantom length descending so longer tokens are replaced
	// before shorter prefixes that could corrupt them.
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].phantom) > len(pairs[j].phantom)
	})
	return pairs
}

// releasePhantomPairs zeroes all secret values in the pairs slice.
func releasePhantomPairs(pairs []phantomPair) {
	for i := range pairs {
		pairs[i].secret.Release()
	}
}

// hasPhantomPrefix checks whether the request body, headers, or URL
// contain the phantom prefix bytes.
func (a *SluiceAddon) hasPhantomPrefix(f *mitmproxy.Flow) bool {
	if bytes.Contains(f.Request.Body, phantomPrefix) {
		return true
	}
	for _, vals := range f.Request.Header {
		for _, v := range vals {
			if bytes.Contains([]byte(v), phantomPrefix) {
				return true
			}
		}
	}
	if bytes.Contains([]byte(f.Request.URL.RawQuery), phantomPrefix) {
		return true
	}
	if bytes.Contains([]byte(f.Request.URL.Path), phantomPrefix) {
		return true
	}
	return false
}

// swapPhantomBytes performs Pass 2 (scoped replacement) and Pass 3 (strip
// unbound) on a byte slice.
func (a *SluiceAddon) swapPhantomBytes(data []byte, pairs []phantomPair, host string, port int, location string) []byte {
	for _, p := range pairs {
		if bytes.Contains(data, p.phantom) {
			data = bytes.ReplaceAll(data, p.phantom, p.secret.Bytes())
		}
	}
	if bytes.Contains(data, phantomPrefix) {
		data = stripUnboundPhantomsFromProvider(data, a.provider)
		log.Printf("[ADDON-INJECT] stripped unbound phantom token from %s for %s:%d", location, host, port)
	}
	return data
}

// swapPhantomHeaders performs Pass 2+3 on all request headers.
func (a *SluiceAddon) swapPhantomHeaders(f *mitmproxy.Flow, pairs []phantomPair, host string, port int) {
	for key, vals := range f.Request.Header {
		for i, v := range vals {
			vb := []byte(v)
			changed := false
			for _, p := range pairs {
				if bytes.Contains(vb, p.phantom) {
					vb = bytes.ReplaceAll(vb, p.phantom, p.secret.Bytes())
					changed = true
				}
			}
			if bytes.Contains(vb, phantomPrefix) {
				vb = stripUnboundPhantomsFromProvider(vb, a.provider)
				changed = true
				log.Printf("[ADDON-INJECT] stripped unbound phantom token from header %q for %s:%d", key, host, port)
			}
			if changed {
				f.Request.Header[key][i] = string(vb)
			}
		}
	}
}

// phantomSwapReader wraps an io.Reader and performs byte-level phantom
// token replacement as data streams through. It buffers data internally
// to handle phantom tokens that span read boundaries.
type phantomSwapReader struct {
	inner    io.Reader
	pairs    []phantomPair
	provider vault.Provider
	buf      bytes.Buffer
	pending  []byte
	eof      bool
	released bool
}

// maxPhantomLen returns the length of the longest phantom token in the
// pairs list. Used to determine how much data to hold back from the
// output buffer to handle tokens that span read boundaries.
func maxPhantomLen(pairs []phantomPair) int {
	m := 0
	for _, p := range pairs {
		if len(p.phantom) > m {
			m = len(p.phantom)
		}
	}
	// Also account for the generic phantom prefix pattern.
	if pLen := len(phantomPrefix) + maxCredNameLen; pLen > m {
		m = pLen
	}
	return m
}

func (r *phantomSwapReader) Read(p []byte) (int, error) {
	for r.buf.Len() == 0 {
		if r.eof {
			if !r.released {
				r.released = true
				releasePhantomPairs(r.pairs)
			}
			return 0, io.EOF
		}

		// Read a chunk from the inner reader.
		chunk := make([]byte, 32*1024)
		n, err := r.inner.Read(chunk)
		if n > 0 {
			r.pending = append(r.pending, chunk[:n]...)
		}
		if err == io.EOF {
			r.eof = true
		} else if err != nil {
			return 0, err
		}

		maxPhan := maxPhantomLen(r.pairs)
		if maxPhan < 1 {
			maxPhan = 1
		}

		// Determine how much data is safe to emit. Hold back up to
		// maxPhan-1 bytes to handle tokens that span boundaries,
		// unless we have reached EOF.
		safe := len(r.pending)
		if !r.eof && safe > maxPhan-1 {
			safe = safe - (maxPhan - 1)
		} else if !r.eof {
			// Not enough data to safely emit. Continue reading.
			continue
		}

		toProcess := r.pending[:safe]
		r.pending = append([]byte(nil), r.pending[safe:]...)

		// Pass 2: scoped replacement.
		for _, pp := range r.pairs {
			if bytes.Contains(toProcess, pp.phantom) {
				toProcess = bytes.ReplaceAll(toProcess, pp.phantom, pp.secret.Bytes())
			}
		}
		// Pass 3: strip unbound.
		if bytes.Contains(toProcess, phantomPrefix) {
			toProcess = stripUnboundPhantomsFromProvider(toProcess, r.provider)
		}

		r.buf.Write(toProcess)
	}

	return r.buf.Read(p)
}

// normalizeRequestAuthority rewrites the request's URL.Host and Host header
// to match the CONNECT target when they diverge. This prevents cross-origin
// routing through an approved tunnel.
func (a *SluiceAddon) normalizeRequestAuthority(f *mitmproxy.Flow, connectHost string, connectPort int) {
	// Extract the inner request's host.
	innerHost := f.Request.URL.Hostname()
	if innerHost == "" {
		innerHost = f.Request.Header.Get("Host")
		if h, _, err := net.SplitHostPort(innerHost); err == nil {
			innerHost = h
		}
	}

	// Build the canonical authority for the CONNECT target.
	connectAuthority := formatAuthority(connectHost, connectPort)

	if innerHost != "" && !strings.EqualFold(innerHost, connectHost) {
		log.Printf("[ADDON-WARN] cross-origin request on tunnel: CONNECT=%s:%d inner=%s (normalizing)",
			connectHost, connectPort, innerHost)
		f.Request.URL.Host = connectAuthority
		f.Request.Header.Set("Host", connectAuthority)
	}

	// Also normalize scheme for well-known CONNECT ports.
	switch connectPort {
	case 443:
		if f.Request.URL.Scheme != "" && f.Request.URL.Scheme != "https" {
			f.Request.URL.Scheme = "https"
		}
	case 80:
		if f.Request.URL.Scheme != "" && f.Request.URL.Scheme != "http" {
			f.Request.URL.Scheme = "http"
		}
	}
}

// formatAuthority builds the host:port authority string, omitting the port
// for standard HTTP(S) ports and using brackets for IPv6 addresses.
func formatAuthority(host string, port int) string {
	if port == 443 || port == 80 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// detectRequestProtocol determines the application-layer protocol for a
// request using the URL scheme and HTTP headers (for gRPC/WebSocket).
func (a *SluiceAddon) detectRequestProtocol(f *mitmproxy.Flow, connectPort int) Protocol {
	var proto Protocol
	switch f.Request.URL.Scheme {
	case "https":
		proto = ProtoHTTPS
	case "http":
		proto = ProtoHTTP
	default:
		proto = DetectProtocol(connectPort)
	}

	isTLS := proto == ProtoHTTPS
	if refined := DetectProtocolFromHeaders(f.Request.Header, isTLS); refined != ProtoGeneric {
		proto = refined
	}
	return proto
}
