package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
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

	// poolResolver expands a bound pool name to its currently active
	// member at the single injection chokepoint (resolvePoolMember).
	// Swapped atomically alongside resolver on reload; may be nil when
	// no pools are configured (treated as identity passthrough). Phase 2
	// mutates the contained health map in place under the resolver's own
	// mutex on the response path.
	poolResolver *atomic.Pointer[vault.PoolResolver]

	// provider retrieves real credential values from the vault.
	provider vault.Provider

	// oauthIndex maps OAuth token endpoint URLs to credential names.
	// Used by the Response handler to detect token responses and perform
	// phantom token replacement. Updated atomically via UpdateOAuthIndex.
	oauthIndex atomic.Pointer[OAuthIndex]

	// redactRules holds compiled MITM response DLP rules. Used by the
	// Response handler to scan HTTPS response headers and bodies for
	// credential patterns and redact matches. Swapped atomically via
	// SetRedactRules (called on startup and SIGHUP). A nil value means
	// response DLP is disabled.
	redactRules atomic.Pointer[[]mitmRedactRule]

	// dlpNoMatchScans counts DLP scans that produced no redaction.
	// Used to rate-limit the "scanned with no match" debug log so it
	// emits every dlpNoMatchLogEvery scans instead of once per response.
	dlpNoMatchScans uint64

	// dlpStreamWarned tracks connections that have already been warned
	// about streaming bypass of DLP. Keyed by client connection id so
	// the warning only fires once per connection instead of once per
	// streamed response chunk. Use sync.Map to avoid per-lookup locking
	// on the hot StreamResponseModifier path.
	dlpStreamWarned sync.Map

	// refreshGroup deduplicates concurrent OAuth token refresh responses
	// for the same credential. Keyed by credential name so only one
	// vault update occurs when multiple requests trigger simultaneous
	// refreshes.
	refreshGroup singleflight.Group

	// refreshAttr maps the real refresh token sluice injected into an
	// outbound OAuth refresh-grant to the pool member that owns it. It is
	// the precise per-request join key for pooled credential refresh
	// attribution (Risk R1). Never nil after NewSluiceAddon.
	refreshAttr *refreshAttribution

	// onOAuthRefresh is called after an OAuth token refresh persist
	// completes successfully. It receives the credential name so the
	// caller can re-inject updated phantom env vars into the agent
	// container. Nil means no post-refresh action.
	onOAuthRefresh func(credName string)

	// persistDone is an optional channel signaled when an async OAuth
	// token persist goroutine completes. Used by tests to avoid
	// time.Sleep-based synchronization. Nil in production.
	persistDone chan struct{}

	// responsePanicHook is a test injection point for the Response
	// handler's deferred recover. When non-nil it is invoked between
	// the OAuth swap and the DLP scan, so a test can force the
	// downstream-of-OAuth panic shape we observed in production
	// without having to engineer a malformed Flow that triggers a
	// real nil deref. Always nil in production.
	responsePanicHook func()

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
		refreshAttr:     newRefreshAttribution(),
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

// WithPoolResolver sets the credential pool resolver pointer used by the
// injection chokepoint to expand a bound pool name to its active member.
func WithPoolResolver(r *atomic.Pointer[vault.PoolResolver]) SluiceAddonOption {
	return func(a *SluiceAddon) { a.poolResolver = r }
}

// SetPoolResolver wires (or rewires) the shared pool resolver pointer. Safe
// to call after construction; the pointer itself is stable and only its
// contents are atomically swapped on reload.
func (a *SluiceAddon) SetPoolResolver(r *atomic.Pointer[vault.PoolResolver]) {
	a.poolResolver = r
}

// resolvePoolMember is the single chokepoint that expands a bound
// credential-or-pool name to the concrete credential whose secret should be
// injected. For a plain credential it returns the name unchanged. For a
// pool it returns the currently active member. Every consumer that reads a
// binding's Credential (pass-1 header inject, pass-2 phantom pairs,
// OAuthIndex.Has gating, persist attribution) routes through here so pool
// expansion happens in exactly one place (Important I2).
func (a *SluiceAddon) resolvePoolMember(name string) string {
	if a.poolResolver == nil {
		return name
	}
	pr := a.poolResolver.Load()
	if pr == nil {
		return name
	}
	if member, ok := pr.ResolveActive(name); ok {
		return member
	}
	return name
}

// injectionTarget is the result of expanding a bound credential-or-pool
// name at the single chokepoint. phantomName is the name the agent's
// phantom string is keyed on (the POOL name when pooled, so the phantom is
// stable across member switches); secretName is the concrete credential
// whose real vault value is injected (the active member when pooled). For a
// plain credential both fields equal the input name and pooled is false.
type injectionTarget struct {
	phantomName string
	secretName  string
	pooled      bool
}

// resolveInjectionTarget is the single chokepoint every credential consumer
// (pass-1 header inject, pass-2 phantom pairs, OAuthIndex.Has gating,
// persist attribution) routes through. It expands a pool name to its active
// member exactly once here so no consumer scatters its own IsPool check
// (Important I2). The pool→member expansion MUST happen before any
// OAuthIndex.Has / JSON-envelope decision: a pool name is not in
// credential_meta so idx.Has(pool) is always false, and gating on the pool
// name would mis-handle the OAuth envelope as a static secret.
func (a *SluiceAddon) resolveInjectionTarget(name string) injectionTarget {
	if a.poolResolver == nil {
		return injectionTarget{phantomName: name, secretName: name}
	}
	pr := a.poolResolver.Load()
	if pr == nil {
		return injectionTarget{phantomName: name, secretName: name}
	}
	if !pr.IsPool(name) {
		return injectionTarget{phantomName: name, secretName: name}
	}
	member, ok := pr.ResolveActive(name)
	if !ok || member == "" {
		// Empty/unresolvable pool: keep the name so callers degrade
		// gracefully (no secret found -> no injection) rather than
		// dereferencing an empty string.
		return injectionTarget{phantomName: name, secretName: name, pooled: true}
	}
	return injectionTarget{phantomName: name, secretName: member, pooled: true}
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
	// Drop the per-connection DLP streaming warning flag so a
	// reconnecting client that triggers another streamed response
	// gets a fresh warning.
	a.dlpStreamWarned.Delete(client.Id)
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
	// Only update host/port if not already set by a prior callback
	// (ServerConnected fires before TlsEstablishedServer). This prevents
	// a host-only TLS callback from overwriting a correct port with a
	// recovered/defaulted value.
	if cs.connectHost == "" {
		cs.connectHost = host
		cs.connectPort = port
	} else if host != "" && host != cs.connectHost {
		cs.connectHost = host
		cs.connectPort = port
	}

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
	verdict, err := checker.CheckAndConsume(
		connectHost, connectPort,
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

	// Chokepoint: expand a bound pool name to its active member BEFORE the
	// vault lookup and the OAuthIndex.Has envelope decision. A pool name is
	// not a vault credential and is not in credential_meta, so both
	// provider.Get and extractInjectableSecret must operate on the resolved
	// member name (Important I2).
	target := a.resolveInjectionTarget(binding.Credential)

	secret, err := a.provider.Get(target.secretName)
	if err != nil {
		log.Printf("[ADDON-INJECT] credential %q lookup failed: %v", target.secretName, err)
		return
	}
	defer secret.Release()

	f.Request.Header.Set(binding.Header, binding.FormatValue(extractInjectableSecret(a.oauthIndex.Load(), target.secretName, secret.String())))
	if target.pooled {
		log.Printf("[ADDON-INJECT] injected header %q for %s:%d (pool %q -> member %q)",
			binding.Header, host, port, binding.Credential, target.secretName)
	} else {
		log.Printf("[ADDON-INJECT] injected header %q for %s:%d (credential %q)",
			binding.Header, host, port, binding.Credential)
	}
}

// extractInjectableSecret returns the value to substitute into a binding's
// `{value}` template.
//
// Static credentials are plain strings stored as-is in the vault; the
// value to inject is the string itself. OAuth credentials are
// JSON-marshalled OAuthCredential structs (access_token + refresh_token
// + token_url + expires_at); the value to inject is just the
// access_token, so a binding like `Authorization: Bearer {value}`
// produces `Bearer <jwt>` rather than `Bearer {"access_token":...}`.
//
// We dispatch on the credential's metadata type (looked up via the
// supplied OAuthIndex, populated from credential_meta on startup and
// SIGHUP) rather than inferring from the secret's JSON shape. Shape
// inference would mis-handle a static credential whose value happens
// to be OAuth-shaped JSON. The credential_meta table is the single
// source of truth for cred_type elsewhere in sluice; the injection
// path follows the same rule.
//
// If the metadata says oauth but parsing fails (corrupted vault
// entry, schema drift, etc.) we fall back to the raw secret. That
// preserves the previous behavior on broken state instead of
// returning an empty string and silently producing `Bearer ` headers.
//
// A nil index (no oauth credentials registered yet, or the QUIC
// path running before UpdateOAuthIndex fires) means every
// credential is treated as static.
func extractInjectableSecret(idx *OAuthIndex, credName, secret string) string {
	if idx == nil || !idx.Has(credName) {
		return secret
	}
	cred, err := vault.ParseOAuth([]byte(secret))
	if err != nil || cred == nil || cred.AccessToken == "" {
		// Generic [INJECT] prefix because both the HTTP/1+2 and the
		// HTTP/3 (QUIC) header-injection paths share this helper.
		// An [ADDON-INJECT] tag would mislead a reader who saw the
		// line in a deployment that uses HTTP/3 exclusively.
		log.Printf("[INJECT] credential %q registered as oauth but vault payload not parseable; injecting raw secret", credName)
		return secret
	}
	return cred.AccessToken
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
		f.Request.Body = a.swapPhantomBytes(f.Request.Body, pairs, host, port, "body", false)
	}

	// Pass 2+3 on URL query.
	if rawQ := f.Request.URL.RawQuery; bytesContainsAnyPhantomPrefix([]byte(rawQ)) {
		f.Request.URL.RawQuery = string(
			a.swapPhantomBytes([]byte(rawQ), pairs, host, port, "URL query", false),
		)
	}

	// Pass 2+3 on URL path. pathContext=true selects path escaping so
	// secrets containing spaces get %20, not '+'.
	if rawP := f.Request.URL.Path; bytesContainsAnyPhantomPrefix([]byte(rawP)) {
		f.Request.URL.Path = string(
			a.swapPhantomBytes([]byte(rawP), pairs, host, port, "URL path", true),
		)
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

// Response performs OAuth response interception and outbound DLP scanning on
// fully-buffered response bodies. When the response comes from a known OAuth
// token endpoint (matched via OAuthIndex), real tokens are replaced with
// deterministic phantom tokens before the response reaches the agent. After
// OAuth processing, response headers and body are scanned for configured
// redact patterns (see SetRedactRules) so credential strings in upstream
// responses are scrubbed before being relayed to the agent.
func (a *SluiceAddon) Response(f *mitmproxy.Flow) {
	// Top-level recover so a panic inside any sub-step (OAuth swap,
	// DLP scan, future hooks) cannot escape into go-mitmproxy's
	// generic recover, which abandons the response body and leaves
	// the agent reading an empty stream. We log the full stack so
	// the underlying bug can be diagnosed later, but the response
	// continues with whatever state f.Response was in at the time
	// of the panic. Real tokens cannot leak: processOAuthResponseIfMatching
	// has its own snapshot/rollback, and any panic in DLP runs AFTER
	// OAuth swap (so tokens are already phantoms by then).
	defer func() {
		if r := recover(); r != nil {
			host := "unknown"
			method := ""
			if f != nil && f.Request != nil {
				if f.Request.URL != nil {
					host = f.Request.URL.Host
				}
				method = f.Request.Method
			}
			log.Printf("[ADDON] PANIC in Response handler for %s %s: %v\n%s", method, host, r, debug.Stack())
		}
	}()

	// Nil-flow guard. The deferred recover above dereferences f to
	// build the log line; without this early return, a nil flow
	// (which go-mitmproxy never produces in practice but tests can)
	// would hit the recover path on every call. Mirror what
	// StreamResponseModifier does so both entry points handle nil
	// flows uniformly.
	if f == nil {
		return
	}
	if f.Response == nil || f.Request == nil {
		return
	}

	a.processOAuthResponseIfMatching(f)

	// Test-only panic injection. Always nil in production. Lets a
	// regression test exercise the deferred recover above without
	// having to construct a Flow that triggers a real downstream
	// nil deref.
	if a.responsePanicHook != nil {
		a.responsePanicHook()
	}

	// Outbound DLP: scan response body and headers for credential
	// patterns that should not reach the agent. Runs after OAuth
	// processing so real tokens are already swapped to phantoms.
	a.scanResponseForDLP(f)
}

// oauthRespAttribution describes how a token-endpoint response is handled.
// phantomName keys the phantom strings the agent receives (the POOL name
// for pooled creds, so the phantom is byte-identical across member switches
// — Risk R3). persistMember names the vault entry the rotated real tokens
// are written to. skipPersist is set when the response belongs to a pooled
// token URL but the owning member could not be recovered from the injected
// real refresh token — the swap still runs (the agent must never see real
// tokens) but the vault write is skipped so we never misfile B's rotated
// tokens under A (Risk R1, fail-closed).
type oauthRespAttribution struct {
	phantomName   string
	persistMember string
	pooled        bool
	skipPersist   bool
}

// resolveOAuthResponseAttribution turns the OAuthIndex match into a precise
// attribution. For a plain credential it is the identity (phantom + persist
// both the matched name). For a pooled member it keys the phantom on the
// pool name and recovers the owning member via the REAL refresh token that
// was injected into this exact outbound request body (the only join key
// that survives two members sharing one token URL). When recovery fails it
// returns skipPersist=true and never falls back to OAuthIndex.Match for the
// persist target (R1: never guess).
func (a *SluiceAddon) resolveOAuthResponseAttribution(f *mitmproxy.Flow, matchedCred string) oauthRespAttribution {
	pr := (*vault.PoolResolver)(nil)
	if a.poolResolver != nil {
		pr = a.poolResolver.Load()
	}
	poolName := ""
	if pr != nil {
		poolName = pr.PoolForMember(matchedCred)
	}
	if poolName == "" {
		// Not a pooled token URL: unchanged 1:1 behavior.
		return oauthRespAttribution{phantomName: matchedCred, persistMember: matchedCred}
	}

	// Pooled token URL. Recover the owning member from the real refresh
	// token sluice injected into this request's body (R1 join key).
	reqCT := ""
	reqBody := []byte(nil)
	if f.Request != nil {
		if f.Request.Header != nil {
			reqCT = f.Request.Header.Get("Content-Type")
		}
		reqBody = f.Request.Body
	}
	realRefresh := extractRequestRefreshToken(reqBody, reqCT)
	member, ok := a.refreshAttr.Recover(realRefresh)
	if !ok {
		log.Printf("[ADDON-OAUTH] R1 fail-closed: pooled token URL for pool %q but owning member "+
			"could not be recovered from the injected refresh token; skipping vault write "+
			"(next refresh will retry)", poolName)
		return oauthRespAttribution{phantomName: poolName, pooled: true, skipPersist: true}
	}
	log.Printf("[ADDON-OAUTH] R1 attributed pooled refresh to member %q (pool %q)", member, poolName)
	return oauthRespAttribution{phantomName: poolName, persistMember: member, pooled: true}
}

// processOAuthResponseIfMatching performs OAuth token phantom swap on the
// response when the request URL matches the OAuth index. Extracted from
// Response so DLP scanning can run independently on non-OAuth responses.
func (a *SluiceAddon) processOAuthResponseIfMatching(f *mitmproxy.Flow) {
	// Only intercept successful responses for OAuth token handling.
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

	// Chokepoint: turn the (collision-prone for pools) OAuthIndex match
	// into a precise phantom-key + persist-member attribution.
	attr := a.resolveOAuthResponseAttribution(f, credName)

	modified, err := a.processAddonOAuthResponse(f, attr)
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
//
// IMPORTANT: response DLP scanning is bypassed when this path is active
// because go-mitmproxy skips the Response addon callback when
// f.Stream=true. go-mitmproxy sets f.Stream=true automatically for:
//   - any response whose Content-Type contains "text/event-stream" (SSE,
//     including LLM streaming completions), and
//   - any response whose body exceeds StreamLargeBodies (default 5 MiB),
//     applied to the range between 5 MiB and maxProxyBody (16 MiB).
//
// These paths bypass response DLP today. When rules are configured, we
// emit a single WARNING per client connection so operators notice the
// gap without log spam from multi-chunk streams. The dedup state lives
// on dlpStreamWarned, scoped to the client connection id.
func (a *SluiceAddon) StreamResponseModifier(f *mitmproxy.Flow, in io.Reader) (out io.Reader) {
	// Default to passing the input through unchanged; named return
	// lets the deferred recover ensure we always hand SOMETHING
	// usable back to go-mitmproxy on a panic, instead of letting
	// the panic escape into mitmproxy's outer recover (which
	// abandons the response body entirely).
	out = in

	// Defensive nil-input guard up front, BEFORE the flow checks
	// below. If both `f` and `in` are nil (rare but possible in tests
	// or on an unusual go-mitmproxy code path), the f-nil early
	// return below would otherwise hand back a nil io.Reader, which
	// the proxy's downstream copy would nil-deref on. http.NoBody
	// keeps the response well-framed (zero bytes) and the panic is
	// avoided regardless of what `f` looks like.
	if in == nil {
		out = http.NoBody
		return out
	}

	if f == nil || f.Request == nil {
		return out
	}

	// Known-safe fallback for the panic recover. Set ONLY after the
	// OAuth phantom swap has produced a clean buffer that contains
	// no real tokens. Critically: we never assign the raw upstream
	// bytes here, because a matched OAuth token-endpoint response
	// contains real access and refresh tokens, and a panic between
	// io.ReadAll and a successful swapOAuthTokens would otherwise
	// leak those tokens straight to the agent. If the panic fires
	// before safeFallback is set, the recover hands back http.NoBody
	// instead. The agent sees an empty 2xx token body and surfaces
	// the failure as a parse error, which is the strictly safer
	// outcome compared to leaking a real bearer.
	var safeFallback []byte
	defer func() {
		if r := recover(); r != nil {
			host := "unknown"
			if f.Request != nil && f.Request.URL != nil {
				host = f.Request.URL.Host
			}
			log.Printf("[ADDON] PANIC in StreamResponseModifier for %s: %v\n%s", host, r, debug.Stack())
			if safeFallback != nil {
				out = bytes.NewReader(safeFallback)
			} else {
				out = http.NoBody
			}
		}
	}()

	// Warn when DLP rules are configured but the response is streamed.
	// Dedupe by client connection id so we emit at most one warning per
	// connection. Otherwise multi-chunk streams produce a line per
	// chunk. When the connection state is unavailable (defensive: rare
	// in production but possible in tests or when go-mitmproxy is
	// re-entered on an unusual code path), fall back to a non-dedup log
	// so the warning is not silently suppressed.
	//
	// The warning is emitted regardless of status code. A streamed 4xx
	// or 5xx body (e.g. an SSE error stream from an LLM API or a large
	// error response) still bypasses DLP scanning, and operators need
	// the visibility signal to know credential patterns in that body
	// would not be redacted. Since the warning does not modify the
	// response, firing it on non-2xx responses is safe.
	if rules := a.loadRedactRules(); len(rules) > 0 {
		host := "unknown"
		if f.Request.URL != nil {
			host = f.Request.URL.Host
		}
		if f.ConnContext != nil && f.ConnContext.ClientConn != nil {
			connID := f.ConnContext.ClientConn.Id
			if _, loaded := a.dlpStreamWarned.LoadOrStore(connID, struct{}{}); !loaded {
				log.Printf("[ADDON-DLP] WARNING: streaming response bypasses DLP for %s (%d rules configured)", host, len(rules))
			}
		} else {
			log.Printf("[ADDON-DLP] WARNING: streaming response bypasses DLP for %s (%d rules configured; connection state unavailable, dedup disabled)", host, len(rules))
		}
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

	// Chokepoint: precise phantom-key + persist-member attribution
	// (pool-stable phantom, R1 fail-closed when member unrecoverable).
	attr := a.resolveOAuthResponseAttribution(f, credName)

	modified, err := a.swapOAuthTokens(body, contentType, attr)
	if err != nil {
		// The body did not parse as an OAuth token response. This is
		// usually an HTML error page from a misconfigured token
		// endpoint, not a credentials envelope, so passing it through
		// is the historical behavior. We deliberately do NOT set
		// safeFallback here: if a later panic somehow fires while
		// returning, the recover defaults to http.NoBody rather than
		// leaking whatever this body contains.
		log.Printf("[ADDON-OAUTH] stream token parse error for credential %q: %v", credName, err)
		return bytes.NewReader(body)
	}

	// Swap completed. The modified buffer is phantom-only and safe to
	// hand back on a late panic.
	safeFallback = modified
	return bytes.NewReader(modified)
}

// processAddonOAuthResponse reads the token response body from the flow,
// replaces real tokens with phantoms, updates the flow's response body,
// and schedules an async vault update. Returns true if the body was
// modified.
//
// If the response is compressed (Content-Encoding: gzip, br, deflate, zstd
// or stacked combinations of those), the body is decoded in place via
// safeReplaceToDecodedBody before parsing. The replacement body is written
// back as plaintext and Content-Encoding is stripped so the client decodes
// nothing further. The deferred recover guards against panics anywhere
// in the rewrite path so a malformed token endpoint response cannot take
// the proxy down.
//
// Atomic semantics around decode: a successful decompress mutates
// f.Response.Body and the encoding/length headers. If a subsequent
// step (swap, panic) fails, the response would otherwise be left as
// plaintext bytes with stripped encoding headers — the client could
// then read the still-real-tokens body unredacted. The pre-decode
// snapshot is restored on every failure path so the flow either has a
// fully phantom-swapped body or the original bytes with original
// headers, never a half-modified mix.
func (a *SluiceAddon) processAddonOAuthResponse(f *mitmproxy.Flow, attr oauthRespAttribution) (modified bool, err error) {
	credName := attr.phantomName
	if f == nil || f.Response == nil {
		return false, nil
	}
	if len(f.Response.Body) == 0 {
		return false, nil
	}

	// Snapshot before any mutation so we can roll back on error/panic.
	origBody := f.Response.Body
	var origContentEncoding, origContentLength, origTransferEncoding []string
	if f.Response.Header != nil {
		origContentEncoding = append([]string(nil), f.Response.Header.Values("Content-Encoding")...)
		origContentLength = append([]string(nil), f.Response.Header.Values("Content-Length")...)
		origTransferEncoding = append([]string(nil), f.Response.Header.Values("Transfer-Encoding")...)
	}
	rollback := func() {
		f.Response.Body = origBody
		if f.Response.Header == nil {
			return
		}
		f.Response.Header.Del("Content-Encoding")
		for _, v := range origContentEncoding {
			f.Response.Header.Add("Content-Encoding", v)
		}
		f.Response.Header.Del("Content-Length")
		for _, v := range origContentLength {
			f.Response.Header.Add("Content-Length", v)
		}
		f.Response.Header.Del("Transfer-Encoding")
		for _, v := range origTransferEncoding {
			f.Response.Header.Add("Transfer-Encoding", v)
		}
	}

	defer func() {
		if r := recover(); r != nil {
			rollback()
			err = fmt.Errorf("panic in OAuth response handler for %q: %v", credName, r)
			modified = false
		}
	}()

	if f.Response.Header != nil && hasAnyContentEncoding(f.Response.Header) {
		if decErr := safeReplaceToDecodedBody(f); decErr != nil {
			rollback()
			return false, fmt.Errorf("decode compressed token response: %w", decErr)
		}
	}

	body := f.Response.Body
	if len(body) == 0 {
		rollback()
		return false, nil
	}

	contentType := ""
	if f.Response.Header != nil {
		contentType = f.Response.Header.Get("Content-Type")
	}

	swapped, err := a.swapOAuthTokens(body, contentType, attr)
	if err != nil {
		rollback()
		return false, err
	}

	// `modified` reflects whether the swap actually changed bytes. A
	// token endpoint that echoed already-phantom tokens (e.g. on a
	// retry where the upstream was previously rotated) would produce
	// a byte-identical body. Reporting modified=true in that case
	// would log a misleading "swapped to phantoms" message and bump
	// metrics that operators read as live token leakage.
	bodyChanged := !bytes.Equal(body, swapped)
	if !bodyChanged {
		// No change to commit. Roll back the decompress so the
		// flow's encoding/length headers continue to advertise the
		// original (still-valid) wire form.
		rollback()
		return false, nil
	}

	f.Response.Body = swapped
	if f.Response.Header != nil {
		f.Response.Header.Set("Content-Length", strconv.Itoa(len(swapped)))
		f.Response.Header.Del("Transfer-Encoding")
		// Body is plaintext after safeReplaceToDecodedBody (or was already
		// plaintext). Drop Content-Encoding so the client does not try to
		// decode it again.
		f.Response.Header.Del("Content-Encoding")
	}

	return true, nil
}

// swapOAuthTokens parses a token response body, replaces real tokens with
// deterministic phantoms, and schedules an async vault persist. Returns
// the modified body. Shared by Response (buffered) and StreamResponseModifier.
//
// attr controls phantom keying and persist target. For a plain credential
// it is the identity. For a pooled credential the phantom is keyed on the
// POOL name (byte-identical across member switches, Risk R3) and the
// persist target is the recovered owning member; when the member could not
// be recovered, attr.skipPersist suppresses the vault write entirely so a
// rotated token is never misfiled (Risk R1, fail-closed) — the swap still
// runs so the agent never receives the real tokens.
func (a *SluiceAddon) swapOAuthTokens(body []byte, contentType string, attr oauthRespAttribution) ([]byte, error) {
	tr, err := parseTokenResponse(body, contentType)
	if err != nil {
		return nil, err
	}

	var accessPhantom, refreshPhantom string
	if attr.pooled {
		// Pooled: phantomName is the pool name. Use the pool-stable
		// synthetic JWT for access and the deterministic static string
		// for refresh, byte-identical to what buildPooledOAuthPhantomPairs
		// emits on the request side, so the agent's stored phantom never
		// changes across a member switch.
		accessPhantom = poolStablePhantomAccess(attr.phantomName)
		refreshPhantom = "SLUICE_PHANTOM:" + attr.phantomName + ".refresh"
	} else {
		accessPhantom = oauthPhantomAccess(attr.phantomName, tr.AccessToken)
		refreshPhantom = oauthPhantomRefresh(attr.phantomName, tr.RefreshToken)
	}

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

	if attr.skipPersist {
		// R1 fail-closed: response swapped to phantoms (agent safe) but
		// the owning pool member is unknown, so do NOT write the vault.
		// The next refresh round-trip carries a fresh tag and retries.
		return modified, nil
	}

	// Asynchronously persist the new tokens to the vault, attributed to
	// the precise member (pooled) or the credential itself (plain).
	realAccess := vault.NewSecureBytes(tr.AccessToken)
	realRefresh := vault.NewSecureBytes(tr.RefreshToken)
	expiresIn := tr.ExpiresIn

	go a.persistAddonOAuthTokens(attr.persistMember, realAccess, realRefresh, expiresIn)

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
	for _, boundName := range boundCreds {
		// Chokepoint: expand a bound pool name to its active member
		// before the vault lookup and the OAuth-envelope decision. The
		// agent holds a pool-keyed phantom; the secret injected is the
		// active member's real token (Important I2).
		target := a.resolveInjectionTarget(boundName)
		name := target.secretName
		secret, err := a.provider.Get(name)
		if err != nil {
			log.Printf("[ADDON-INJECT] credential %q lookup failed: %v", name, err)
			continue
		}
		if vault.IsOAuth(secret.Bytes()) {
			if target.pooled {
				poolName := target.phantomName
				member := target.secretName
				oauthPairs, parseErr := buildPooledOAuthPhantomPairs(
					poolName, member, secret, "ADDON-INJECT",
					func(realRefresh string) {
						a.refreshAttr.Tag(realRefresh, member)
					},
				)
				if parseErr != nil {
					continue
				}
				pairs = append(pairs, oauthPairs...)
				continue
			}
			oauthPairs, parseErr := buildOAuthPhantomPairs(name, secret, "ADDON-INJECT")
			if parseErr != nil {
				continue
			}
			pairs = append(pairs, oauthPairs...)
			continue
		}
		// Static (non-OAuth) credential. Pools reject static members, so
		// a pooled target never reaches here; the phantom is keyed on the
		// resolved name (== bound name for plain creds).
		phantom := []byte(PhantomToken(name))
		encoded := encodePhantomForPair(phantom)
		pairs = append(pairs, phantomPair{
			phantom:             phantom,
			encodedPhantom:      encoded,
			encodedPhantomLower: encodePhantomLowerForPair(encoded),
			secret:              secret,
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
	if bytesContainsAnyPhantomPrefix(f.Request.Body) {
		return true
	}
	for _, vals := range f.Request.Header {
		for _, v := range vals {
			if bytesContainsAnyPhantomPrefix([]byte(v)) {
				return true
			}
		}
	}
	if bytesContainsAnyPhantomPrefix([]byte(f.Request.URL.RawQuery)) {
		return true
	}
	if bytesContainsAnyPhantomPrefix([]byte(f.Request.URL.Path)) {
		return true
	}
	return false
}

// bytesContainsAnyPhantomPrefix reports whether the data contains the
// literal phantom prefix or either case of the URL-encoded prefix (%3A or
// %3a). Form-urlencoded request bodies and URL query/path components
// percent-encode the colon in phantom tokens, and RFC 3986 §2.1 makes the
// hex digits case-insensitive, so a scan that only checks one case would
// miss phantoms emitted by clients that lowercase their percent escapes.
func bytesContainsAnyPhantomPrefix(data []byte) bool {
	return bytes.Contains(data, phantomPrefix) ||
		bytes.Contains(data, urlEncodedPhantomPrefix) ||
		bytes.Contains(data, urlEncodedPhantomPrefixLower)
}

// swapPhantomBytes performs Pass 2 (scoped replacement) and Pass 3 (strip
// unbound) on a byte slice.
//
// Each pair is matched in both its literal form (`SLUICE_PHANTOM:<name>`,
// the shape used in JSON bodies and raw header values) and its URL-encoded
// form (`SLUICE_PHANTOM%3A<name>`, the shape used in
// application/x-www-form-urlencoded request bodies and URL query strings).
// The encoded path is what makes OAuth refresh round-trips work: refresh
// POSTs to providers like Anthropic and Google use form-urlencoded bodies,
// so the colon in the phantom token gets percent-encoded on the wire.
// Without the encoded scan the upstream receives `SLUICE_PHANTOM%3A...`
// literally, returns `invalid_grant`, and the agent falls back to a fresh
// interactive OAuth — every time tokens expire.
//
// The encoded phantom is precomputed once per pair (in encodePhantomForPair)
// and stored on phantomPair.encodedPhantom so we don't re-allocate it on
// every body, query, or header scan. The encoded secret is computed on
// demand once per swap call, only when the encoded phantom actually appears.
//
// pathContext chooses between query escaping (false; body, URL query,
// header) and path escaping (true; URL path). The two differ in how
// spaces are encoded: QueryEscape uses '+', PathEscape uses '%20'. Using
// query escaping for a path substitution would turn a space in the
// secret into a literal '+' in the URL path, which the server reads as
// a plus character, not a space — corrupting the request. The boolean is
// passed in explicitly so the type system enforces the choice; callers
// cannot accidentally pick path escaping by typo-ing the location label.
// location is still passed for the audit log message but never drives
// behavior.
func (a *SluiceAddon) swapPhantomBytes(data []byte, pairs []phantomPair, host string, port int, location string, pathContext bool) []byte {
	for _, p := range pairs {
		if bytes.Contains(data, p.phantom) {
			data = bytes.ReplaceAll(data, p.phantom, p.secret.Bytes())
		}
		// Encoded swap covers both uppercase (%3A, the canonical form Go
		// emits) and lowercase (%3a, valid per RFC 3986 §2.1). The
		// replacement secret is escaped once on first hit and reused so
		// the cost stays linear in number-of-encoded-forms, not pairs.
		var encodedSecret []byte
		ensureEncodedSecret := func() {
			if encodedSecret != nil {
				return
			}
			if pathContext {
				encodedSecret = pathEscapeBytes(p.secret.Bytes())
			} else {
				encodedSecret = queryEscapeBytes(p.secret.Bytes())
			}
		}
		if len(p.encodedPhantom) > 0 && bytes.Contains(data, p.encodedPhantom) {
			ensureEncodedSecret()
			data = bytes.ReplaceAll(data, p.encodedPhantom, encodedSecret)
		}
		if len(p.encodedPhantomLower) > 0 && bytes.Contains(data, p.encodedPhantomLower) {
			ensureEncodedSecret()
			data = bytes.ReplaceAll(data, p.encodedPhantomLower, encodedSecret)
		}
	}
	if bytesContainsAnyPhantomPrefix(data) {
		data = stripUnboundPhantomsFromProvider(data, a.provider)
		log.Printf("[ADDON-INJECT] stripped unbound phantom token from %s for %s:%d", location, host, port)
	}
	return data
}

// swapPhantomHeaders performs Pass 2+3 on all request headers.
//
// Each pair is matched in both its literal and URL-encoded forms so phantom
// tokens carried in percent-encoded header values (custom cookie schemes,
// query-style header payloads) cannot bypass the swap.
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
				var encodedSecret []byte
				ensureEncodedSecret := func() {
					if encodedSecret == nil {
						encodedSecret = queryEscapeBytes(p.secret.Bytes())
					}
				}
				if len(p.encodedPhantom) > 0 && bytes.Contains(vb, p.encodedPhantom) {
					ensureEncodedSecret()
					vb = bytes.ReplaceAll(vb, p.encodedPhantom, encodedSecret)
					changed = true
				}
				if len(p.encodedPhantomLower) > 0 && bytes.Contains(vb, p.encodedPhantomLower) {
					ensureEncodedSecret()
					vb = bytes.ReplaceAll(vb, p.encodedPhantomLower, encodedSecret)
					changed = true
				}
			}
			if bytesContainsAnyPhantomPrefix(vb) {
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
//
// The result accounts for both literal phantom tokens (SLUICE_PHANTOM:name)
// and their URL-encoded forms (SLUICE_PHANTOM%3Aname). The encoded form is
// strictly longer because the colon expands to %3A, so a holdback sized for
// the literal form alone would lose URL-encoded phantoms that straddle a
// read boundary. Uses the precomputed encodedPhantom on each pair so no
// per-chunk allocation is required.
func maxPhantomLen(pairs []phantomPair) int {
	m := 0
	for _, p := range pairs {
		if len(p.phantom) > m {
			m = len(p.phantom)
		}
		if len(p.encodedPhantom) > m {
			m = len(p.encodedPhantom)
		}
		if len(p.encodedPhantomLower) > m {
			m = len(p.encodedPhantomLower)
		}
	}
	// Also account for the generic phantom prefix pattern. Uppercase and
	// lowercase encoded prefixes are the same length, so either works as
	// the lower bound.
	if pLen := len(urlEncodedPhantomPrefix) + maxCredNameLen; pLen > m {
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

		// Pass 2: scoped replacement, in both literal and URL-encoded forms
		// (both case variants of %3A). The encoded phantom is precomputed
		// once per pair so this hot path only allocates when an encoded
		// phantom is actually present and we need the encoded form of the
		// real secret.
		for _, pp := range r.pairs {
			if bytes.Contains(toProcess, pp.phantom) {
				toProcess = bytes.ReplaceAll(toProcess, pp.phantom, pp.secret.Bytes())
			}
			var encodedSecret []byte
			ensureEncodedSecret := func() {
				if encodedSecret == nil {
					encodedSecret = queryEscapeBytes(pp.secret.Bytes())
				}
			}
			if len(pp.encodedPhantom) > 0 && bytes.Contains(toProcess, pp.encodedPhantom) {
				ensureEncodedSecret()
				toProcess = bytes.ReplaceAll(toProcess, pp.encodedPhantom, encodedSecret)
			}
			if len(pp.encodedPhantomLower) > 0 && bytes.Contains(toProcess, pp.encodedPhantomLower) {
				ensureEncodedSecret()
				toProcess = bytes.ReplaceAll(toProcess, pp.encodedPhantomLower, encodedSecret)
			}
		}
		// Pass 3: strip unbound, including URL-encoded phantoms.
		if bytesContainsAnyPhantomPrefix(toProcess) {
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
