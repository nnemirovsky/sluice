package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/vault"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QUICBlockRuleConfig defines a content deny rule for QUICProxy construction.
type QUICBlockRuleConfig struct {
	Pattern string
	Name    string
}

// QUICRedactRuleConfig defines a content redact rule for QUICProxy construction.
type QUICRedactRuleConfig struct {
	Pattern     string
	Replacement string
	Name        string
}

type quicBlockRule struct {
	re   *regexp.Regexp
	name string
}

type quicRedactRule struct {
	re          *regexp.Regexp
	replacement string
	name        string
}

// quicInspectRules holds compiled content inspection rules for atomic swap.
type quicInspectRules struct {
	block  []quicBlockRule
	redact []quicRedactRule
}

// expectedDest holds the SOCKS5 destination that was policy-checked so the
// QUIC proxy can verify SNI and use the correct port for credential resolution.
// When checker is non-nil, each HTTP/3 request is evaluated via
// CheckAndConsume before forwarding (ask-rule path). A nil checker means the
// session was explicitly allowed at the UDP dispatch layer (fast path).
type expectedDest struct {
	host    string
	port    int
	checker *RequestPolicyChecker
}

// QUICProxy terminates QUIC connections from the agent using sluice's CA
// certificate. It generates per-host TLS certificates based on the SNI
// from the TLS ClientHello, enabling HTTP/3 MITM credential injection.
type QUICProxy struct {
	caCert   tls.Certificate
	caX509   *x509.Certificate
	provider vault.Provider
	resolver *atomic.Pointer[vault.BindingResolver]
	// poolResolver expands a binding that NAMES A POOL to the pool's
	// active member before the vault lookup, mirroring the HTTP-MITM
	// chokepoint (SluiceAddon.resolveInjectionTarget). Without it a
	// pool-named binding would call provider.Get(<pool>) — there is no
	// vault secret stored under a pool name — and injection would fail
	// for that destination over QUIC (Finding 2). Optional: nil means
	// no pools are configured and every binding name is taken verbatim.
	//
	// QUIC pool support is intentionally limited to active-member
	// expansion. The per-request OAuth refresh attribution (Risk R1),
	// pool-stable phantom keying (Risk R3), and 429/401 auto-failover
	// implemented in the HTTP-MITM addon are NOT replicated here: the
	// QUIC injection path is a simpler buffered header/body swap with
	// no response-side OAuth interception. A pool binding over QUIC
	// injects the CURRENT active member's real credential; member
	// rotation happens only when the HTTP path (or an operator) flips
	// the active member. See CLAUDE.md "Credential pools" for the
	// authoritative HTTP-vs-QUIC capability matrix.
	poolResolver *atomic.Pointer[vault.PoolResolver]
	audit        *audit.FileLogger
	rules        atomic.Pointer[quicInspectRules]

	// oauthIndex points at the same OAuthIndex the SluiceAddon uses
	// so QUIC/HTTP3 header injection follows the same OAuth-vs-static
	// dispatch rules as the HTTP/1+2 path. Optional: a nil index means
	// every credential is treated as static (the right answer when no
	// oauth credentials are registered). Updated atomically via
	// SetOAuthIndex from Server.UpdateOAuthIndex.
	oauthIndex atomic.Pointer[OAuthIndex]

	// upstreamTLSConfig overrides the TLS configuration for outbound HTTP/3
	// connections to real upstreams. Nil uses system roots. Tests set this
	// to trust the test CA.
	upstreamTLSConfig *tls.Config
	// upstreamDial overrides the QUIC dial function for outbound connections.
	// Nil uses the default dial. Tests set this to redirect to a local upstream.
	upstreamDial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)

	// transports caches HTTP/3 transports per upstream host so that multiple
	// requests to the same host reuse one QUIC connection instead of opening
	// a new connection (and performing a full TLS handshake) per request.
	transports sync.Map // map[string]*http3.Transport

	// certCache caches per-host TLS certificates so that repeated QUIC
	// connections to the same host reuse an already-generated certificate
	// instead of performing expensive ECDSA key generation and signing on
	// every connection. Certificates have 24h validity, and the cache is
	// never evicted (host cardinality is bounded by policy allow rules).
	certCache sync.Map // map[string]tls.Certificate

	// expectedDests maps UDP source addresses to the SOCKS5 destination
	// (host + port) that was policy-checked. handleConnection verifies
	// the TLS SNI matches the expected host, and buildHandler uses the
	// policy-checked port for credential resolution rather than trusting
	// the URL port from the HTTP/3 request.
	expectedDests sync.Map // map[string]expectedDest

	// mu protects listener lifecycle.
	mu       sync.Mutex
	listener *quic.Listener
	addr     net.Addr
	closed   bool
}

// SetOAuthIndex atomically replaces the QUIC proxy's OAuth index. The
// addon and the QUIC proxy each hold their own pointer so concurrent
// header-injection paths can read without locking; both are kept in
// sync from Server.UpdateOAuthIndex.
func (q *QUICProxy) SetOAuthIndex(idx *OAuthIndex) {
	q.oauthIndex.Store(idx)
}

// NewQUICProxy creates a QUIC proxy that terminates agent QUIC connections.
// The caCert is used to sign per-host TLS certificates derived from the SNI.
// Block rules cause requests with matching body content to be rejected.
// Redact rules sanitize matching patterns in response bodies before forwarding
// to the agent.
func NewQUICProxy(
	caCert tls.Certificate,
	provider vault.Provider,
	resolver *atomic.Pointer[vault.BindingResolver],
	poolResolver *atomic.Pointer[vault.PoolResolver],
	auditLog *audit.FileLogger,
	blockConfigs []QUICBlockRuleConfig,
	redactConfigs []QUICRedactRuleConfig,
) (*QUICProxy, error) {
	caX509 := caCert.Leaf
	if caX509 == nil {
		var err error
		caX509, err = x509.ParseCertificate(caCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse CA cert: %w", err)
		}
	}
	qp := &QUICProxy{
		caCert:       caCert,
		caX509:       caX509,
		provider:     provider,
		resolver:     resolver,
		poolResolver: poolResolver,
		audit:        auditLog,
	}
	if err := qp.UpdateRules(blockConfigs, redactConfigs); err != nil {
		return nil, err
	}
	return qp, nil
}

// UpdateRules compiles new content inspection rules and atomically swaps them
// in. This is safe to call while handleConnection goroutines are running.
func (q *QUICProxy) UpdateRules(blockConfigs []QUICBlockRuleConfig, redactConfigs []QUICRedactRuleConfig) error {
	rules := &quicInspectRules{}
	for _, cfg := range blockConfigs {
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return fmt.Errorf("compile quic block pattern %q: %w", cfg.Name, err)
		}
		rules.block = append(rules.block, quicBlockRule{re: re, name: cfg.Name})
	}
	for _, cfg := range redactConfigs {
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return fmt.Errorf("compile quic redact pattern %q: %w", cfg.Name, err)
		}
		rules.redact = append(rules.redact, quicRedactRule{re: re, replacement: cfg.Replacement, name: cfg.Name})
	}
	q.rules.Store(rules)
	return nil
}

// ListenAndServe starts the QUIC listener on the given UDP address and
// accepts connections. It blocks until Close is called or an unrecoverable
// error occurs.
func (q *QUICProxy) ListenAndServe(addr string) error {
	tlsCfg := &tls.Config{
		GetConfigForClient: q.getConfigForClient,
		NextProtos:         []string{"h3"},
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{})
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}

	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("quic proxy already closed")
	}
	q.listener = ln
	q.addr = ln.Addr()
	q.mu.Unlock()

	log.Printf("[QUIC] listening on %s", ln.Addr())
	for {
		conn, acceptErr := ln.Accept(context.Background())
		if acceptErr != nil {
			q.mu.Lock()
			closed := q.closed
			q.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("quic accept: %w", acceptErr)
		}
		go q.handleConnection(conn)
	}
}

// Addr returns the local address the QUIC proxy is listening on.
// Returns nil if not yet listening.
func (q *QUICProxy) Addr() net.Addr {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.addr
}

// RegisterExpectedHost records that packets arriving from srcAddr should
// have a TLS SNI matching host. The port is the SOCKS5 destination port
// used for policy evaluation and credential binding resolution.
// Must be called before forwarding QUIC packets so handleConnection can
// verify the SNI against the SOCKS5 destination that was policy-checked.
//
// This is the fast path for explicit allow rule matches (no per-request
// policy check). Use RegisterExpectedHostWithChecker for ask-rule matches
// that require per-HTTP/3-request approval.
func (q *QUICProxy) RegisterExpectedHost(srcAddr string, host string, port int) {
	q.expectedDests.Store(srcAddr, expectedDest{host: host, port: port})
}

// RegisterExpectedHostWithChecker is like RegisterExpectedHost but attaches
// a RequestPolicyChecker that buildHandler calls before forwarding each
// HTTP/3 request. Used when EvaluateQUICDetailed returns Ask so each
// request on the QUIC session goes through per-request approval.
func (q *QUICProxy) RegisterExpectedHostWithChecker(srcAddr string, host string, port int, checker *RequestPolicyChecker) {
	q.expectedDests.Store(srcAddr, expectedDest{host: host, port: port, checker: checker})
}

// UnregisterExpectedHost removes the expected host mapping for srcAddr.
func (q *QUICProxy) UnregisterExpectedHost(srcAddr string) {
	q.expectedDests.Delete(srcAddr)
}

// Close shuts down the QUIC listener and all cached upstream transports.
func (q *QUICProxy) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.transports.Range(func(key, value any) bool {
		if t, ok := value.(*http3.Transport); ok {
			_ = t.Close()
		}
		q.transports.Delete(key)
		return true
	})
	if q.listener != nil {
		return q.listener.Close()
	}
	return nil
}

// getOrCreateTransport returns a cached HTTP/3 transport for the given host,
// creating one if it does not already exist. This avoids a full QUIC+TLS
// handshake per request when multiple requests target the same upstream.
func (q *QUICProxy) getOrCreateTransport(host string) *http3.Transport {
	if v, ok := q.transports.Load(host); ok {
		return v.(*http3.Transport)
	}
	tlsCfg := &tls.Config{
		ServerName: host,
	}
	if q.upstreamTLSConfig != nil {
		tlsCfg = q.upstreamTLSConfig.Clone()
		tlsCfg.ServerName = host
	}
	t := &http3.Transport{
		TLSClientConfig: tlsCfg,
		Dial:            q.upstreamDial,
	}
	if existing, loaded := q.transports.LoadOrStore(host, t); loaded {
		_ = t.Close()
		return existing.(*http3.Transport)
	}
	return t
}

// getConfigForClient returns a per-connection TLS config with a certificate
// matching the SNI from the ClientHello. Certificates are cached per host so
// that repeated connections avoid expensive ECDSA key generation.
func (q *QUICProxy) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	host := hello.ServerName
	if host == "" {
		host = "localhost"
	}

	cert, err := q.getOrCreateCert(host)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, nil
}

// getOrCreateCert returns a cached TLS certificate for the host, generating
// one if it does not already exist in the cache.
func (q *QUICProxy) getOrCreateCert(host string) (tls.Certificate, error) {
	if v, ok := q.certCache.Load(host); ok {
		return v.(tls.Certificate), nil
	}
	cert, err := GenerateHostCert(q.caCert, host)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate cert for %s: %w", host, err)
	}
	// Store-or-load to handle concurrent generation for the same host.
	if existing, loaded := q.certCache.LoadOrStore(host, cert); loaded {
		return existing.(tls.Certificate), nil
	}
	return cert, nil
}

// handleConnection processes a single accepted QUIC connection by serving
// HTTP/3 requests through a reverse-proxy handler that applies phantom token
// replacement in request headers/body, content inspection (deny/redact), and
// forwards to the real upstream via an HTTP/3 transport.
func (q *QUICProxy) handleConnection(conn *quic.Conn) {
	sni := conn.ConnectionState().TLS.ServerName
	remoteKey := conn.RemoteAddr().String()
	log.Printf("[QUIC] accepted connection from %s (SNI: %s)", remoteKey, sni)

	// Look up the SOCKS5 destination that was policy-checked for this source.
	// Reject connections with no registered expected host to prevent direct
	// connections to the loopback QUIC listener from bypassing policy.
	expected, ok := q.expectedDests.Load(remoteKey)
	if !ok {
		log.Printf("[QUIC] no expected destination for %s, rejecting", remoteKey)
		if err := conn.CloseWithError(0x01, "no expected destination"); err != nil {
			log.Printf("[QUIC] close error: %v", err)
		}
		return
	}
	dest := expected.(expectedDest)

	// Verify the TLS SNI matches the SOCKS5 destination that was
	// policy-checked. Without this check, an agent could send QUIC packets
	// to an allowed destination but set the SNI to a different host,
	// bypassing policy and potentially exfiltrating credentials.
	if sni != dest.host {
		log.Printf("[QUIC] SNI mismatch: expected %q, got %q from %s", dest.host, sni, remoteKey)
		if err := conn.CloseWithError(0x01, "SNI mismatch"); err != nil {
			log.Printf("[QUIC] close error: %v", err)
		}
		return
	}

	handler := q.buildHandler(sni, dest.port, dest.checker)
	srv := &http3.Server{
		Handler: handler,
	}
	if err := srv.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[QUIC] serve error for %s: %v", sni, err)
	}
}

// buildHandler returns an http.Handler that proxies HTTP/3 requests to the
// given upstream host. It applies phantom token replacement in request
// headers and body, checks content deny rules, and applies redact rules
// to the response body before returning it to the agent. The destPort is
// the SOCKS5 destination port that was policy-checked, used for credential
// binding resolution instead of trusting the URL port from the request.
//
// When checker is non-nil (ask-rule path), each HTTP/3 request is evaluated
// via CheckAndConsume before forwarding. Denied requests return 403. A nil
// checker means the session was explicitly allowed and no per-request check
// is needed.
func (q *QUICProxy) buildHandler(upstreamHost string, destPort int, checker *RequestPolicyChecker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := upstreamHost
		if host == "" {
			host = r.Host
		}
		port := destPort

		// Per-request policy check for ask-rule sessions.
		if checker != nil {
			verdict, err := checker.CheckAndConsume(
				host, port,
				WithRequestInfo(r.Method, r.URL.RequestURI()),
				WithProtocol(ProtoQUIC.String()),
				WithSkipBrokerRateLimit(),
			)
			if err != nil || verdict != policy.Allow {
				q.logAudit(host, port, "deny", fmt.Sprintf("per-request policy denied (%s %s)", r.Method, r.URL.RequestURI()))
				http.Error(w, "blocked by per-request policy", http.StatusForbidden)
				return
			}
		}

		// Build phantom token pairs for credentials bound to this destination.
		pairs := q.buildPhantomPairs(host, port)
		defer func() {
			for i := range pairs {
				pairs[i].secret.Release()
			}
		}()

		// Binding-specific header injection.
		if res := q.resolver.Load(); res != nil {
			if binding, ok := res.ResolveForProtocol(host, port, ProtoQUIC.String()); ok {
				// Finding 2: a binding may name a pool. Expand to the
				// active member before the vault lookup AND before the
				// OAuth-envelope decision (extractInjectableSecret keys
				// off credential_meta, which has no entry for a pool
				// name), exactly as the HTTP-MITM chokepoint does.
				secretName := q.resolvePoolMember(binding.Credential)
				secret, err := q.provider.Get(secretName)
				if err != nil {
					log.Printf("[QUIC-MITM] credential %q lookup failed: %v", secretName, err)
				} else {
					if binding.Header != "" {
						r.Header.Set(binding.Header, binding.FormatValue(extractInjectableSecret(q.oauthIndex.Load(), secretName, secret.String())))
					}
					secret.Release()
				}
			}
		}

		// Replace phantom tokens in request headers.
		q.replacePhantomInHeaders(r, pairs, host, port)

		// Read and process request body.
		var reqBody []byte
		if r.Body != nil && r.Body != http.NoBody {
			var readErr error
			reqBody, readErr = io.ReadAll(io.LimitReader(r.Body, maxProxyBody+1))
			_ = r.Body.Close()
			if readErr != nil {
				http.Error(w, "request body read error", http.StatusBadGateway)
				return
			}
			if int64(len(reqBody)) > maxProxyBody {
				log.Printf("[QUIC] request body exceeds %d bytes for %s:%d, rejecting", maxProxyBody, host, port)
				http.Error(w, "request body exceeds proxy limit", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// Check content deny rules BEFORE phantom replacement so patterns
		// never run against decrypted credentials. Rules are loaded
		// atomically so SIGHUP-reloaded rules take effect immediately.
		rules := q.rules.Load()
		if rules != nil {
			for _, rule := range rules.block {
				if rule.re.Match(reqBody) {
					q.logAudit(host, port, "deny", fmt.Sprintf("blocked by content rule %q", rule.name))
					http.Error(w, "blocked by content policy", http.StatusForbidden)
					return
				}
			}
		}

		// Replace phantom tokens with real credentials after deny check.
		if len(reqBody) > 0 {
			reqBody = q.replacePhantomInBody(reqBody, pairs, host, port)
		}

		// Build upstream request URL.
		upstreamURL := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())

		var bodyReader io.Reader
		if reqBody != nil {
			bodyReader = bytes.NewReader(reqBody)
		}
		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bodyReader)
		if err != nil {
			http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
			return
		}

		// Copy request headers to upstream.
		for key, vals := range r.Header {
			for _, v := range vals {
				upReq.Header.Add(key, v)
			}
		}
		if reqBody != nil {
			upReq.ContentLength = int64(len(reqBody))
		}

		// Forward to upstream via HTTP/3 using a cached transport per host
		// to avoid a full QUIC+TLS handshake on every request.
		transport := q.getOrCreateTransport(host)

		resp, err := transport.RoundTrip(upReq)
		if err != nil {
			q.logAudit(host, port, "allow", fmt.Sprintf("upstream error: %v", err))
			http.Error(w, "upstream request failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		// Read upstream response body for redaction.
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody+1))
		if err != nil {
			http.Error(w, "upstream response read error", http.StatusBadGateway)
			return
		}
		if int64(len(respBody)) > maxProxyBody {
			log.Printf("[QUIC] response body exceeds %d bytes from %s:%d, rejecting", maxProxyBody, host, port)
			http.Error(w, "upstream response exceeds proxy limit", http.StatusBadGateway)
			return
		}

		// Apply redact rules to response body. Reload atomically in case
		// rules were updated via SIGHUP since the block check above.
		rules = q.rules.Load()
		if rules != nil {
			for _, rule := range rules.redact {
				respBody = rule.re.ReplaceAll(respBody, []byte(rule.replacement))
			}
		}

		// Copy response headers.
		for key, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
		// Update content-length to reflect redacted body.
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)

		q.logAudit(host, port, "allow", "")
	})
}

// resolvePoolMember expands a binding name that NAMES A POOL to the pool's
// current active member, mirroring SluiceAddon.resolveInjectionTarget on the
// HTTP-MITM path (Finding 2). A plain credential name (or any name when no
// pool resolver is configured) is returned verbatim. An empty or
// unresolvable pool returns the pool name unchanged so the downstream
// provider.Get fails cleanly (no injection) rather than panicking.
//
// QUIC-LIMITED: this performs ONLY active-member expansion. The HTTP path's
// per-request refresh attribution (R1), pool-stable phantom (R3), and
// 429/401 auto-failover are not implemented on QUIC; the active member is
// whatever the HTTP path / operator last selected. Documented in CLAUDE.md.
func (q *QUICProxy) resolvePoolMember(name string) string {
	if q.poolResolver == nil {
		return name
	}
	pr := q.poolResolver.Load()
	if pr == nil || !pr.IsPool(name) {
		return name
	}
	member, ok := pr.ResolveActive(name)
	if !ok || member == "" {
		return name
	}
	return member
}

// resolvePoolTarget classifies a binding name. When name is a configured
// pool, isPool is true and member is the pool's current active member (or
// "" when the pool is empty/unresolvable). For a plain credential (or when
// no pool resolver is configured) isPool is false and member == name.
//
// Finding 1 (R3 on QUIC): this is the QUIC analogue of
// SluiceAddon.resolveInjectionTarget. It is required so the QUIC OAuth path
// can route a pooled binding through buildPooledOAuthPhantomPairs — which
// keys the agent-facing access phantom on the POOL name (a pool-stable
// synthetic JWT) rather than re-signing the active member's real JWT. The
// latter changes the agent-held phantom on every member switch, violating
// the R3 pool-stable access-token guarantee. Only phantom stability +
// active-member-secret selection is replicated on QUIC; the documented QUIC
// limitation (no response-side R1 attribution, no 429/401 failover) stands.
func (q *QUICProxy) resolvePoolTarget(name string) (member string, isPool bool) {
	if q.poolResolver == nil {
		return name, false
	}
	pr := q.poolResolver.Load()
	if pr == nil || !pr.IsPool(name) {
		return name, false
	}
	m, ok := pr.ResolveActive(name)
	if !ok || m == "" {
		// Empty/unresolvable pool: keep the pool name so the caller's
		// provider.Get fails cleanly (no injection) instead of panicking.
		return "", true
	}
	return m, true
}

// buildPhantomPairs resolves credentials bound to the destination and returns
// phantom/secret pairs sorted by phantom length descending.
//
// TODO: this duplicates SluiceAddon.buildPhantomPairs in addon.go. The two
// implementations use different receiver types (QUICProxy uses vault.BindingResolver
// directly, SluiceAddon uses atomic.Pointer). Consolidating requires a shared
// abstraction which is premature while the two code paths diverge on
// protocol-specific details (HTTP/1-2 streaming vs HTTP/3 buffered).
func (q *QUICProxy) buildPhantomPairs(host string, port int) []phantomPair {
	var pairs []phantomPair
	if res := q.resolver.Load(); res != nil {
		for _, boundName := range res.CredentialsForDestination(host, port, ProtoQUIC.String()) {
			// Finding 1/2: classify the binding. A pooled binding
			// resolves to its active member for the vault lookup, but
			// the agent-facing phantom MUST stay keyed on the POOL name
			// so it is byte-identical across member switches (R3).
			member, isPool := q.resolvePoolTarget(boundName)
			secretName := member
			if isPool && member == "" {
				// Empty/unresolvable pool: keep the pool name so the
				// provider.Get below fails cleanly (no injection).
				secretName = boundName
			}
			secret, err := q.provider.Get(secretName)
			if err != nil {
				log.Printf("[QUIC-MITM] credential %q lookup failed: %v", secretName, err)
				continue
			}
			// Check if this is an OAuth credential. If so, build two phantom
			// pairs (access + refresh) instead of one static pair.
			if vault.IsOAuth(secret.Bytes()) {
				var oauthPairs []phantomPair
				var parseErr error
				if isPool {
					// Finding 1 (R3 on QUIC): pool-stable synthetic-JWT
					// access phantom keyed on the POOL name, refresh
					// phantom is the deterministic SLUICE_PHANTOM:<pool>
					// .refresh string, secrets are the ACTIVE member's
					// real tokens. Byte-identical to the HTTP path so the
					// agent-held phantom never changes on a member switch.
					// onRefreshInject is nil: QUIC has no response-side
					// R1 attribution (documented limitation).
					oauthPairs, parseErr = buildPooledOAuthPhantomPairs(
						boundName, secretName, secret, "QUIC-MITM", nil,
					)
				} else {
					oauthPairs, parseErr = buildOAuthPhantomPairs(boundName, secret, "QUIC-MITM")
				}
				if parseErr != nil {
					continue
				}
				pairs = append(pairs, oauthPairs...)
				continue
			}
			phantom := []byte(PhantomToken(boundName))
			encoded := encodePhantomForPair(phantom)
			pairs = append(pairs, phantomPair{
				phantom:             phantom,
				encodedPhantom:      encoded,
				encodedPhantomLower: encodePhantomLowerForPair(encoded),
				secret:              secret,
			})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].phantom) > len(pairs[j].phantom)
	})
	return pairs
}

// replacePhantomInHeaders replaces phantom tokens in HTTP request headers
// with real credential values and strips any unbound phantom tokens.
func (q *QUICProxy) replacePhantomInHeaders(r *http.Request, pairs []phantomPair, host string, port int) {
	for key, vals := range r.Header {
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
				vb = q.stripUnboundPhantoms(vb)
				changed = true
				log.Printf("[QUIC-MITM] stripped unbound phantom from header %q for %s:%d", key, host, port)
			}
			if changed {
				r.Header[key][i] = string(vb)
			}
		}
	}
}

// replacePhantomInBody replaces phantom tokens in a request body with real
// credential values and strips any unbound phantom tokens. Matches both
// the literal SLUICE_PHANTOM:<name> form and the URL-encoded
// SLUICE_PHANTOM%3A<name> form (uppercase and lowercase hex) so that
// HTTP/3 form-urlencoded OAuth refreshes route through the same swap as
// HTTP/1.x and HTTP/2.
func (q *QUICProxy) replacePhantomInBody(body []byte, pairs []phantomPair, host string, port int) []byte {
	for _, p := range pairs {
		if bytes.Contains(body, p.phantom) {
			body = bytes.ReplaceAll(body, p.phantom, p.secret.Bytes())
		}
		var encodedSecret []byte
		ensureEncodedSecret := func() {
			if encodedSecret == nil {
				encodedSecret = queryEscapeBytes(p.secret.Bytes())
			}
		}
		if len(p.encodedPhantom) > 0 && bytes.Contains(body, p.encodedPhantom) {
			ensureEncodedSecret()
			body = bytes.ReplaceAll(body, p.encodedPhantom, encodedSecret)
		}
		if len(p.encodedPhantomLower) > 0 && bytes.Contains(body, p.encodedPhantomLower) {
			ensureEncodedSecret()
			body = bytes.ReplaceAll(body, p.encodedPhantomLower, encodedSecret)
		}
	}
	if bytesContainsAnyPhantomPrefix(body) {
		body = q.stripUnboundPhantoms(body)
		log.Printf("[QUIC-MITM] stripped unbound phantom from body for %s:%d", host, port)
	}
	return body
}

// stripUnboundPhantoms removes phantom tokens not bound to the destination.
// Delegates to the shared helper.
func (q *QUICProxy) stripUnboundPhantoms(data []byte) []byte {
	return stripUnboundPhantomsFromProvider(data, q.provider)
}

// logAudit writes an audit event for an HTTP/3 request if the audit logger
// is configured.
func (q *QUICProxy) logAudit(host string, port int, verdict, reason string) {
	if q.audit == nil {
		return
	}
	if err := q.audit.Log(audit.Event{
		Destination: host,
		Port:        port,
		Protocol:    ProtoQUIC.String(),
		Verdict:     verdict,
		Reason:      reason,
	}); err != nil {
		log.Printf("audit log write error: %v", err)
	}
}
