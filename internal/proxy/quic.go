package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/vault"
)

// maxQUICBody limits the request/response body size the QUIC proxy is willing
// to buffer. 16 MiB is sufficient for typical API traffic while preventing
// memory exhaustion from concurrent large requests.
const maxQUICBody = 16 << 20

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
type expectedDest struct {
	host string
	port int
}

// QUICProxy terminates QUIC connections from the agent using sluice's CA
// certificate. It generates per-host TLS certificates based on the SNI
// from the TLS ClientHello, enabling HTTP/3 MITM credential injection.
type QUICProxy struct {
	caCert   tls.Certificate
	caX509   *x509.Certificate
	provider vault.Provider
	resolver *atomic.Pointer[vault.BindingResolver]
	audit    *audit.FileLogger
	rules    atomic.Pointer[quicInspectRules]

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

// NewQUICProxy creates a QUIC proxy that terminates agent QUIC connections.
// The caCert is used to sign per-host TLS certificates derived from the SNI.
// Block rules cause requests with matching body content to be rejected.
// Redact rules sanitize matching patterns in response bodies before forwarding
// to the agent.
func NewQUICProxy(
	caCert tls.Certificate,
	provider vault.Provider,
	resolver *atomic.Pointer[vault.BindingResolver],
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
		caCert:   caCert,
		caX509:   caX509,
		provider: provider,
		resolver: resolver,
		audit:    auditLog,
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
		ln.Close()
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
func (q *QUICProxy) RegisterExpectedHost(srcAddr string, host string, port int) {
	q.expectedDests.Store(srcAddr, expectedDest{host: host, port: port})
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
			t.Close()
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
		t.Close()
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

	handler := q.buildHandler(sni, dest.port)
	srv := &http3.Server{
		Handler: handler,
	}
	if err := srv.ServeQUICConn(conn); err != nil && err != http.ErrServerClosed {
		log.Printf("[QUIC] serve error for %s: %v", sni, err)
	}
}

// buildHandler returns an http.Handler that proxies HTTP/3 requests to the
// given upstream host. It applies phantom token replacement in request
// headers and body, checks content deny rules, and applies redact rules
// to the response body before returning it to the agent. The destPort is
// the SOCKS5 destination port that was policy-checked, used for credential
// binding resolution instead of trusting the URL port from the request.
func (q *QUICProxy) buildHandler(upstreamHost string, destPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := upstreamHost
		if host == "" {
			host = r.Host
		}
		port := destPort

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
				secret, err := q.provider.Get(binding.Credential)
				if err != nil {
					log.Printf("[QUIC-MITM] credential %q lookup failed: %v", binding.Credential, err)
				} else {
					if binding.Header != "" {
						r.Header.Set(binding.Header, binding.FormatValue(secret.String()))
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
			reqBody, readErr = io.ReadAll(io.LimitReader(r.Body, maxQUICBody+1))
			_ = r.Body.Close()
			if readErr != nil {
				http.Error(w, "request body read error", http.StatusBadGateway)
				return
			}
			if int64(len(reqBody)) > maxQUICBody {
				log.Printf("[QUIC] request body exceeds %d bytes for %s:%d, rejecting", maxQUICBody, host, port)
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
		defer resp.Body.Close()

		// Read upstream response body for redaction.
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxQUICBody+1))
		if err != nil {
			http.Error(w, "upstream response read error", http.StatusBadGateway)
			return
		}
		if int64(len(respBody)) > maxQUICBody {
			log.Printf("[QUIC] response body exceeds %d bytes from %s:%d, rejecting", maxQUICBody, host, port)
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

// buildPhantomPairs resolves credentials bound to the destination and returns
// phantom/secret pairs sorted by phantom length descending.
func (q *QUICProxy) buildPhantomPairs(host string, port int) []phantomPair {
	var pairs []phantomPair
	if res := q.resolver.Load(); res != nil {
		for _, name := range res.CredentialsForDestination(host, port, ProtoQUIC.String()) {
			secret, err := q.provider.Get(name)
			if err != nil {
				log.Printf("[QUIC-MITM] credential %q lookup failed: %v", name, err)
				continue
			}
			pairs = append(pairs, phantomPair{
				phantom: []byte(PhantomToken(name)),
				secret:  secret,
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
			}
			if bytes.Contains(vb, phantomPrefix) {
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
// credential values and strips any unbound phantom tokens.
func (q *QUICProxy) replacePhantomInBody(body []byte, pairs []phantomPair, host string, port int) []byte {
	for _, p := range pairs {
		if bytes.Contains(body, p.phantom) {
			body = bytes.ReplaceAll(body, p.phantom, p.secret.Bytes())
		}
	}
	if bytes.Contains(body, phantomPrefix) {
		body = q.stripUnboundPhantoms(body)
		log.Printf("[QUIC-MITM] stripped unbound phantom from body for %s:%d", host, port)
	}
	return body
}

// stripUnboundPhantoms removes phantom tokens not bound to the destination.
func (q *QUICProxy) stripUnboundPhantoms(data []byte) []byte {
	names, _ := q.provider.List()
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j])
	})
	for _, name := range names {
		phantom := []byte(PhantomToken(name))
		if bytes.Contains(data, phantom) {
			data = bytes.ReplaceAll(data, phantom, nil)
		}
	}
	if bytes.Contains(data, phantomPrefix) {
		data = phantomStripRe.ReplaceAll(data, nil)
	}
	return data
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

