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
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/vault"
)

// maxQUICBody limits the request/response body size the QUIC proxy is willing
// to buffer. 128 MiB is generous for typical API traffic.
const maxQUICBody = 128 << 20

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

// QUICProxy terminates QUIC connections from the agent using sluice's CA
// certificate. It generates per-host TLS certificates based on the SNI
// from the TLS ClientHello, enabling HTTP/3 MITM credential injection.
type QUICProxy struct {
	caCert      tls.Certificate
	caX509      *x509.Certificate
	provider    vault.Provider
	resolver    *atomic.Pointer[vault.BindingResolver]
	audit       *audit.FileLogger
	blockRules  []quicBlockRule
	redactRules []quicRedactRule

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
	for _, cfg := range blockConfigs {
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile quic block pattern %q: %w", cfg.Name, err)
		}
		qp.blockRules = append(qp.blockRules, quicBlockRule{re: re, name: cfg.Name})
	}
	for _, cfg := range redactConfigs {
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile quic redact pattern %q: %w", cfg.Name, err)
		}
		qp.redactRules = append(qp.redactRules, quicRedactRule{re: re, replacement: cfg.Replacement, name: cfg.Name})
	}
	return qp, nil
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

// getConfigForClient returns a per-connection TLS config that generates a
// certificate matching the SNI from the ClientHello.
func (q *QUICProxy) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	host := hello.ServerName
	if host == "" {
		host = "localhost"
	}

	cert, err := GenerateHostCert(q.caCert, host)
	if err != nil {
		return nil, fmt.Errorf("generate cert for %s: %w", host, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, nil
}

// handleConnection processes a single accepted QUIC connection by serving
// HTTP/3 requests through a reverse-proxy handler that applies phantom token
// replacement in request headers/body, content inspection (deny/redact), and
// forwards to the real upstream via an HTTP/3 transport.
func (q *QUICProxy) handleConnection(conn *quic.Conn) {
	sni := conn.ConnectionState().TLS.ServerName
	log.Printf("[QUIC] accepted connection from %s (SNI: %s)", conn.RemoteAddr(), sni)

	handler := q.buildHandler(sni)
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
// to the response body before returning it to the agent.
func (q *QUICProxy) buildHandler(upstreamHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := upstreamHost
		if host == "" {
			host = r.Host
		}
		port := 443
		if r.URL.Port() != "" {
			if p, err := strconv.Atoi(r.URL.Port()); err == nil {
				port = p
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
			if binding, ok := res.ResolveForProtocol(host, port, "quic"); ok {
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
			reqBody, readErr = io.ReadAll(io.LimitReader(r.Body, maxQUICBody))
			_ = r.Body.Close()
			if readErr != nil {
				http.Error(w, "request body read error", http.StatusBadGateway)
				return
			}
		}

		// Check content deny rules BEFORE phantom replacement so patterns
		// never run against decrypted credentials.
		for _, rule := range q.blockRules {
			if rule.re.Match(reqBody) {
				q.logAudit(host, port, "deny", fmt.Sprintf("blocked by content rule %q", rule.name))
				http.Error(w, "blocked by content policy", http.StatusForbidden)
				return
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
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxQUICBody))
		if err != nil {
			http.Error(w, "upstream response read error", http.StatusBadGateway)
			return
		}

		// Apply redact rules to response body.
		for _, rule := range q.redactRules {
			respBody = rule.re.ReplaceAll(respBody, []byte(rule.replacement))
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
		for _, name := range res.CredentialsForDestination(host, port, "quic") {
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
		Protocol:    "quic",
		Verdict:     verdict,
		Reason:      reason,
	}); err != nil {
		log.Printf("audit log write error: %v", err)
	}
}

