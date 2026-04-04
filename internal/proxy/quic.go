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

// Close shuts down the QUIC listener.
func (q *QUICProxy) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	if q.listener != nil {
		return q.listener.Close()
	}
	return nil
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
			if p, err := fmt.Sscanf(r.URL.Port(), "%d", &port); p == 0 || err != nil {
				port = 443
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
			reqBody, readErr = io.ReadAll(r.Body)
			_ = r.Body.Close()
			if readErr != nil {
				http.Error(w, "request body read error", http.StatusBadGateway)
				return
			}
			reqBody = q.replacePhantomInBody(reqBody, pairs, host, port)
		}

		// Check content deny rules on request body.
		for _, rule := range q.blockRules {
			if rule.re.Match(reqBody) {
				q.logAudit(host, port, "deny", fmt.Sprintf("blocked by content rule %q", rule.name))
				http.Error(w, "blocked by content policy", http.StatusForbidden)
				return
			}
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

		// Forward to upstream via HTTP/3.
		tlsCfg := &tls.Config{
			ServerName: host,
		}
		if q.upstreamTLSConfig != nil {
			tlsCfg = q.upstreamTLSConfig.Clone()
			tlsCfg.ServerName = host
		}
		transport := &http3.Transport{
			TLSClientConfig: tlsCfg,
			Dial:            q.upstreamDial,
		}
		defer transport.Close()

		resp, err := transport.RoundTrip(upReq)
		if err != nil {
			q.logAudit(host, port, "allow", fmt.Sprintf("upstream error: %v", err))
			http.Error(w, "upstream request failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Read upstream response body for redaction.
		respBody, err := io.ReadAll(resp.Body)
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

// ExtractSNI extracts the Server Name Indication from a QUIC Initial packet
// by parsing the TLS ClientHello embedded in the CRYPTO frame. This is used
// for logging and routing before the QUIC handshake completes.
//
// The function parses the minimal QUIC long header structure to reach the
// TLS payload. Returns empty string if the packet cannot be parsed.
func ExtractSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// Must be a long header (form bit set).
	if data[0]&0x80 == 0 {
		return ""
	}

	offset := 5 // skip first byte + 4-byte version

	// DCID length + DCID
	if offset >= len(data) {
		return ""
	}
	dcidLen := int(data[offset])
	offset += 1 + dcidLen

	// SCID length + SCID
	if offset >= len(data) {
		return ""
	}
	scidLen := int(data[offset])
	offset += 1 + scidLen

	// Token length (variable-length integer)
	if offset >= len(data) {
		return ""
	}
	tokenLen, tokenLenSize := decodeVarInt(data[offset:])
	if tokenLenSize == 0 {
		return ""
	}
	offset += tokenLenSize + int(tokenLen)

	// Packet length (variable-length integer)
	if offset >= len(data) {
		return ""
	}
	_, pktLenSize := decodeVarInt(data[offset:])
	if pktLenSize == 0 {
		return ""
	}
	offset += pktLenSize

	// The rest is encrypted packet number + payload. We cannot decrypt it
	// without knowing the initial keys derived from the DCID.
	// For SNI extraction before handshake we need to derive QUIC initial
	// secrets, which is complex. Return empty for now.
	// The TLS ClientHello SNI is available after the handshake via
	// GetConfigForClient, which is the primary extraction path.
	_ = offset
	return ""
}

// decodeVarInt decodes a QUIC variable-length integer (RFC 9000, Section 16).
// Returns the value and the number of bytes consumed. Returns 0,0 on error.
func decodeVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	prefix := data[0] >> 6
	length := 1 << prefix
	if len(data) < length {
		return 0, 0
	}
	var val uint64
	switch length {
	case 1:
		val = uint64(data[0] & 0x3F)
	case 2:
		val = uint64(data[0]&0x3F)<<8 | uint64(data[1])
	case 4:
		val = uint64(data[0]&0x3F)<<24 | uint64(data[1])<<16 |
			uint64(data[2])<<8 | uint64(data[3])
	case 8:
		val = uint64(data[0]&0x3F)<<56 | uint64(data[1])<<48 |
			uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 |
			uint64(data[6])<<8 | uint64(data[7])
	}
	return val, length
}
