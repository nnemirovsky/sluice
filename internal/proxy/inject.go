package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/nemirovsky/sluice/internal/vault"
)

// maxMITMBody limits the request body size the HTTPS MITM proxy reads for
// phantom token replacement. Matches the QUIC proxy limit (16 MiB).
const maxMITMBody = 16 << 20

// phantomPrefix is the byte prefix for all phantom tokens, used for quick
// detection before applying the more expensive regex strip.
var phantomPrefix = []byte("SLUICE_PHANTOM:")

// phantomStripRe is a last-resort regex for stripping phantom tokens when
// provider.List() cannot enumerate all credential names. It matches word
// characters, dots, and hyphens.
// The primary strip path uses exact matching via provider.List().
var phantomStripRe = regexp.MustCompile(`SLUICE_PHANTOM:[\w.\-]+`)

// PhantomToken returns the placeholder token for a credential name.
// Agents use this token in requests. The MITM proxy replaces it with
// the real credential value at injection time.
func PhantomToken(credentialName string) string {
	return "SLUICE_PHANTOM:" + credentialName
}

// pinIDKeyType is the context key for per-connection pin IDs used to
// locate pinned IPs in the injector's outbound transport.
type pinIDKeyType struct{}

var pinIDCtxKey = pinIDKeyType{}

// Injector is an HTTP/HTTPS MITM proxy that intercepts requests and injects
// credentials from the vault. It resolves bindings by destination, decrypts
// credentials, and performs byte-level replacement of phantom tokens in
// headers and request body.
type Injector struct {
	Proxy    *goproxy.ProxyHttpServer
	provider vault.Provider
	resolver *atomic.Pointer[vault.BindingResolver]
	caCert   tls.Certificate
	// authToken is a random nonce generated at startup. The SOCKS5 dial
	// function includes it in CONNECT requests so the injector can verify
	// that connections originate from the proxy, not from other local
	// processes that discovered the listener port.
	authToken string
	// pinnedIPs maps pinID -> []string of resolved IPs. Each SOCKS5
	// connection generates a unique pin ID to avoid races between
	// concurrent connections to the same hostname. The SOCKS5 dial
	// function pins the policy-approved IPs before routing through the
	// injector so goproxy's outbound connections use the same addresses
	// that passed policy checks.
	pinnedIPs sync.Map
	// wsProxy handles WebSocket frame-level inspection when non-nil.
	// When a 101 Switching Protocols response with WebSocket upgrade
	// headers is detected, the response body is replaced with a
	// wsFrameInterceptor that performs phantom token replacement and
	// content inspection on individual WebSocket frames.
	wsProxy *WSProxy
}

// PinIPs stores resolved IPs keyed by a unique per-connection pin ID so
// that the injector's outbound transport dials policy-approved addresses
// instead of re-resolving DNS. The pin ID is passed through the CONNECT
// request header and propagated via goproxy's UserData to avoid races
// between concurrent connections to the same hostname.
func (inj *Injector) PinIPs(pinID string, resolvedIPs []string) {
	inj.pinnedIPs.Store(pinID, resolvedIPs)
}

// UnpinIPs removes the pinned IP entry for the given pin ID. Call this when
// the SOCKS5 connection closes to avoid leaking entries in the sync.Map.
func (inj *Injector) UnpinIPs(pinID string) {
	inj.pinnedIPs.Delete(pinID)
}

// NewInjector creates an MITM proxy that injects credentials into matching
// requests. The caCert is used to generate per-host TLS certificates for
// HTTPS interception. The authToken must be included in CONNECT requests
// to prevent unauthorized local processes from accessing credential injection.
// wsProxy enables frame-level WebSocket inspection when non-nil.
func NewInjector(provider vault.Provider, resolver *atomic.Pointer[vault.BindingResolver], caCert tls.Certificate, authToken string, wsProxy *WSProxy) *Injector {
	inj := &Injector{
		provider:  provider,
		resolver:  resolver,
		caCert:    caCert,
		authToken: authToken,
		wsProxy:   wsProxy,
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Use a transport that dials pinned IPs (set by the SOCKS5 dial
	// function) instead of re-resolving DNS. This prevents DNS rebinding
	// attacks where the hostname resolves to a different IP between
	// policy evaluation and the goproxy outbound connection. The pin ID
	// is threaded through goproxy's UserData and the request context so
	// each connection uses its own pinned addresses without racing.
	proxy.Tr = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			if pinID, ok := ctx.Value(pinIDCtxKey).(string); ok && pinID != "" {
				if pinnedIPs, ok := inj.pinnedIPs.Load(pinID); ok {
					ips := pinnedIPs.([]string)
					var lastErr error
					for _, ip := range ips {
						target := net.JoinHostPort(ip, port)
						conn, err := (&net.Dialer{Timeout: connectTimeout}).DialContext(ctx, network, target)
						if err == nil {
							return conn, nil
						}
						lastErr = err
					}
					if lastErr != nil {
						return nil, lastErr
					}
				}
			}
			return (&net.Dialer{Timeout: connectTimeout}).DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// MITM all authenticated HTTPS connections so phantom tokens can be
	// replaced in any traffic, not just requests to hosts with bindings.
	// This prevents phantom token leaks to unexpected destinations.
	// The auth token check prevents unauthorized local processes from
	// using the injector. The token is always set in production
	// (generated in server.New).
	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&inj.caCert),
	}
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			// Verify the request originated from our SOCKS5 dial function.
			if inj.authToken != "" {
				if ctx.Req == nil || ctx.Req.Header.Get("X-Sluice-Auth") != inj.authToken {
					return goproxy.RejectConnect, host
				}
			}
			// Store the per-connection pin ID in UserData. goproxy
			// propagates UserData to inner MITM request contexts,
			// allowing injectCredentials to thread it into the
			// request context for the outbound transport.
			if ctx.Req != nil {
				ctx.UserData = ctx.Req.Header.Get("X-Sluice-Pin")
			}
			return mitmAction, host
		},
	))

	proxy.OnRequest().DoFunc(inj.injectCredentials)

	if inj.wsProxy != nil {
		proxy.OnResponse().DoFunc(inj.handleWSUpgrade)
	}

	inj.Proxy = proxy
	return inj
}

// handleWSUpgrade detects 101 Switching Protocols responses with WebSocket
// upgrade headers and replaces the response body with a wsFrameInterceptor.
// goproxy's built-in WebSocket relay then reads/writes through the interceptor,
// which performs frame-level phantom token replacement and content inspection.
func (inj *Injector) handleWSUpgrade(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return resp
	}
	if !isWSUpgradeResponse(resp.Header) {
		return resp
	}
	upstream, ok := resp.Body.(io.ReadWriter)
	if !ok {
		return resp
	}

	host := ctx.Req.URL.Hostname()
	if host == "" {
		host = ctx.Req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	port := portFromRequest(ctx.Req)

	proto := "ws"
	if ctx.Req.URL.Scheme == "https" {
		proto = "wss"
	}

	interceptor := newWSFrameInterceptor(upstream, inj.wsProxy, host, port, proto)
	resp.Body = interceptor

	log.Printf("[WS] intercepting WebSocket upgrade for %s:%d (%s)", host, port, proto)
	return resp
}

// isWSUpgradeResponse checks if the response headers indicate a WebSocket upgrade.
func isWSUpgradeResponse(h http.Header) bool {
	if !strings.EqualFold(h.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range strings.Split(h.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// wsFrameInterceptor wraps an upstream WebSocket connection and performs
// frame-level inspection. It implements io.ReadWriteCloser so it can
// replace resp.Body in goproxy's WebSocket handling. goproxy's proxyWebsocket
// does bidirectional io.Copy between the client and this interceptor.
//
// Read (upstream -> client): reads frames from the real upstream, applies
// content redaction rules, and returns processed frame bytes.
//
// Write (client -> upstream): parses WebSocket frames from client data,
// applies phantom token replacement and content deny rules, and forwards
// processed frames to the real upstream.
type wsFrameInterceptor struct {
	upstream io.ReadWriter
	wp       *WSProxy
	host     string
	port     int
	proto    string

	pairs []phantomPair

	readBuf     bytes.Buffer
	readTracker FragmentTracker

	writePending []byte
	writeTracker FragmentTracker

	closeOnce sync.Once
}

func newWSFrameInterceptor(upstream io.ReadWriter, wp *WSProxy, host string, port int, proto string) *wsFrameInterceptor {
	fi := &wsFrameInterceptor{
		upstream: upstream,
		wp:       wp,
		host:     host,
		port:     port,
		proto:    proto,
	}

	if res := wp.resolver.Load(); res != nil {
		for _, name := range res.CredentialsForDestination(host, port, proto) {
			secret, err := wp.provider.Get(name)
			if err != nil {
				log.Printf("[WS-MITM] credential %q lookup failed: %v", name, err)
				continue
			}
			fi.pairs = append(fi.pairs, phantomPair{
				phantom: []byte(PhantomToken(name)),
				secret:  secret,
			})
		}
	}
	sort.Slice(fi.pairs, func(i, j int) bool {
		return len(fi.pairs[i].phantom) > len(fi.pairs[j].phantom)
	})

	return fi
}

// Read implements io.Reader. It reads WebSocket frames from the real upstream,
// applies content redaction rules to text frames, and returns the processed
// frame bytes for goproxy to forward to the client.
func (fi *wsFrameInterceptor) Read(p []byte) (int, error) {
	for fi.readBuf.Len() == 0 {
		frame, err := ReadFrame(fi.upstream)
		if err != nil {
			return 0, err
		}

		if frame.IsControl() {
			if writeErr := WriteFrame(&fi.readBuf, frame); writeErr != nil {
				return 0, writeErr
			}
			break
		}

		payload, opcode, complete, acceptErr := fi.readTracker.Accept(frame)
		if acceptErr != nil {
			return 0, acceptErr
		}
		if !complete {
			continue
		}

		if opcode == OpcodeBinary {
			out := &Frame{FIN: true, Opcode: OpcodeBinary}
			out.SetPayload(payload)
			if writeErr := WriteFrame(&fi.readBuf, out); writeErr != nil {
				return 0, writeErr
			}
			break
		}

		if opcode == OpcodeText {
			rules := fi.wp.rules.Load()
			if rules != nil {
				text := string(payload)
				for _, rule := range rules.redact {
					text = rule.re.ReplaceAllString(text, rule.replacement)
				}
				payload = []byte(text)
			}
			out := &Frame{FIN: true, Opcode: OpcodeText}
			out.SetPayload(payload)
			if writeErr := WriteFrame(&fi.readBuf, out); writeErr != nil {
				return 0, writeErr
			}
			break
		}
	}

	return fi.readBuf.Read(p)
}

// Write implements io.Writer. It receives raw WebSocket frame bytes from
// the client (via goproxy's io.Copy), parses complete frames, applies
// phantom token replacement and content deny rules to text frames, and
// forwards processed frames to the real upstream.
func (fi *wsFrameInterceptor) Write(p []byte) (int, error) {
	n := len(p)
	// Cap pending buffer at one max frame plus header overhead to prevent
	// unbounded memory growth from a slow upstream or malformed data.
	const maxPendingWrite = maxFramePayload + 14
	if len(fi.writePending)+len(p) > maxPendingWrite {
		return 0, fmt.Errorf("ws write buffer overflow: %d bytes exceeds limit", len(fi.writePending)+len(p))
	}
	fi.writePending = append(fi.writePending, p...)

	for len(fi.writePending) > 0 {
		reader := bytes.NewReader(fi.writePending)
		frame, err := ReadFrame(reader)
		if err != nil {
			// If the error is due to insufficient data (io.EOF or
			// io.ErrUnexpectedEOF), wait for more bytes. Otherwise
			// the frame is structurally invalid and will never parse.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return 0, fmt.Errorf("ws frame parse: %w", err)
		}

		consumed := len(fi.writePending) - int(reader.Len())
		fi.writePending = fi.writePending[consumed:]

		if frame.IsControl() {
			if writeErr := WriteFrame(fi.upstream, frame); writeErr != nil {
				return 0, writeErr
			}
			if frame.Opcode == OpcodeClose {
				return n, nil
			}
			continue
		}

		payload, opcode, complete, acceptErr := fi.writeTracker.Accept(frame)
		if acceptErr != nil {
			return 0, acceptErr
		}
		if !complete {
			continue
		}

		if opcode == OpcodeBinary {
			out := &Frame{FIN: true, Opcode: OpcodeBinary}
			out.SetPayload(payload)
			if writeErr := WriteFrame(fi.upstream, out); writeErr != nil {
				return 0, writeErr
			}
			continue
		}

		if opcode == OpcodeText {
			rules := fi.wp.rules.Load()
			if rules != nil {
				for _, rule := range rules.block {
					if rule.re.Match(payload) {
						sendCloseFrame(fi.upstream, 1008, "blocked by content policy")
						return 0, fmt.Errorf("blocked by ws content deny rule %q", rule.name)
					}
				}
			}

			for _, pp := range fi.pairs {
				if bytes.Contains(payload, pp.phantom) {
					payload = bytes.ReplaceAll(payload, pp.phantom, pp.secret.Bytes())
				}
			}

			if bytes.Contains(payload, phantomPrefix) {
				payload = fi.wp.stripUnboundPhantoms(payload)
				log.Printf("[WS-MITM] stripped unbound phantom token from text frame")
			}

			out := &Frame{FIN: true, Opcode: OpcodeText}
			out.SetPayload(payload)
			if writeErr := WriteFrame(fi.upstream, out); writeErr != nil {
				return 0, writeErr
			}
		}
	}

	return n, nil
}

// Close releases credential secrets and closes the upstream connection.
func (fi *wsFrameInterceptor) Close() error {
	fi.closeOnce.Do(func() {
		for i := range fi.pairs {
			fi.pairs[i].secret.Release()
		}
		if closer, ok := fi.upstream.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	return nil
}

func (inj *Injector) injectCredentials(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Reject direct forward-proxy requests that bypassed CONNECT auth.
	// For authenticated CONNECT tunnels, goproxy propagates the pin ID
	// via UserData. Direct HTTP proxy requests have nil UserData because
	// HandleConnect never ran. When authToken is empty (tests), skip the
	// check to preserve test compatibility.
	if inj.authToken != "" && ctx.UserData == nil {
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
	}

	// Thread the per-connection pin ID into the request context so
	// the custom DialContext can locate the correct pinned IPs.
	if pinID, ok := ctx.UserData.(string); ok && pinID != "" {
		r = r.WithContext(context.WithValue(r.Context(), pinIDCtxKey, pinID))
	}

	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}

	port := portFromRequest(r)

	// 1. Binding-specific header injection: set the configured header
	// with the formatted credential value for hosts with a binding.
	// Use the request scheme (not the port heuristic) since the injector
	// only handles HTTP/HTTPS traffic and the scheme is known from the
	// request. This ensures bindings with protocols=["http"] match on
	// non-standard ports (e.g. 8000) where DetectProtocol returns "generic".
	proto := r.URL.Scheme
	if proto == "" {
		proto = string(DetectProtocol(port))
	}
	// Refine protocol from HTTP headers to detect WebSocket upgrades
	// and gRPC requests. This ensures bindings and rules scoped to
	// protocols=["grpc"] or protocols=["wss"] match correctly.
	if refined := DetectProtocolFromHeaders(r.Header, proto == "https"); refined != ProtoGeneric {
		proto = string(refined)
	}
	if res := inj.resolver.Load(); res != nil {
		if binding, ok := res.ResolveForProtocol(host, port, proto); ok {
			secret, err := inj.provider.Get(binding.Credential)
			if err != nil {
				log.Printf("[INJECT] credential %q lookup failed: %v", binding.Credential, err)
			} else {
				if binding.Header != "" {
					r.Header.Set(binding.Header, binding.FormatValue(secret.String()))
				}
				secret.Release()
				log.Printf("[INJECT] injected credential %q for %s:%d", binding.Credential, host, port)
			}
		}
	}

	// 2. Scoped phantom replacement: replace phantom tokens only for
	// credentials bound to this destination. Strip any remaining phantom
	// tokens to prevent leakage without enabling cross-credential
	// exfiltration to unintended destinations.
	var boundCreds []string
	if res := inj.resolver.Load(); res != nil {
		boundCreds = res.CredentialsForDestination(host, port, proto)
	}

	var pairs []phantomPair
	for _, name := range boundCreds {
		secret, err := inj.provider.Get(name)
		if err != nil {
			log.Printf("[INJECT] credential %q lookup failed: %v", name, err)
			continue
		}
		pairs = append(pairs, phantomPair{
			phantom: []byte(PhantomToken(name)),
			secret:  secret,
		})
	}
	// Sort by phantom length descending so longer tokens (e.g.
	// SLUICE_PHANTOM:api_key_v2) are replaced before shorter prefixes
	// (e.g. SLUICE_PHANTOM:api_key) that would otherwise corrupt them
	// via substring match in bytes.ReplaceAll.
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].phantom) > len(pairs[j].phantom)
	})

	defer func() {
		for i := range pairs {
			pairs[i].secret.Release()
		}
	}()

	// Replace bound phantom tokens in headers, then strip any remaining
	// unbound phantom tokens so they never reach upstream servers.
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
				vb = inj.stripUnboundPhantoms(vb)
				changed = true
				log.Printf("[INJECT] stripped unbound phantom token from header %q for %s:%d", key, host, port)
			}
			if changed {
				r.Header[key][i] = string(vb)
			}
		}
	}

	// Replace bound phantom tokens in the request body, then strip
	// any remaining unbound phantom tokens.
	// Limit body size to prevent memory exhaustion from oversized
	// requests (matches the QUIC proxy's maxQUICBody limit).
	if r.Body != nil && r.Body != http.NoBody {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, maxMITMBody))
		_ = r.Body.Close()
		if readErr != nil {
			log.Printf("[INJECT] body read error for %s:%d: %v", host, port, readErr)
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "request body read error")
		}
		changed := false
		for _, p := range pairs {
			if bytes.Contains(body, p.phantom) {
				body = bytes.ReplaceAll(body, p.phantom, p.secret.Bytes())
				changed = true
			}
		}
		if bytes.Contains(body, phantomPrefix) {
			body = inj.stripUnboundPhantoms(body)
			changed = true
			log.Printf("[INJECT] stripped unbound phantom token from body for %s:%d", host, port)
		}
		if changed {
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	// Replace bound phantom tokens in the URL query and path, then strip
	// any remaining unbound phantom tokens. SDKs rarely put credentials in
	// URLs, but the safety-net philosophy requires covering all request data.
	if rawQ := r.URL.RawQuery; bytes.Contains([]byte(rawQ), phantomPrefix) {
		qb := []byte(rawQ)
		for _, p := range pairs {
			if bytes.Contains(qb, p.phantom) {
				qb = bytes.ReplaceAll(qb, p.phantom, p.secret.Bytes())
			}
		}
		if bytes.Contains(qb, phantomPrefix) {
			qb = inj.stripUnboundPhantoms(qb)
			log.Printf("[INJECT] stripped unbound phantom token from URL query for %s:%d", host, port)
		}
		r.URL.RawQuery = string(qb)
	}
	if rawP := r.URL.Path; bytes.Contains([]byte(rawP), phantomPrefix) {
		pb := []byte(rawP)
		for _, p := range pairs {
			if bytes.Contains(pb, p.phantom) {
				pb = bytes.ReplaceAll(pb, p.phantom, p.secret.Bytes())
			}
		}
		if bytes.Contains(pb, phantomPrefix) {
			pb = inj.stripUnboundPhantoms(pb)
			log.Printf("[INJECT] stripped unbound phantom token from URL path for %s:%d", host, port)
		}
		r.URL.Path = string(pb)
		r.URL.RawPath = ""
	}

	return r, nil
}

// stripUnboundPhantoms removes phantom tokens from data using exact matching
// via provider.List() first, then falls back to regex for any remaining tokens
// from providers that don't support listing. Exact matching handles credential
// names with hyphens and other characters that the regex can't safely match.
func (inj *Injector) stripUnboundPhantoms(data []byte) []byte {
	names, _ := inj.provider.List()
	// Sort by name length descending so longer phantom tokens are stripped
	// before shorter prefixes that could corrupt them via substring match.
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j])
	})
	for _, name := range names {
		phantom := []byte(PhantomToken(name))
		if bytes.Contains(data, phantom) {
			data = bytes.ReplaceAll(data, phantom, nil)
		}
	}
	// Last-resort regex strip for phantom tokens from providers that
	// don't support List() (e.g. env provider).
	if bytes.Contains(data, phantomPrefix) {
		data = phantomStripRe.ReplaceAll(data, nil)
	}
	return data
}

func portFromRequest(r *http.Request) int {
	if p := r.URL.Port(); p != "" {
		if port, err := strconv.Atoi(p); err == nil {
			return port
		}
	}
	if r.URL.Scheme == "https" {
		return 443
	}
	return 80
}
