package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/nemirovsky/sluice/internal/vault"
)

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
func NewInjector(provider vault.Provider, resolver *atomic.Pointer[vault.BindingResolver], caCert tls.Certificate, authToken string) *Injector {
	inj := &Injector{
		provider:  provider,
		resolver:  resolver,
		caCert:    caCert,
		authToken: authToken,
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

	inj.Proxy = proxy
	return inj
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
	if res := inj.resolver.Load(); res != nil {
		if binding, ok := res.ResolveForProtocol(host, port, proto); ok {
			secret, err := inj.provider.Get(binding.Credential)
			if err != nil {
				log.Printf("[INJECT] credential %q lookup failed: %v", binding.Credential, err)
			} else {
				if binding.InjectHeader != "" {
					r.Header.Set(binding.InjectHeader, binding.FormatValue(secret.String()))
				}
				secret.Release()
				log.Printf("[INJECT] injected credential %q for %s:%d", binding.Credential, host, port)
			}
		}
	}

	// 2. Global phantom replacement: replace ALL known phantom tokens
	// in headers and body regardless of binding match. This prevents
	// phantom tokens from leaking to any upstream.
	names, err := inj.provider.List()
	if err != nil || len(names) == 0 {
		return r, nil
	}

	type phantomPair struct {
		phantom []byte
		secret  vault.SecureBytes
	}
	var pairs []phantomPair
	for _, name := range names {
		secret, err := inj.provider.Get(name)
		if err != nil {
			continue
		}
		pairs = append(pairs, phantomPair{
			phantom: []byte(PhantomToken(name)),
			secret:  secret,
		})
	}
	if len(pairs) == 0 {
		return r, nil
	}
	defer func() {
		for i := range pairs {
			pairs[i].secret.Release()
		}
	}()

	// Replace phantom tokens in all request headers.
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
			if changed {
				r.Header[key][i] = string(vb)
			}
		}
	}

	// Replace phantom tokens in the request body.
	if r.Body != nil && r.Body != http.NoBody {
		body, readErr := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if readErr != nil {
			log.Printf("[INJECT] body read error for %s:%d: %v", host, port, readErr)
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "request body read error")
		}
		for _, p := range pairs {
			if bytes.Contains(body, p.phantom) {
				body = bytes.ReplaceAll(body, p.phantom, p.secret.Bytes())
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	return r, nil
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
