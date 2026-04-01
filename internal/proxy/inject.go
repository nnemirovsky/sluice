package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/nemirovsky/sluice/internal/vault"
)

// PhantomToken returns the placeholder token for a credential name.
// Agents use this token in requests. The MITM proxy replaces it with
// the real credential value at injection time.
func PhantomToken(credentialName string) string {
	return "SLUICE_PHANTOM:" + credentialName
}

// Injector is an HTTPS MITM proxy that intercepts requests and injects
// credentials from the vault. It resolves bindings by destination, decrypts
// credentials, and performs byte-level replacement of phantom tokens in
// headers and request body.
type Injector struct {
	Proxy    *goproxy.ProxyHttpServer
	store    *vault.Store
	resolver *vault.BindingResolver
	caCert   tls.Certificate
}

// NewInjector creates an MITM proxy that injects credentials into matching
// requests. The caCert is used to generate per-host TLS certificates for
// HTTPS interception.
func NewInjector(store *vault.Store, resolver *vault.BindingResolver, caCert tls.Certificate) *Injector {
	inj := &Injector{
		store:    store,
		resolver: resolver,
		caCert:   caCert,
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Configure per-host cert generation using the provided CA.
	connectAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&inj.caCert),
	}
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return connectAction, host
		},
	))

	proxy.OnRequest().DoFunc(inj.injectCredentials)

	inj.Proxy = proxy
	return inj
}

func (inj *Injector) injectCredentials(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}

	port := portFromRequest(r)

	binding, ok := inj.resolver.Resolve(host, port)
	if !ok {
		return r, nil
	}

	secret, err := inj.store.Get(binding.Credential)
	if err != nil {
		log.Printf("[INJECT] credential %q lookup failed: %v", binding.Credential, err)
		return r, nil
	}
	defer secret.Release()

	value := binding.FormatValue(secret.String())
	phantom := PhantomToken(binding.Credential)

	// Set the configured header if specified.
	if binding.InjectHeader != "" {
		r.Header.Set(binding.InjectHeader, value)
	}

	// Replace phantom tokens in all request headers.
	for key, vals := range r.Header {
		for i, v := range vals {
			if strings.Contains(v, phantom) {
				r.Header[key][i] = strings.ReplaceAll(v, phantom, value)
			}
		}
	}

	// Replace phantom tokens in the request body.
	if r.Body != nil && r.Body != http.NoBody {
		body, readErr := io.ReadAll(r.Body)
		r.Body.Close()
		if readErr == nil {
			if bytes.Contains(body, []byte(phantom)) {
				body = bytes.ReplaceAll(body, []byte(phantom), []byte(value))
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
	}

	log.Printf("[INJECT] injected credential %q for %s:%d", binding.Credential, host, port)
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
