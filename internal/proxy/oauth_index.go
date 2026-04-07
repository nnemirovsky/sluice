package proxy

import (
	"log"
	"net/url"
	"strings"

	"github.com/nemirovsky/sluice/internal/store"
)

// OAuthIndex maps token endpoint URLs to credential names for fast lookup
// during response interception. The injector checks every HTTPS response
// against this index to detect OAuth token responses that need phantom
// token replacement.
type OAuthIndex struct {
	entries []oauthEntry
}

type oauthEntry struct {
	tokenURL   *url.URL // parsed token URL (scheme + host + path)
	credential string   // credential name in vault
}

// NewOAuthIndex builds an index from credential metadata. Only entries with
// cred_type "oauth" and a non-empty token_url are included. Entries with
// unparseable URLs are logged and skipped.
func NewOAuthIndex(metas []store.CredentialMeta) *OAuthIndex {
	idx := &OAuthIndex{}
	for _, m := range metas {
		if m.CredType != "oauth" || m.TokenURL == "" {
			continue
		}
		parsed, err := url.Parse(m.TokenURL)
		if err != nil {
			log.Printf("[INJECT-OAUTH] skip credential %q: invalid token_url %q: %v", m.Name, m.TokenURL, err)
			continue
		}
		// Require scheme and host for meaningful matching.
		if parsed.Scheme == "" || parsed.Host == "" {
			log.Printf("[INJECT-OAUTH] skip credential %q: token_url %q missing scheme or host", m.Name, m.TokenURL)
			continue
		}
		idx.entries = append(idx.entries, oauthEntry{
			tokenURL:   parsed,
			credential: m.Name,
		})
	}
	return idx
}

// normalizePath returns "/" for an empty path, matching the HTTP convention
// where http://host and http://host/ refer to the same resource.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// normalizeHost strips the default port for the given scheme so that
// "auth.example.com" and "auth.example.com:443" compare equal for HTTPS.
func normalizeHost(host, scheme string) string {
	defaultPort := ""
	switch scheme {
	case "https":
		defaultPort = ":443"
	case "http":
		defaultPort = ":80"
	}
	if defaultPort != "" {
		host = strings.TrimSuffix(host, defaultPort)
	}
	return host
}

// Match checks if a request URL matches any configured token endpoint.
// Matching is exact on scheme, host, and path (with empty path normalized
// to "/"). Default ports (443 for https, 80 for http) are stripped before
// host comparison. Query parameters and fragments are ignored. Returns the
// credential name and true if matched.
func (idx *OAuthIndex) Match(requestURL *url.URL) (credName string, ok bool) {
	if idx == nil || requestURL == nil {
		return "", false
	}
	reqPath := normalizePath(requestURL.Path)
	reqHost := normalizeHost(requestURL.Host, requestURL.Scheme)
	for _, e := range idx.entries {
		if e.tokenURL.Scheme == requestURL.Scheme &&
			normalizeHost(e.tokenURL.Host, e.tokenURL.Scheme) == reqHost &&
			normalizePath(e.tokenURL.Path) == reqPath {
			return e.credential, true
		}
	}
	return "", false
}

// Len returns the number of entries in the index.
func (idx *OAuthIndex) Len() int {
	if idx == nil {
		return 0
	}
	return len(idx.entries)
}
