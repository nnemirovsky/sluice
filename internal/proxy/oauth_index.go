package proxy

import (
	"log"
	"net/url"
	"strings"

	"github.com/nemirovsky/sluice/internal/store"
)

// OAuthIndex maps token endpoint URLs to credential names for fast lookup
// during response interception. The MITM addon checks every HTTPS response
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

// MatchAll returns every credential whose token endpoint matches the
// request URL, in index order. Two pool members commonly share ONE token
// URL (the documented Codex deployment: two OpenAI accounts, one
// auth.openai.com), and a plain OAuth credential may share that same token
// URL too. Match returns only the first index entry, which silently drops
// the others; callers that must reason about pool membership (request-side
// token-host phantom expansion, response-side attribution, token-endpoint
// failover) need the full set so they can pick the pooled/correct member
// instead of whichever name happened to sort first in credential_meta.
func (idx *OAuthIndex) MatchAll(requestURL *url.URL) []string {
	if idx == nil || requestURL == nil {
		return nil
	}
	reqPath := normalizePath(requestURL.Path)
	reqHost := normalizeHost(requestURL.Host, requestURL.Scheme)
	var creds []string
	for _, e := range idx.entries {
		if e.tokenURL.Scheme == requestURL.Scheme &&
			normalizeHost(e.tokenURL.Host, e.tokenURL.Scheme) == reqHost &&
			normalizePath(e.tokenURL.Path) == reqPath {
			creds = append(creds, e.credential)
		}
	}
	return creds
}

// Len returns the number of entries in the index.
func (idx *OAuthIndex) Len() int {
	if idx == nil {
		return 0
	}
	return len(idx.entries)
}

// Has returns true if the named credential is registered as OAuth in
// this index (i.e. its credential_meta entry had cred_type="oauth" and
// a usable token_url). The injection path uses this to decide whether
// the secret returned by the vault is a JSON-marshalled OAuthCredential
// envelope that needs access_token extraction, vs a static credential
// whose value should be passed through to the binding template
// verbatim. We treat credential metadata as authoritative rather than
// inferring from the secret's shape, so a static credential whose
// value happens to be JSON cannot be misclassified.
func (idx *OAuthIndex) Has(credName string) bool {
	if idx == nil {
		return false
	}
	for _, e := range idx.entries {
		if e.credential == credName {
			return true
		}
	}
	return false
}
