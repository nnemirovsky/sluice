package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/store"
)

// tokenHostIndex returns an OAuthIndex with a single OAuth token endpoint at
// https://auth.example.com/token, used by the pre-gate tests.
func tokenHostIndex() *OAuthIndex {
	return NewOAuthIndex([]store.CredentialMeta{
		{Name: "oauth_cred", CredType: "oauth", TokenURL: "https://auth.example.com/token"},
	})
}

func flowWith(method, rawURL, ct string, body []byte) *mitmproxy.Flow {
	u, _ := url.Parse(rawURL)
	h := make(http.Header)
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &mitmproxy.Flow{
		Request: &mitmproxy.Request{
			Method: method,
			URL:    u,
			Header: h,
			Body:   body,
		},
	}
}

// TestRequestFlowGrantType_PreGate is the Finding 2 fail-before/pass-after
// guard: the body grant_type parse must run ONLY for an HTTP POST whose
// scheme+host matches a known OAuth token endpoint. A non-POST request, or a
// POST to a non-token host, must return "" WITHOUT parsing the body even
// though the body is a perfectly valid refresh-grant form.
func TestRequestFlowGrantType_PreGate(t *testing.T) {
	idx := tokenHostIndex()
	refreshBody := []byte("grant_type=refresh_token&refresh_token=rt-xxx")
	const formCT = "application/x-www-form-urlencoded"

	cases := []struct {
		name   string
		method string
		url    string
		want   string
	}{
		{
			// Pass-after: a real refresh POST to the token host is still
			// parsed (the gate must not break the existing behavior).
			name:   "POST to token host parses",
			method: "POST",
			url:    "https://auth.example.com/token",
			want:   "refresh_token",
		},
		{
			// Pre-gate: same valid refresh body, but a GET cannot be a
			// token request -> not parsed, returns "".
			name:   "GET to token host skipped",
			method: "GET",
			url:    "https://auth.example.com/token",
			want:   "",
		},
		{
			// Pre-gate: POST but to a non-token host (the vast majority of
			// proxied traffic) -> not parsed, returns "".
			name:   "POST to non-token host skipped",
			method: "POST",
			url:    "https://api.example.com/v1/chat",
			want:   "",
		},
		{
			// Method comparison is case-insensitive (RFC methods are
			// uppercase but be defensive).
			name:   "lowercase post to token host parses",
			method: "post",
			url:    "https://auth.example.com/token",
			want:   "refresh_token",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := flowWith(c.method, c.url, formCT, refreshBody)
			if got := requestFlowGrantType(f, idx); got != c.want {
				t.Fatalf("requestFlowGrantType(%s %s) = %q, want %q",
					c.method, c.url, got, c.want)
			}
		})
	}
}

// TestRequestFlowGrantType_NilSafe verifies the gate degrades safely when the
// index is nil (startup race before UpdateOAuthIndex fires): with no known
// token hosts, nothing can be a token request, so it returns "".
func TestRequestFlowGrantType_NilSafe(t *testing.T) {
	f := flowWith("POST", "https://auth.example.com/token",
		"application/x-www-form-urlencoded",
		[]byte("grant_type=refresh_token&refresh_token=x"))
	if got := requestFlowGrantType(f, nil); got != "" {
		t.Fatalf("requestFlowGrantType with nil index = %q, want \"\"", got)
	}
	if got := requestFlowGrantType(nil, tokenHostIndex()); got != "" {
		t.Fatalf("requestFlowGrantType(nil flow) = %q, want \"\"", got)
	}
}

// TestOAuthIndexMatchesHost covers the cheap host-only pre-gate matcher:
// scheme+host match ignoring path; default-port normalization; no match for a
// different host/scheme.
func TestOAuthIndexMatchesHost(t *testing.T) {
	idx := tokenHostIndex()
	mustParse := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return u
	}
	if !idx.MatchesHost(mustParse("https://auth.example.com/token")) {
		t.Fatal("exact host+path should match")
	}
	if !idx.MatchesHost(mustParse("https://auth.example.com/some/other/path")) {
		t.Fatal("same host, different path should still match (host-only gate)")
	}
	if !idx.MatchesHost(mustParse("https://auth.example.com:443/token")) {
		t.Fatal("default https port must normalize to a match")
	}
	if idx.MatchesHost(mustParse("https://api.example.com/token")) {
		t.Fatal("different host must not match")
	}
	if idx.MatchesHost(mustParse("http://auth.example.com/token")) {
		t.Fatal("different scheme must not match")
	}
	if (*OAuthIndex)(nil).MatchesHost(mustParse("https://auth.example.com/token")) {
		t.Fatal("nil index must not match")
	}
}

// TestRequestGrantType_CapRaisedAndObservable is the Finding 9 guard: the
// probe cap is now 64 KiB (a realistic large OAuth token request with a
// JWT client_assertion + long refresh token is still parsed), and a body
// over the cap is NOT parsed (bounded worst case, the original perf bug
// stays fixed).
func TestRequestGrantType_CapRaisedAndObservable(t *testing.T) {
	const formCT = "application/x-www-form-urlencoded"

	// A ~40 KiB refresh-grant body (long JWT-shaped client_assertion). Under
	// the old 8 KiB cap this returned "" (Finding 9 silent drop); under the
	// 64 KiB cap it must parse correctly.
	bigAssertion := strings.Repeat("A", 40<<10)
	largeRefresh := []byte("grant_type=refresh_token&refresh_token=rt-xxx&client_assertion=" + bigAssertion)
	if len(largeRefresh) <= 8<<10 {
		t.Fatalf("test body must exceed the old 8 KiB cap, got %d", len(largeRefresh))
	}
	if len(largeRefresh) >= maxGrantTypeProbeBody {
		t.Fatalf("test body must stay under the new cap, got %d (cap %d)",
			len(largeRefresh), maxGrantTypeProbeBody)
	}
	if got := requestGrantType(largeRefresh, formCT); got != "refresh_token" {
		t.Fatalf("large (under-cap) refresh body grant_type = %q, want refresh_token", got)
	}

	// A body over the new cap is still not probed (returns "").
	overCap := []byte("grant_type=refresh_token&x=" + strings.Repeat("B", maxGrantTypeProbeBody))
	if len(overCap) <= maxGrantTypeProbeBody {
		t.Fatalf("over-cap body must exceed the cap, got %d", len(overCap))
	}
	if got := requestGrantType(overCap, formCT); got != "" {
		t.Fatalf("over-cap body grant_type = %q, want \"\" (probe skipped)", got)
	}
}

// TestExtractRequestRefreshToken_SingleParse is the Finding 3 guard: an
// explicit form Content-Type whose body happens to start with '{' is parsed
// ONLY as form (no JSON fallback double string(body)); behavior for the
// normal cases (form body, JSON body, headerless JSON) is unchanged.
func TestExtractRequestRefreshToken_SingleParse(t *testing.T) {
	const formCT = "application/x-www-form-urlencoded"

	// form CT, real form body -> parsed as form.
	if got := extractRequestRefreshToken([]byte("refresh_token=rt-1"), formCT); got != "rt-1" {
		t.Fatalf("form body = %q, want rt-1", got)
	}
	// form CT, JSON-shaped body -> form parse yields nothing, JSON fallback
	// NOT run (Finding 3) -> "".
	if got := extractRequestRefreshToken([]byte(`{"refresh_token":"rt-2"}`), formCT); got != "" {
		t.Fatalf("form-CT json body = %q, want \"\" (json fallback must not run)", got)
	}
	// json CT, JSON body -> parsed as JSON.
	if got := extractRequestRefreshToken([]byte(`{"refresh_token":"rt-3"}`), "application/json"); got != "rt-3" {
		t.Fatalf("json body = %q, want rt-3", got)
	}
	// absent CT, JSON body -> form parse misses, JSON fallback still
	// reachable (headerless JSON token request must remain recoverable).
	if got := extractRequestRefreshToken([]byte(`{"refresh_token":"rt-4"}`), ""); got != "rt-4" {
		t.Fatalf("headerless json body = %q, want rt-4 (fallback must stay reachable)", got)
	}
}
