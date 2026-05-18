package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/vault"
)

// phantomSigningKey is used to re-sign JWT tokens so phantom JWTs have a
// valid structure but cannot be used against the real API. This is a
// fixed key because phantom JWTs only need structural validity for
// client-side claim parsing, not cryptographic security.
var phantomSigningKey = []byte("sluice-phantom-jwt-signing-key")

// oauthPhantomAccess returns a phantom token for an OAuth access token.
// When called without a real token (request-side, stripping), returns the
// deterministic SLUICE_PHANTOM string. When called with a real JWT token
// (response-side), preserves the header and payload but re-signs so the
// token is structurally valid but useless against the real API.
func oauthPhantomAccess(credName string, realToken ...string) string {
	if len(realToken) > 0 && realToken[0] != "" {
		if phantom := resignJWT(realToken[0]); phantom != "" {
			return phantom
		}
	}
	return "SLUICE_PHANTOM:" + credName + ".access"
}

// poolStablePhantomAccess returns the pool-keyed phantom access token for a
// pooled OAuth credential (Risk R3). resignJWT is deterministic per *real*
// token, so a naive phantom would change every time sluice fails over to a
// different pool member — the agent would see its access token mutate
// underneath it and the "agent never notices" guarantee would break.
//
// Instead we synthesize a structurally valid JWT from a deterministic
// payload keyed on the POOL NAME (stable sub/iss, far-future exp), HMAC'd
// with the same fixed phantomSigningKey. The result is byte-identical for a
// given pool regardless of which member is currently active, so a
// cross-member refresh never changes the token the agent holds.
//
// Static-form fallback: if the consuming agent is verified to treat the
// access token as opaque (never parses it client-side), emitting the plain
// "SLUICE_PHANTOM:<pool>.access" string is equally pool-stable and simpler.
// The synthetic-JWT path is primary because resignJWT exists specifically
// because *something* (OpenAI Codex / Hermes) parses the JWT client-side, so
// we must not assume opacity.
func poolStablePhantomAccess(poolName string) string {
	// Header: {"alg":"HS256","typ":"JWT"} — fixed, no per-pool variation.
	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"HS256","typ":"JWT"}`),
	)
	// Payload: deterministic, keyed on the pool name. exp is a far-future
	// fixed timestamp (2100-01-01T00:00:00Z = 4102444800) so client-side
	// expiry checks treat it as valid; iat is intentionally omitted so the
	// payload is a pure function of the pool name (an iat would make the
	// phantom time-varying and break byte-identity).
	//
	// The pool name is marshaled through encoding/json — never concatenated
	// into the JSON string — so a name containing '"', '\', or control
	// characters cannot produce an invalid JWT or inject extra claims
	// (Finding 4). A fixed-field struct keeps the output deterministic and
	// byte-stable for a given pool name (no map iteration ordering).
	payloadJSON, err := json.Marshal(struct {
		Sub string `json:"sub"`
		Iss string `json:"iss"`
		Exp int64  `json:"exp"`
	}{
		Sub: "sluice-pool:" + poolName,
		Iss: "sluice-phantom",
		Exp: 4102444800,
	})
	if err != nil {
		// json.Marshal of a fixed struct with string/int fields cannot
		// fail in practice; fall back to the static-form pool-stable
		// phantom rather than emitting a malformed token.
		return "SLUICE_PHANTOM:" + poolName + ".access"
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, phantomSigningKey)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// oauthPhantomRefresh returns a phantom for an OAuth refresh token.
func oauthPhantomRefresh(credName string, realToken ...string) string {
	if len(realToken) > 0 && realToken[0] != "" {
		if phantom := resignJWT(realToken[0]); phantom != "" {
			return phantom
		}
	}
	return "SLUICE_PHANTOM:" + credName + ".refresh"
}

// resignJWT takes a JWT string, preserves the header and payload, and
// replaces the signature with an HMAC-SHA256 using sluice's phantom key.
// Returns empty string if the input is not a valid 3-part JWT.
func resignJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	// Verify parts 0 and 1 are valid base64url.
	if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return ""
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return ""
	}

	// Re-sign: HMAC-SHA256(header.payload, phantomSigningKey)
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, phantomSigningKey)
	mac.Write([]byte(signingInput))
	newSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + newSig
}

// extractRequestRefreshToken pulls the `refresh_token` value out of an
// outbound OAuth token-endpoint request body. By the time the Response
// addon runs, pass-2 has already swapped sluice's phantom for the active
// member's REAL refresh token, so this returns the real token value — the
// Risk R1 join key. RFC 6749 §6 mandates application/x-www-form-urlencoded
// for the refresh grant; some non-conformant endpoints accept JSON, so both
// are parsed (form first, JSON fallback). Returns "" when no refresh_token
// field is present (e.g. an authorization_code grant), which the caller
// treats as "not a refresh round-trip, nothing to attribute".
func extractRequestRefreshToken(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	ct := strings.ToLower(contentType)
	isFormCT := strings.Contains(ct, "application/x-www-form-urlencoded")
	if isFormCT || !strings.Contains(ct, "json") {
		if vals, err := url.ParseQuery(string(body)); err == nil {
			if rt := vals.Get("refresh_token"); rt != "" {
				return rt
			}
		}
		// An explicit form Content-Type is authoritative: the body was
		// already parsed as form, so do not also stringify+JSON-parse it
		// when it merely starts with '{' (Finding 3, the double string(body)
		// alloc). Behavior is identical for normal cases (form body -> form,
		// form-CT-with-json-body -> no refresh_token -> ""). The JSON
		// fallback below stays reachable only for absent/ambiguous CT, where
		// a conformant-but-headerless JSON token request must still be
		// recoverable.
		if isFormCT {
			return ""
		}
	}
	if strings.Contains(ct, "json") || strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		var probe struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &probe); err == nil && probe.RefreshToken != "" {
			return probe.RefreshToken
		}
	}
	return ""
}

// maxGrantTypeProbeBody bounds the request body requestGrantType will copy +
// parse. RFC 6749 §4 token requests are small, but an RFC 7523
// client_assertion (a signed JWT, optionally with a long refresh token and a
// large key-bound assertion) can run to tens of KiB. The original 8 KiB cap
// was unsafe: a legitimately large refresh-grant payload at a pool's token
// host would probe as "" -> the pool token-host gate would treat it as a
// non-refresh grant and silently NOT expand the refresh phantom, the inverted
// form of the very failure the gate prevents (Finding 9). 64 KiB is well above
// any realistic OAuth token-request body (a 4 KiB RSA-signed JWT base64s to
// ~6 KiB; even several stacked assertions plus a JWT refresh token stay under
// 64 KiB) while still bounding the worst-case string()+ParseQuery so an
// unbounded body to the token host cannot become an O(body) hot-path cost
// (the original perf bug). Combined with requestFlowGrantType's POST +
// token-host pre-gate (Finding 2) the parse only runs for token-host requests
// at all, so the larger cap is effectively free.
const maxGrantTypeProbeBody = 64 << 10 // 64 KiB

// grantTypeProbeTruncated counts requests whose body exceeded
// maxGrantTypeProbeBody and were therefore NOT probed for grant_type. A
// truncated probe at a pool token host silently degrades into "no refresh
// expansion", so it must be observable. Rate-limited like the DLP no-match
// log so a pathological client cannot spam production logs.
var grantTypeProbeTruncated uint64

// grantTypeProbeTruncLogEvery sets the rate-limit cadence for the
// cap-truncation warning (one line per N truncations).
const grantTypeProbeTruncLogEvery = 100

// requestGrantType pulls the `grant_type` value out of an outbound OAuth
// token-endpoint request body. RFC 6749 §4 mandates
// application/x-www-form-urlencoded for token requests; some non-conformant
// clients send JSON, so both are parsed (form first, JSON fallback) using the
// same shape as extractRequestRefreshToken. Returns "" when the body is empty,
// larger than maxGrantTypeProbeBody, or has no parseable grant_type (e.g. a
// malformed body or an opaque device-poll request) — the caller treats
// absent/unknown the same as a non-refresh grant and passes the request
// through unmodified. The form parse is restricted to bodies whose
// Content-Type indicates form-encoding (or is absent/ambiguous, since a
// well-formed token request omitting Content-Type is still form-encoded);
// JSON and large/binary bodies (octet-stream, multipart, text/*) are not
// run through string()+url.ParseQuery, keeping the proxy hot path cheap.
func requestGrantType(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > maxGrantTypeProbeBody {
		// Cap hit: the grant_type is not probed, so a real refresh-grant
		// payload this large would NOT get the pool refresh phantom expanded
		// (Finding 9). Rate-limited WARNING so the silent degrade is
		// observable in a log aggregator without spamming under a
		// pathological client.
		if n := atomic.AddUint64(&grantTypeProbeTruncated, 1); n%grantTypeProbeTruncLogEvery == 1 {
			log.Printf("[ADDON-INJECT] WARNING: request body %d bytes exceeds grant_type probe cap %d; "+
				"grant_type not parsed, pool refresh-phantom expansion skipped for this request "+
				"(occurrence #%d)", len(body), maxGrantTypeProbeBody, n)
		}
		return ""
	}
	ct := strings.TrimSpace(strings.ToLower(contentType))
	// Parse as form only when the Content-Type is form-encoded, or absent — a
	// conformant token request that omitted the header is still form-encoded.
	// An explicit non-form CT (octet-stream, multipart, text/*, json) is not a
	// form token request, so the O(body) string()+url.ParseQuery is skipped;
	// JSON is handled by the dedicated fallback below.
	isFormCT := strings.Contains(ct, "application/x-www-form-urlencoded")
	if isFormCT || ct == "" {
		if vals, err := url.ParseQuery(string(body)); err == nil {
			if gt := vals.Get("grant_type"); gt != "" {
				return gt
			}
		}
		// An explicit form Content-Type is authoritative: skip the
		// stringify+JSON-parse fallback for a body that merely starts with
		// '{' (Finding 3, the double string(body) alloc). Behavior is
		// identical for normal cases (form body -> form,
		// form-CT-with-json-body -> no grant_type -> ""). The JSON fallback
		// stays reachable only for absent CT (ct == ""), preserving
		// recovery of a headerless JSON token request.
		if isFormCT {
			return ""
		}
	}
	if strings.Contains(ct, "json") || strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		var probe struct {
			GrantType string `json:"grant_type"`
		}
		if err := json.Unmarshal(body, &probe); err == nil && probe.GrantType != "" {
			return probe.GrantType
		}
	}
	return ""
}

// requestFlowGrantType extracts the OAuth grant_type from a flow's outbound
// request (body + Content-Type). Returns "" when the flow / request / body is
// nil-or-empty or the grant_type is not parseable, which the pool token-host
// expansion treats the same as a non-refresh grant (pass through unmodified).
//
// Cheap pre-gate (Finding 2): requestFlowGrantType runs on EVERY proxied
// request, but the only consumer (the pool token-host expansion in
// buildPhantomPairs) acts solely on grant_type=="refresh_token" requests to a
// pool's OAuth token host. A token request is, per RFC 6749 §3.2, an
// HTTP POST to the token endpoint. So unless the request is a POST whose
// scheme+host matches a known OAuth token endpoint (idx.MatchesHost — host
// only, no path normalization, no body copy), the request cannot be a token
// round-trip and we return "" without ever calling string(body)+ParseQuery.
// This skips the O(body) grant_type probe for the vast majority of
// non-OAuth-token traffic. classifyFailover keeps its own independent
// response-side parse (gated on the OAuthIndex path match), so the two paths
// stay consistent without sharing this request-side gate.
func requestFlowGrantType(f *mitmproxy.Flow, idx *OAuthIndex) string {
	if f == nil || f.Request == nil {
		return ""
	}
	// Pre-gate: only an HTTP POST to a known OAuth token host can be a token
	// request. url.ParseQuery / json.Unmarshal of the body are skipped
	// entirely otherwise.
	if !strings.EqualFold(f.Request.Method, "POST") {
		return ""
	}
	if !idx.MatchesHost(f.Request.URL) {
		return ""
	}
	ct := ""
	if f.Request.Header != nil {
		ct = f.Request.Header.Get("Content-Type")
	}
	return requestGrantType(f.Request.Body, ct)
}

// tokenResponse is the parsed result from an OAuth token endpoint. Fields
// match the RFC 6749 token response format.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

// parseTokenResponse extracts token fields from a response body. Supports
// both application/json and application/x-www-form-urlencoded formats per
// RFC 6749. Returns nil if the body does not contain an access_token.
func parseTokenResponse(body []byte, contentType string) (*tokenResponse, error) {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		return parseFormTokenResponse(body)
	}
	// Default to JSON parsing (covers application/json and unknown types).
	return parseJSONTokenResponse(body)
}

func parseJSONTokenResponse(body []byte) (*tokenResponse, error) {
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse json token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("parse json token response: missing access_token")
	}
	return &tr, nil
}

func parseFormTokenResponse(body []byte) (*tokenResponse, error) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse form token response: %w", err)
	}
	at := vals.Get("access_token")
	if at == "" {
		return nil, fmt.Errorf("parse form token response: missing access_token")
	}
	tr := &tokenResponse{
		AccessToken:  at,
		RefreshToken: vals.Get("refresh_token"),
		TokenType:    vals.Get("token_type"),
	}
	if ei := vals.Get("expires_in"); ei != "" {
		if v, err := strconv.Atoi(ei); err == nil {
			tr.ExpiresIn = v
		}
	}
	return tr, nil
}

// adder is the interface for vault providers that support writing credentials.
type adder interface {
	Add(name, value string) ([]byte, error)
}

// findAdder extracts a provider that supports Add from the given provider.
// For a ChainProvider it walks the inner providers and returns the first one
// that implements Add. For a direct provider it returns itself if it supports
// Add, or nil otherwise.
//
// Limitation: in a ChainProvider like [hashicorp, age], Get() returns from
// the first provider that has the credential (hashicorp), but findAdder
// returns the first provider that supports Add (age). Refreshed tokens
// would be written to age while subsequent Get() calls still return the
// stale value from hashicorp. In practice this is not an issue because
// only the age backend (vault.Store) implements Add. If additional
// writable providers are added in the future, this function should be
// updated to prefer the provider that originally served the credential.
func findAdder(p vault.Provider) adder {
	if a, ok := p.(adder); ok {
		return a
	}
	type chainLike interface {
		Providers() []vault.Provider
	}
	if chain, ok := p.(chainLike); ok {
		for _, inner := range chain.Providers() {
			if a, ok := inner.(adder); ok {
				return a
			}
		}
	}
	return nil
}
