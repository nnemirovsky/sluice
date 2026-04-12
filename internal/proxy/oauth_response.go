package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

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
