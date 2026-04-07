package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
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

// interceptOAuthResponse is a goproxy response handler that detects OAuth
// token responses and replaces real tokens with deterministic phantom tokens.
// It reads the response body, swaps tokens, and returns the modified response
// immediately. Vault persistence happens asynchronously to avoid blocking.
func (inj *Injector) interceptOAuthResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || ctx.Req == nil {
		return resp
	}

	// Only intercept successful responses.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp
	}

	idx := inj.oauthIndex.Load()
	if idx == nil {
		return resp
	}

	credName, ok := idx.Match(ctx.Req.URL)
	if !ok {
		return resp
	}

	// Each response must be independently processed since goproxy delivers
	// a unique *http.Response per request. Singleflight is used only for
	// the async vault persistence goroutine to prevent concurrent writes.
	modified, _ := inj.processOAuthResponse(resp, credName)
	if modified != nil {
		return modified
	}
	return resp
}

// processOAuthResponse reads the token response body, replaces real tokens
// with phantoms, and schedules an async vault update. Returns the modified
// response or nil if processing fails (caller returns original response).
func (inj *Injector) processOAuthResponse(resp *http.Response, credName string) (*http.Response, error) {
	if resp.Body == nil {
		return nil, fmt.Errorf("nil body")
	}

	// Read the body with the same size limit as requests.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody+1))
	_ = resp.Body.Close()
	if err != nil {
		log.Printf("[INJECT-OAUTH] body read error for credential %q: %v", credName, err)
		// Cannot return unchanged since we already consumed and closed the
		// original body. An empty body is unavoidable here. The agent will
		// see an empty response for this request, which is acceptable since
		// the read failure means the data was already lost.
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return resp, nil
	}
	if int64(len(body)) > maxProxyBody {
		log.Printf("[INJECT-OAUTH] response body exceeds %d bytes for credential %q, passing through", maxProxyBody, credName)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	contentType := resp.Header.Get("Content-Type")
	tr, err := parseTokenResponse(body, contentType)
	if err != nil {
		log.Printf("[INJECT-OAUTH] failed to parse token response for credential %q: %v", credName, err)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	accessPhantom := oauthPhantomAccess(credName, tr.AccessToken)
	refreshPhantom := oauthPhantomRefresh(credName, tr.RefreshToken)

	// Replace real tokens with phantoms in the response body.
	// Do this as byte-level replacement so it works for both JSON and form
	// encoded responses without needing to re-serialize.
	// Replace the longer token first to prevent substring corruption when
	// one token is a prefix of the other.
	modified := body
	if tr.RefreshToken != "" {
		if len(tr.RefreshToken) >= len(tr.AccessToken) {
			modified = bytes.ReplaceAll(modified, []byte(tr.RefreshToken), []byte(refreshPhantom))
			modified = bytes.ReplaceAll(modified, []byte(tr.AccessToken), []byte(accessPhantom))
		} else {
			modified = bytes.ReplaceAll(modified, []byte(tr.AccessToken), []byte(accessPhantom))
			modified = bytes.ReplaceAll(modified, []byte(tr.RefreshToken), []byte(refreshPhantom))
		}
	} else {
		modified = bytes.ReplaceAll(modified, []byte(tr.AccessToken), []byte(accessPhantom))
	}

	// Update the response with modified body.
	resp.Body = io.NopCloser(bytes.NewReader(modified))
	resp.ContentLength = int64(len(modified))
	resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
	resp.Header.Del("Transfer-Encoding")

	log.Printf("[INJECT-OAUTH] intercepted token response for credential %q, swapped to phantoms", credName)

	// Asynchronously persist the new tokens to the vault.
	// The agent already has phantom tokens. Vault write failure is logged
	// but does not block the response.
	realAccess := vault.NewSecureBytes(tr.AccessToken)
	realRefresh := vault.NewSecureBytes(tr.RefreshToken)
	expiresIn := tr.ExpiresIn

	go inj.persistOAuthTokens(credName, realAccess, realRefresh, expiresIn)

	return resp, nil
}

// persistOAuthTokens updates the vault with new real tokens from a token
// response. Called asynchronously from processOAuthResponse. Uses SecureBytes
// and releases them after the vault write.
func (inj *Injector) persistOAuthTokens(credName string, realAccess, realRefresh vault.SecureBytes, expiresIn int) {
	defer realAccess.Release()
	defer realRefresh.Release()
	if inj.persistDone != nil {
		defer func() { inj.persistDone <- struct{}{} }()
	}

	// Load existing OAuth credential from vault to preserve token_url and
	// other metadata.
	existing, err := inj.provider.Get(credName)
	if err != nil {
		log.Printf("[INJECT-OAUTH] vault read failed for credential %q: %v", credName, err)
		return
	}
	defer existing.Release()

	cred, err := vault.ParseOAuth(existing.Bytes())
	if err != nil {
		log.Printf("[INJECT-OAUTH] parse existing oauth credential %q failed: %v", credName, err)
		return
	}

	cred.UpdateTokens(realAccess.String(), realRefresh.String(), expiresIn)

	data, err := cred.Marshal()
	if err != nil {
		log.Printf("[INJECT-OAUTH] marshal updated oauth credential %q failed: %v", credName, err)
		return
	}

	// Use singleflight to deduplicate concurrent vault writes for the same
	// credential. Multiple simultaneous token responses can trigger parallel
	// persist goroutines, but only one write is necessary.
	//
	// Safety: when two goroutines race here with different data, the deduped
	// goroutine's write is skipped. This is safe because concurrent token
	// responses for the same credential come from the same refresh_token
	// grant, so both carry identical access/refresh values. If the provider
	// uses rotating refresh tokens, the second request would fail at the
	// provider before reaching this code.
	_, _, shared := inj.refreshGroup.Do("persist:"+credName, func() (interface{}, error) {
		adder := findAdder(inj.provider)
		if adder == nil {
			log.Printf("[INJECT-OAUTH] provider does not support Add for credential %q", credName)
			return nil, fmt.Errorf("provider does not support Add")
		}
		if _, err := adder.Add(credName, string(data)); err != nil {
			log.Printf("[INJECT-OAUTH] vault write failed for credential %q: %v", credName, err)
			return nil, err
		}
		return nil, nil
	})

	if shared {
		log.Printf("[INJECT-OAUTH] deduplicated concurrent persist for credential %q", credName)
	} else {
		log.Printf("[INJECT-OAUTH] persisted updated tokens for credential %q", credName)
	}

	// Notify the caller so updated phantom env vars can be re-injected
	// into the agent container (e.g. via docker exec).
	if inj.onOAuthRefresh != nil {
		inj.onOAuthRefresh(credName)
	}
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
