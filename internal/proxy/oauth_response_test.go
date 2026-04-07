package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// setupOAuthTestInjector creates an injector with an OAuth credential in the
// vault and the OAuth index populated. Returns the injector, vault store, and
// the backend URL hostname for binding configuration. The injector's
// persistDone channel is initialized so tests can wait for async vault writes
// instead of using time.Sleep.
func setupOAuthTestInjector(t *testing.T, credName, tokenURL string, oauthCred *vault.OAuthCredential) (*Injector, *vault.Store) {
	t.Helper()
	inj, vaultStore := setupTestInjector(t, nil)
	inj.persistDone = make(chan struct{}, 10)

	// Store the OAuth credential in the vault.
	data, err := oauthCred.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultStore.Add(credName, string(data)); err != nil {
		t.Fatal(err)
	}

	// Populate the OAuth index.
	metas := []store.CredentialMeta{
		{Name: credName, CredType: "oauth", TokenURL: tokenURL},
	}
	inj.UpdateOAuthIndex(metas)

	return inj, vaultStore
}

// waitPersist waits for n async persist goroutines to complete, with a
// timeout to prevent tests from hanging.
func waitPersist(t *testing.T, inj *Injector, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-inj.persistDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for persist goroutine %d/%d", i+1, n)
		}
	}
}

func TestInterceptOAuthResponseJSON(t *testing.T) {
	// Token endpoint returns a JSON token response.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token":  "new-real-access-token-12345",
			"refresh_token": "new-real-refresh-token-67890",
			"expires_in":    3600,
			"token_type":    "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "old-real-access-token",
		RefreshToken: "old-real-refresh-token",
		TokenURL:     tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "test_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Real tokens must NOT appear in the response.
	if strings.Contains(bodyStr, "new-real-access-token-12345") {
		t.Error("real access token leaked in response body")
	}
	if strings.Contains(bodyStr, "new-real-refresh-token-67890") {
		t.Error("real refresh token leaked in response body")
	}

	// Phantom tokens must appear instead.
	accessPhantom := oauthPhantomAccess("test_oauth")
	refreshPhantom := oauthPhantomRefresh("test_oauth")

	if !strings.Contains(bodyStr, accessPhantom) {
		t.Errorf("expected access phantom %q in response, got %q", accessPhantom, bodyStr)
	}
	if !strings.Contains(bodyStr, refreshPhantom) {
		t.Errorf("expected refresh phantom %q in response, got %q", refreshPhantom, bodyStr)
	}

	// Content-Length should match modified body.
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, body length = %d", resp.ContentLength, len(body))
	}

	waitPersist(t, inj, 1)
}

func TestInterceptOAuthResponseFormEncoded(t *testing.T) {
	// Token endpoint returns a form-encoded response (per RFC 6749).
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = fmt.Fprint(w, "access_token=form-real-access&refresh_token=form-real-refresh&expires_in=7200&token_type=bearer")
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "form_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=authorization_code"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "form-real-access") {
		t.Error("real access token leaked in form-encoded response")
	}
	if strings.Contains(bodyStr, "form-real-refresh") {
		t.Error("real refresh token leaked in form-encoded response")
	}

	accessPhantom := oauthPhantomAccess("form_oauth")
	if !strings.Contains(bodyStr, accessPhantom) {
		t.Errorf("expected access phantom in form response, got %q", bodyStr)
	}

	// Also verify refresh phantom in form-encoded response.
	refreshPhantom := oauthPhantomRefresh("form_oauth")
	if !strings.Contains(bodyStr, refreshPhantom) {
		t.Errorf("expected refresh phantom in form response, got %q", bodyStr)
	}

	waitPersist(t, inj, 1)
}

func TestInterceptOAuthResponseOnlyAccessToken(t *testing.T) {
	// Token endpoint returns only access_token, no refresh_token.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": "access-only-real-token",
			"expires_in":   1800,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh-should-be-preserved",
		TokenURL:     tokenEndpoint.URL,
	}

	inj, vaultStore := setupOAuthTestInjector(t, "partial_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "access-only-real-token") {
		t.Error("real access token leaked")
	}
	if !strings.Contains(bodyStr, oauthPhantomAccess("partial_oauth")) {
		t.Errorf("expected access phantom in response, got %q", bodyStr)
	}

	waitPersist(t, inj, 1)

	// Verify vault was updated and refresh_token is preserved.
	stored, err := vaultStore.Get("partial_oauth")
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Release()

	cred, err := vault.ParseOAuth(stored.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "access-only-real-token" {
		t.Errorf("vault access_token = %q, want 'access-only-real-token'", cred.AccessToken)
	}
	if cred.RefreshToken != "old-refresh-should-be-preserved" {
		t.Errorf("vault refresh_token = %q, want 'old-refresh-should-be-preserved'", cred.RefreshToken)
	}
}

func TestInterceptOAuthResponseNon2xx(t *testing.T) {
	// Non-2xx responses should pass through unchanged.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"token expired"}`)
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "err_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "invalid_grant") {
		t.Error("error response body was modified when it should pass through")
	}
}

func TestInterceptOAuthResponseNonMatchingURL(t *testing.T) {
	// A response from a non-token-URL should pass through unchanged.
	apiEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": "this-looks-like-a-token-but-is-not",
			"data":         "some api response",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer apiEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    "https://auth.example.com/oauth/token",
	}

	inj, _ := setupOAuthTestInjector(t, "api_oauth", "https://auth.example.com/oauth/token", oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("GET", apiEndpoint.URL+"/api/data", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	// The response should contain the original token since this URL does not
	// match any configured token_url.
	if !strings.Contains(string(body), "this-looks-like-a-token-but-is-not") {
		t.Error("non-matching URL response was modified when it should pass through")
	}
}

func TestInterceptOAuthResponseVaultPersistence(t *testing.T) {
	// Verify that the vault is updated with new tokens after interception.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token":  "updated-access-token",
			"refresh_token": "updated-refresh-token",
			"expires_in":    7200,
			"token_type":    "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "original-access",
		RefreshToken: "original-refresh",
		TokenURL:     tokenEndpoint.URL,
	}

	inj, vaultStore := setupOAuthTestInjector(t, "persist_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	waitPersist(t, inj, 1)

	stored, err := vaultStore.Get("persist_oauth")
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Release()

	cred, err := vault.ParseOAuth(stored.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "updated-access-token" {
		t.Errorf("vault access_token = %q, want 'updated-access-token'", cred.AccessToken)
	}
	if cred.RefreshToken != "updated-refresh-token" {
		t.Errorf("vault refresh_token = %q, want 'updated-refresh-token'", cred.RefreshToken)
	}
	if cred.ExpiresAt.IsZero() {
		t.Error("vault expires_at should be set")
	}
	// TokenURL should be preserved from original credential.
	if cred.TokenURL != tokenEndpoint.URL {
		t.Errorf("vault token_url = %q, want %q", cred.TokenURL, tokenEndpoint.URL)
	}
}

func TestInterceptOAuthResponseConcurrentRefreshDedup(t *testing.T) {
	// Verify that singleflight deduplicates concurrent token refreshes.
	var mu sync.Mutex
	requestCount := 0

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requestCount++
		count := requestCount
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token":  fmt.Sprintf("concurrent-access-%d", count),
			"refresh_token": fmt.Sprintf("concurrent-refresh-%d", count),
			"expires_in":    3600,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenURL:     tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "dedup_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)

	// Send multiple concurrent requests to the token endpoint.
	var wg sync.WaitGroup
	results := make([]string, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
			}
			req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			results[idx] = string(body)
		}(i)
	}
	wg.Wait()

	// Wait for async vault write goroutines. Each response triggers a persist
	// goroutine (singleflight deduplicates the vault write, not the goroutine).
	// Count non-empty results to know how many goroutines were spawned.
	nonEmpty := 0
	for _, body := range results {
		if body != "" {
			nonEmpty++
		}
	}
	waitPersist(t, inj, nonEmpty)

	// All responses should contain phantom tokens, not real tokens.
	accessPhantom := oauthPhantomAccess("dedup_oauth")
	for i, body := range results {
		if body == "" {
			continue
		}
		if !strings.Contains(body, accessPhantom) {
			t.Errorf("response %d missing access phantom: %s", i, body)
		}
		if strings.Contains(body, "concurrent-access-") {
			t.Errorf("response %d leaked real access token: %s", i, body)
		}
	}
}

func TestInterceptOAuthResponseNonJSONContentType(t *testing.T) {
	// Non-JSON/non-form content type that happens to contain token-like fields
	// should fail parsing and pass through unchanged.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "this is not a token response")
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "plain_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "this is not a token response" {
		t.Errorf("non-JSON response was modified: %q", string(body))
	}
}

func TestInterceptOAuthResponseTransferEncodingCleared(t *testing.T) {
	// Verify that Transfer-Encoding is cleared and Content-Length is set.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Transfer-Encoding", "chunked")
		resp := map[string]interface{}{
			"access_token": "real-token-for-te-test",
			"expires_in":   3600,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "te_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	// The phantom token should be present.
	if !strings.Contains(string(body), oauthPhantomAccess("te_oauth")) {
		t.Errorf("expected access phantom in response, got %q", string(body))
	}

	// Content-Length should match body.
	if resp.ContentLength >= 0 && resp.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length %d does not match body length %d", resp.ContentLength, len(body))
	}

	waitPersist(t, inj, 1)
}

func TestParseTokenResponseJSON(t *testing.T) {
	body := []byte(`{"access_token":"at-123","refresh_token":"rt-456","expires_in":3600,"token_type":"Bearer"}`)
	tr, err := parseTokenResponse(body, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "at-123" {
		t.Errorf("access_token = %q, want 'at-123'", tr.AccessToken)
	}
	if tr.RefreshToken != "rt-456" {
		t.Errorf("refresh_token = %q, want 'rt-456'", tr.RefreshToken)
	}
	if tr.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", tr.ExpiresIn)
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want 'Bearer'", tr.TokenType)
	}
}

func TestParseTokenResponseFormEncoded(t *testing.T) {
	body := []byte("access_token=at-abc&refresh_token=rt-def&expires_in=7200&token_type=bearer")
	tr, err := parseTokenResponse(body, "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "at-abc" {
		t.Errorf("access_token = %q, want 'at-abc'", tr.AccessToken)
	}
	if tr.RefreshToken != "rt-def" {
		t.Errorf("refresh_token = %q, want 'rt-def'", tr.RefreshToken)
	}
	if tr.ExpiresIn != 7200 {
		t.Errorf("expires_in = %d, want 7200", tr.ExpiresIn)
	}
}

func TestParseTokenResponseFormEncodedWithCharset(t *testing.T) {
	body := []byte("access_token=at-xyz&token_type=bearer")
	tr, err := parseTokenResponse(body, "application/x-www-form-urlencoded; charset=utf-8")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "at-xyz" {
		t.Errorf("access_token = %q, want 'at-xyz'", tr.AccessToken)
	}
}

func TestParseTokenResponseMissingAccessToken(t *testing.T) {
	body := []byte(`{"refresh_token":"rt-only","expires_in":3600}`)
	_, err := parseTokenResponse(body, "application/json")
	if err == nil {
		t.Error("expected error for missing access_token")
	}
}

func TestParseTokenResponseInvalidJSON(t *testing.T) {
	body := []byte(`{not valid json`)
	_, err := parseTokenResponse(body, "application/json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestOAuthPhantomTokenFormat(t *testing.T) {
	access := oauthPhantomAccess("my_cred")
	if access != "SLUICE_PHANTOM:my_cred.access" {
		t.Errorf("access phantom = %q, want 'SLUICE_PHANTOM:my_cred.access'", access)
	}

	refresh := oauthPhantomRefresh("my_cred")
	if refresh != "SLUICE_PHANTOM:my_cred.refresh" {
		t.Errorf("refresh phantom = %q, want 'SLUICE_PHANTOM:my_cred.refresh'", refresh)
	}
}

func TestInterceptOAuthResponseEmptyIndex(t *testing.T) {
	// With an empty OAuth index, all responses should pass through unchanged.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": "some-token-value",
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer backend.Close()

	inj, _ := setupTestInjector(t, nil)
	// OAuth index is empty by default.

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", backend.URL+"/token", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "some-token-value") {
		t.Error("response was modified despite empty OAuth index")
	}
}

func TestInterceptOAuthResponseMultipleCredentials(t *testing.T) {
	// Test with multiple OAuth credentials and verify correct one is matched.
	tokenEndpoint1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "real-token-for-cred1",
			"refresh_token": "real-refresh-for-cred1",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint1.Close()

	tokenEndpoint2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "real-token-for-cred2",
			"refresh_token": "real-refresh-for-cred2",
			"expires_in":    1800,
		})
	}))
	defer tokenEndpoint2.Close()

	inj, vaultStore := setupTestInjector(t, nil)
	inj.persistDone = make(chan struct{}, 10)

	// Store two OAuth credentials.
	cred1 := &vault.OAuthCredential{
		AccessToken: "old-access-1",
		TokenURL:    tokenEndpoint1.URL,
	}
	data1, _ := cred1.Marshal()
	_, _ = vaultStore.Add("cred1", string(data1))

	cred2 := &vault.OAuthCredential{
		AccessToken: "old-access-2",
		TokenURL:    tokenEndpoint2.URL,
	}
	data2, _ := cred2.Marshal()
	_, _ = vaultStore.Add("cred2", string(data2))

	metas := []store.CredentialMeta{
		{Name: "cred1", CredType: "oauth", TokenURL: tokenEndpoint1.URL},
		{Name: "cred2", CredType: "oauth", TokenURL: tokenEndpoint2.URL},
	}
	inj.UpdateOAuthIndex(metas)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Request to endpoint 1 should use cred1 phantoms.
	req1, _ := http.NewRequest("POST", tokenEndpoint1.URL, nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()

	if !strings.Contains(string(body1), oauthPhantomAccess("cred1")) {
		t.Errorf("expected cred1 phantom in response to endpoint1, got %q", string(body1))
	}
	if strings.Contains(string(body1), oauthPhantomAccess("cred2")) {
		t.Error("cred2 phantom should not appear in response to endpoint1")
	}

	// Request to endpoint 2 should use cred2 phantoms.
	req2, _ := http.NewRequest("POST", tokenEndpoint2.URL, nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	if !strings.Contains(string(body2), oauthPhantomAccess("cred2")) {
		t.Errorf("expected cred2 phantom in response to endpoint2, got %q", string(body2))
	}

	waitPersist(t, inj, 2)
}

func TestInterceptOAuthResponseVaultWriteFailure(t *testing.T) {
	// Even if the vault write would fail (e.g., provider doesn't support Add),
	// the response should still contain phantom tokens. We test this by using
	// a provider wrapper that does not implement Add.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "real-token-vault-fail",
			"refresh_token": "real-refresh-vault-fail",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    tokenEndpoint.URL,
	}

	// Use a read-only provider wrapper that does not implement Add.
	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	data, err := oauthCred.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultStore.Add("vfail_oauth", string(data)); err != nil {
		t.Fatal(err)
	}

	// Wrap with a readOnlyProvider that strips the Add interface.
	readOnly := &readOnlyProvider{inner: vaultStore}

	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)
	wsProxy, _ := NewWSProxy(readOnly, &resolverPtr, nil, nil)
	inj := NewInjector(readOnly, &resolverPtr, caCert, "", wsProxy)
	inj.persistDone = make(chan struct{}, 10)

	metas := []store.CredentialMeta{
		{Name: "vfail_oauth", CredType: "oauth", TokenURL: tokenEndpoint.URL},
	}
	inj.UpdateOAuthIndex(metas)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Real tokens must not leak even if vault write fails.
	if strings.Contains(bodyStr, "real-token-vault-fail") {
		t.Error("real access token leaked despite vault write failure")
	}
	if !strings.Contains(bodyStr, oauthPhantomAccess("vfail_oauth")) {
		t.Errorf("expected access phantom despite vault write failure, got %q", bodyStr)
	}

	waitPersist(t, inj, 1)
}

func TestInterceptOAuthResponseOnRefreshCallback(t *testing.T) {
	// Verify that the onOAuthRefresh callback is invoked after vault
	// persistence when configured.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-real-access-for-callback",
			"refresh_token": "new-real-refresh-for-callback",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenURL:     tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "callback_oauth", tokenEndpoint.URL, oauthCred)

	// Configure onOAuthRefresh callback.
	var callbackCredName string
	inj.SetOnOAuthRefresh(func(credName string) {
		callbackCredName = credName
	})

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	waitPersist(t, inj, 1)

	// Verify the callback was invoked with the correct credential name.
	if callbackCredName != "callback_oauth" {
		t.Errorf("onOAuthRefresh callback credName = %q, want %q", callbackCredName, "callback_oauth")
	}
}

func TestInterceptOAuthResponseNoCallbackWithoutConfig(t *testing.T) {
	// When onOAuthRefresh is not set, phantom swap still works but no
	// callback is invoked.
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "access-no-cb",
			"refresh_token": "refresh-no-cb",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenURL:     tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "no_cb_oauth", tokenEndpoint.URL, oauthCred)
	// Do NOT set onOAuthRefresh.

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	bodyStr := string(body)

	// Real tokens must not appear in the response.
	if strings.Contains(bodyStr, "access-no-cb") {
		t.Error("real access token leaked in response")
	}
	if strings.Contains(bodyStr, "refresh-no-cb") {
		t.Error("real refresh token leaked in response")
	}

	// Phantom tokens must be present.
	if !strings.Contains(bodyStr, oauthPhantomAccess("no_cb_oauth")) {
		t.Errorf("expected access phantom in response, got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, oauthPhantomRefresh("no_cb_oauth")) {
		t.Errorf("expected refresh phantom in response, got %q", bodyStr)
	}

	waitPersist(t, inj, 1)
}

func TestInterceptOAuthResponseOversizedBody(t *testing.T) {
	// Response body exceeding maxProxyBody (16 MiB) should pass through
	// unchanged without phantom replacement.
	bigBody := strings.Repeat("x", maxProxyBody+1)
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bigBody))
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken: "old-access",
		TokenURL:    tokenEndpoint.URL,
	}

	inj, _ := setupOAuthTestInjector(t, "oversized_oauth", tokenEndpoint.URL, oauthCred)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Oversized body should pass through (no phantom replacement, no persist).
	if len(body) < maxProxyBody {
		t.Errorf("expected body length >= %d, got %d", maxProxyBody, len(body))
	}
}

// readOnlyProvider wraps a vault.Provider but does not implement the Add interface,
// so persistOAuthTokens will fail gracefully.
type readOnlyProvider struct {
	inner vault.Provider
}

func (p *readOnlyProvider) Get(name string) (vault.SecureBytes, error) {
	return p.inner.Get(name)
}

func (p *readOnlyProvider) List() ([]string, error) {
	return p.inner.List()
}

func (p *readOnlyProvider) Name() string {
	return "read-only-test"
}

func TestInterceptOAuthResponseChainProviderPersistence(t *testing.T) {
	// Verify that OAuth token persistence works when the injector uses a
	// ChainProvider wrapping a vault.Store (which implements Add).
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "chain-updated-access",
			"refresh_token": "chain-updated-refresh",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	oauthCred := &vault.OAuthCredential{
		AccessToken:  "chain-old-access",
		RefreshToken: "chain-old-refresh",
		TokenURL:     tokenEndpoint.URL,
	}

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	data, err := oauthCred.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultStore.Add("chain_oauth", string(data)); err != nil {
		t.Fatal(err)
	}

	// Wrap the store in a ChainProvider so the Add type assertion on the
	// outer provider fails. The fix should walk inner providers.
	chain := vault.NewChainProvider(vaultStore)

	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)
	wsProxy, _ := NewWSProxy(chain, &resolverPtr, nil, nil)
	inj := NewInjector(chain, &resolverPtr, caCert, "", wsProxy)
	inj.persistDone = make(chan struct{}, 10)

	metas := []store.CredentialMeta{
		{Name: "chain_oauth", CredType: "oauth", TokenURL: tokenEndpoint.URL},
	}
	inj.UpdateOAuthIndex(metas)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", tokenEndpoint.URL, strings.NewReader("grant_type=refresh_token"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	waitPersist(t, inj, 1)

	// Verify the vault was updated through the chain.
	stored, err := vaultStore.Get("chain_oauth")
	if err != nil {
		t.Fatalf("get from vault after chain persist: %v", err)
	}
	defer stored.Release()

	cred, err := vault.ParseOAuth(stored.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "chain-updated-access" {
		t.Errorf("vault access_token = %q, want 'chain-updated-access'", cred.AccessToken)
	}
	if cred.RefreshToken != "chain-updated-refresh" {
		t.Errorf("vault refresh_token = %q, want 'chain-updated-refresh'", cred.RefreshToken)
	}
}

func TestFindAdderDirect(t *testing.T) {
	dir := t.TempDir()
	s, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAdder(s)
	if a == nil {
		t.Fatal("expected non-nil adder for vault.Store")
	}
}

func TestFindAdderChain(t *testing.T) {
	dir := t.TempDir()
	s, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	chain := vault.NewChainProvider(s)
	a := findAdder(chain)
	if a == nil {
		t.Fatal("expected non-nil adder for ChainProvider wrapping vault.Store")
	}
}

func TestFindAdderReadOnlyChain(t *testing.T) {
	dir := t.TempDir()
	s, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	readOnly := &readOnlyProvider{inner: s}
	chain := vault.NewChainProvider(readOnly)
	a := findAdder(chain)
	if a != nil {
		t.Fatal("expected nil adder for ChainProvider wrapping readOnlyProvider")
	}
}

func TestFindAdderNil(t *testing.T) {
	readOnly := &readOnlyProvider{}
	a := findAdder(readOnly)
	if a != nil {
		t.Fatal("expected nil adder for readOnlyProvider")
	}
}
