package proxy

import (
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

func TestNewOAuthIndexFiltersOAuthEntries(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "static_cred", CredType: "static", TokenURL: ""},
		{Name: "oauth_cred", CredType: "oauth", TokenURL: "https://auth.example.com/oauth/token"},
		{Name: "another_static", CredType: "static", TokenURL: ""},
		{Name: "google_oauth", CredType: "oauth", TokenURL: "https://oauth2.googleapis.com/token"},
	}

	idx := NewOAuthIndex(metas)

	if idx.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", idx.Len())
	}
}

func TestNewOAuthIndexSkipsEmptyTokenURL(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "bad_oauth", CredType: "oauth", TokenURL: ""},
	}

	idx := NewOAuthIndex(metas)

	if idx.Len() != 0 {
		t.Fatalf("expected 0 entries for oauth with empty token_url, got %d", idx.Len())
	}
}

func TestNewOAuthIndexSkipsInvalidURL(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "bad_url", CredType: "oauth", TokenURL: "://missing-scheme"},
	}

	idx := NewOAuthIndex(metas)

	if idx.Len() != 0 {
		t.Fatalf("expected 0 entries for invalid URL, got %d", idx.Len())
	}
}

func TestNewOAuthIndexSkipsMissingHost(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "no_host", CredType: "oauth", TokenURL: "https:///just-path"},
	}

	idx := NewOAuthIndex(metas)

	if idx.Len() != 0 {
		t.Fatalf("expected 0 entries for URL without host, got %d", idx.Len())
	}
}

func TestNewOAuthIndexNilMetas(t *testing.T) {
	idx := NewOAuthIndex(nil)

	if idx.Len() != 0 {
		t.Fatalf("expected 0 entries for nil metas, got %d", idx.Len())
	}
}

func TestOAuthIndexMatchExact(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "openai_oauth", CredType: "oauth", TokenURL: "https://auth0.openai.com/oauth/token"},
		{Name: "google_oauth", CredType: "oauth", TokenURL: "https://oauth2.googleapis.com/token"},
	}
	idx := NewOAuthIndex(metas)

	u, _ := url.Parse("https://auth0.openai.com/oauth/token")
	name, ok := idx.Match(u)
	if !ok {
		t.Fatal("expected match for openai token URL")
	}
	if name != "openai_oauth" {
		t.Errorf("expected credential name %q, got %q", "openai_oauth", name)
	}

	u, _ = url.Parse("https://oauth2.googleapis.com/token")
	name, ok = idx.Match(u)
	if !ok {
		t.Fatal("expected match for google token URL")
	}
	if name != "google_oauth" {
		t.Errorf("expected credential name %q, got %q", "google_oauth", name)
	}
}

func TestOAuthIndexMatchIgnoresQuery(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "test_oauth", CredType: "oauth", TokenURL: "https://auth.example.com/token"},
	}
	idx := NewOAuthIndex(metas)

	u, _ := url.Parse("https://auth.example.com/token?client_id=abc&grant_type=refresh_token")
	name, ok := idx.Match(u)
	if !ok {
		t.Fatal("expected match even with query parameters")
	}
	if name != "test_oauth" {
		t.Errorf("expected credential name %q, got %q", "test_oauth", name)
	}
}

func TestOAuthIndexNoMatchDifferentScheme(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "test_oauth", CredType: "oauth", TokenURL: "https://auth.example.com/token"},
	}
	idx := NewOAuthIndex(metas)

	u, _ := url.Parse("http://auth.example.com/token")
	_, ok := idx.Match(u)
	if ok {
		t.Error("expected no match for different scheme (http vs https)")
	}
}

func TestOAuthIndexNoMatchDifferentHost(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "test_oauth", CredType: "oauth", TokenURL: "https://auth.example.com/token"},
	}
	idx := NewOAuthIndex(metas)

	u, _ := url.Parse("https://auth.other.com/token")
	_, ok := idx.Match(u)
	if ok {
		t.Error("expected no match for different host")
	}
}

func TestOAuthIndexNoMatchDifferentPath(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "test_oauth", CredType: "oauth", TokenURL: "https://auth.example.com/oauth/token"},
	}
	idx := NewOAuthIndex(metas)

	u, _ := url.Parse("https://auth.example.com/oauth/authorize")
	_, ok := idx.Match(u)
	if ok {
		t.Error("expected no match for different path")
	}
}

func TestOAuthIndexNoMatch(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "test_oauth", CredType: "oauth", TokenURL: "https://auth.example.com/token"},
	}
	idx := NewOAuthIndex(metas)

	u, _ := url.Parse("https://api.example.com/v1/chat")
	_, ok := idx.Match(u)
	if ok {
		t.Error("expected no match for unrelated URL")
	}
}

func TestOAuthIndexMatchNilURL(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "test_oauth", CredType: "oauth", TokenURL: "https://auth.example.com/token"},
	}
	idx := NewOAuthIndex(metas)

	_, ok := idx.Match(nil)
	if ok {
		t.Error("expected no match for nil URL")
	}
}

func TestOAuthIndexMatchNilIndex(t *testing.T) {
	var idx *OAuthIndex
	u, _ := url.Parse("https://auth.example.com/token")
	_, ok := idx.Match(u)
	if ok {
		t.Error("expected no match for nil index")
	}
}

func TestOAuthIndexMatchEmptyIndex(t *testing.T) {
	idx := NewOAuthIndex(nil)
	u, _ := url.Parse("https://auth.example.com/token")
	_, ok := idx.Match(u)
	if ok {
		t.Error("expected no match for empty index")
	}
}

func TestOAuthIndexMultipleEntries(t *testing.T) {
	metas := []store.CredentialMeta{
		{Name: "openai", CredType: "oauth", TokenURL: "https://auth0.openai.com/oauth/token"},
		{Name: "google", CredType: "oauth", TokenURL: "https://oauth2.googleapis.com/token"},
		{Name: "github", CredType: "oauth", TokenURL: "https://github.com/login/oauth/access_token"},
	}
	idx := NewOAuthIndex(metas)

	tests := []struct {
		url      string
		wantName string
		wantOK   bool
	}{
		{"https://auth0.openai.com/oauth/token", "openai", true},
		{"https://oauth2.googleapis.com/token", "google", true},
		{"https://github.com/login/oauth/access_token", "github", true},
		{"https://other.com/token", "", false},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.url)
		name, ok := idx.Match(u)
		if ok != tt.wantOK {
			t.Errorf("Match(%q): ok = %v, want %v", tt.url, ok, tt.wantOK)
		}
		if name != tt.wantName {
			t.Errorf("Match(%q): name = %q, want %q", tt.url, name, tt.wantName)
		}
	}
}

func TestUpdateOAuthIndexHotReload(t *testing.T) {
	addon := NewSluiceAddon()

	// Initially empty.
	idx := addon.oauthIndex.Load()
	if idx != nil && idx.Len() != 0 {
		t.Fatalf("expected 0 initial entries, got %d", idx.Len())
	}

	// Hot-reload with new metas.
	metas := []store.CredentialMeta{
		{Name: "openai", CredType: "oauth", TokenURL: "https://auth0.openai.com/oauth/token"},
		{Name: "google", CredType: "oauth", TokenURL: "https://oauth2.googleapis.com/token"},
	}
	addon.UpdateOAuthIndex(metas)

	idx = addon.oauthIndex.Load()
	if idx.Len() != 2 {
		t.Fatalf("expected 2 entries after reload, got %d", idx.Len())
	}

	u, _ := url.Parse("https://auth0.openai.com/oauth/token")
	name, ok := idx.Match(u)
	if !ok || name != "openai" {
		t.Errorf("expected match for openai after reload, got name=%q ok=%v", name, ok)
	}

	// Hot-reload again with different metas (simulates credential removal).
	metas2 := []store.CredentialMeta{
		{Name: "google", CredType: "oauth", TokenURL: "https://oauth2.googleapis.com/token"},
	}
	addon.UpdateOAuthIndex(metas2)

	idx = addon.oauthIndex.Load()
	if idx.Len() != 1 {
		t.Fatalf("expected 1 entry after second reload, got %d", idx.Len())
	}

	// Previous entry should no longer match.
	u, _ = url.Parse("https://auth0.openai.com/oauth/token")
	_, ok = idx.Match(u)
	if ok {
		t.Error("expected no match for removed credential after reload")
	}

	// Remaining entry should still match.
	u, _ = url.Parse("https://oauth2.googleapis.com/token")
	name, ok = idx.Match(u)
	if !ok || name != "google" {
		t.Errorf("expected match for google after reload, got name=%q ok=%v", name, ok)
	}
}

func TestOAuthIndexAtomicSwap(t *testing.T) {
	// Verify that the atomic pointer swap works correctly.
	var ptr atomic.Pointer[OAuthIndex]

	idx1 := NewOAuthIndex([]store.CredentialMeta{
		{Name: "cred1", CredType: "oauth", TokenURL: "https://a.com/token"},
	})
	ptr.Store(idx1)

	idx2 := NewOAuthIndex([]store.CredentialMeta{
		{Name: "cred2", CredType: "oauth", TokenURL: "https://b.com/token"},
	})
	ptr.Store(idx2)

	loaded := ptr.Load()
	if loaded.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", loaded.Len())
	}

	u, _ := url.Parse("https://b.com/token")
	name, ok := loaded.Match(u)
	if !ok || name != "cred2" {
		t.Errorf("expected match for cred2 after swap, got name=%q ok=%v", name, ok)
	}

	// Old index should not match new URL.
	u, _ = url.Parse("https://a.com/token")
	_, ok = loaded.Match(u)
	if ok {
		t.Error("expected no match for old URL after swap")
	}
}

func TestOAuthIndexMatchDefaultPortNormalization(t *testing.T) {
	tests := []struct {
		name     string
		tokenURL string
		reqURL   string
		wantOK   bool
	}{
		{
			name:     "index without port, request with :443",
			tokenURL: "https://auth.example.com/token",
			reqURL:   "https://auth.example.com:443/token",
			wantOK:   true,
		},
		{
			name:     "index with :443, request without port",
			tokenURL: "https://auth.example.com:443/token",
			reqURL:   "https://auth.example.com/token",
			wantOK:   true,
		},
		{
			name:     "http index without port, request with :80",
			tokenURL: "http://auth.example.com/token",
			reqURL:   "http://auth.example.com:80/token",
			wantOK:   true,
		},
		{
			name:     "non-default port must match exactly",
			tokenURL: "https://auth.example.com:8443/token",
			reqURL:   "https://auth.example.com/token",
			wantOK:   false,
		},
		{
			name:     "non-default port matches same port",
			tokenURL: "https://auth.example.com:8443/token",
			reqURL:   "https://auth.example.com:8443/token",
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metas := []store.CredentialMeta{
				{Name: "cred", CredType: "oauth", TokenURL: tt.tokenURL},
			}
			idx := NewOAuthIndex(metas)
			u, _ := url.Parse(tt.reqURL)
			_, ok := idx.Match(u)
			if ok != tt.wantOK {
				t.Errorf("Match(%q) against token_url %q: got %v, want %v",
					tt.reqURL, tt.tokenURL, ok, tt.wantOK)
			}
		})
	}
}
