package vault

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseOAuth(t *testing.T) {
	t.Run("valid full credential", func(t *testing.T) {
		data := []byte(`{
			"access_token": "real-access-token",
			"refresh_token": "real-refresh-token",
			"token_url": "https://auth0.openai.com/oauth/token",
			"expires_at": "2026-04-07T12:00:00Z"
		}`)
		cred, err := ParseOAuth(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.AccessToken != "real-access-token" {
			t.Errorf("access_token = %q, want %q", cred.AccessToken, "real-access-token")
		}
		if cred.RefreshToken != "real-refresh-token" {
			t.Errorf("refresh_token = %q, want %q", cred.RefreshToken, "real-refresh-token")
		}
		if cred.TokenURL != "https://auth0.openai.com/oauth/token" {
			t.Errorf("token_url = %q, want %q", cred.TokenURL, "https://auth0.openai.com/oauth/token")
		}
		if cred.ExpiresAt.IsZero() {
			t.Error("expires_at should not be zero")
		}
	})

	t.Run("valid without refresh token", func(t *testing.T) {
		data := []byte(`{
			"access_token": "access-only",
			"token_url": "https://example.com/token"
		}`)
		cred, err := ParseOAuth(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.AccessToken != "access-only" {
			t.Errorf("access_token = %q, want %q", cred.AccessToken, "access-only")
		}
		if cred.RefreshToken != "" {
			t.Errorf("refresh_token should be empty, got %q", cred.RefreshToken)
		}
	})

	t.Run("missing access_token", func(t *testing.T) {
		data := []byte(`{
			"token_url": "https://example.com/token"
		}`)
		_, err := ParseOAuth(data)
		if err == nil {
			t.Fatal("expected error for missing access_token")
		}
	})

	t.Run("missing token_url", func(t *testing.T) {
		data := []byte(`{
			"access_token": "some-token"
		}`)
		_, err := ParseOAuth(data)
		if err == nil {
			t.Fatal("expected error for missing token_url")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParseOAuth([]byte(`not json`))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParseOAuth([]byte{})
		if err == nil {
			t.Fatal("expected error for empty input")
		}
	})
}

func TestOAuthCredentialMarshal(t *testing.T) {
	cred := &OAuthCredential{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		TokenURL:     "https://auth.example.com/token",
		ExpiresAt:    time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC),
	}

	data, err := cred.Marshal()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse it back to verify round-trip.
	parsed, err := ParseOAuth(data)
	if err != nil {
		t.Fatalf("round-trip parse error: %v", err)
	}
	if parsed.AccessToken != cred.AccessToken {
		t.Errorf("access_token = %q, want %q", parsed.AccessToken, cred.AccessToken)
	}
	if parsed.RefreshToken != cred.RefreshToken {
		t.Errorf("refresh_token = %q, want %q", parsed.RefreshToken, cred.RefreshToken)
	}
	if parsed.TokenURL != cred.TokenURL {
		t.Errorf("token_url = %q, want %q", parsed.TokenURL, cred.TokenURL)
	}
	if !parsed.ExpiresAt.Equal(cred.ExpiresAt) {
		t.Errorf("expires_at = %v, want %v", parsed.ExpiresAt, cred.ExpiresAt)
	}
}

func TestOAuthCredentialMarshalRoundTrip(t *testing.T) {
	t.Run("without optional fields", func(t *testing.T) {
		cred := &OAuthCredential{
			AccessToken: "access-only",
			TokenURL:    "https://example.com/token",
		}
		data, err := cred.Marshal()
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		parsed, err := ParseOAuth(data)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if parsed.RefreshToken != "" {
			t.Errorf("refresh_token should be empty, got %q", parsed.RefreshToken)
		}
		if !parsed.ExpiresAt.IsZero() {
			t.Errorf("expires_at should be zero, got %v", parsed.ExpiresAt)
		}
	})
}

func TestUpdateTokens(t *testing.T) {
	t.Run("both tokens updated", func(t *testing.T) {
		cred := &OAuthCredential{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			TokenURL:     "https://example.com/token",
		}

		before := time.Now()
		cred.UpdateTokens("new-access", "new-refresh", 3600)

		if cred.AccessToken != "new-access" {
			t.Errorf("access_token = %q, want %q", cred.AccessToken, "new-access")
		}
		if cred.RefreshToken != "new-refresh" {
			t.Errorf("refresh_token = %q, want %q", cred.RefreshToken, "new-refresh")
		}

		// ExpiresAt should be approximately 1 hour from now.
		expectedMin := before.Add(3599 * time.Second)
		expectedMax := before.Add(3601 * time.Second)
		if cred.ExpiresAt.Before(expectedMin) || cred.ExpiresAt.After(expectedMax) {
			t.Errorf("expires_at = %v, want approximately %v", cred.ExpiresAt, before.Add(3600*time.Second))
		}
	})

	t.Run("access only, refresh preserved", func(t *testing.T) {
		cred := &OAuthCredential{
			AccessToken:  "old-access",
			RefreshToken: "keep-this-refresh",
			TokenURL:     "https://example.com/token",
		}

		cred.UpdateTokens("new-access", "", 7200)

		if cred.AccessToken != "new-access" {
			t.Errorf("access_token = %q, want %q", cred.AccessToken, "new-access")
		}
		if cred.RefreshToken != "keep-this-refresh" {
			t.Errorf("refresh_token should be preserved, got %q", cred.RefreshToken)
		}
	})

	t.Run("no expires_in", func(t *testing.T) {
		cred := &OAuthCredential{
			AccessToken: "old-access",
			TokenURL:    "https://example.com/token",
		}

		cred.UpdateTokens("new-access", "new-refresh", 0)

		if cred.AccessToken != "new-access" {
			t.Errorf("access_token = %q, want %q", cred.AccessToken, "new-access")
		}
		if !cred.ExpiresAt.IsZero() {
			t.Errorf("expires_at should remain zero when expiresIn=0, got %v", cred.ExpiresAt)
		}
	})
}

func TestIsOAuth(t *testing.T) {
	t.Run("valid oauth JSON", func(t *testing.T) {
		data := []byte(`{"access_token": "tok", "token_url": "https://example.com/token"}`)
		if !IsOAuth(data) {
			t.Error("expected IsOAuth to return true for valid OAuth JSON")
		}
	})

	t.Run("full oauth JSON", func(t *testing.T) {
		data := []byte(`{
			"access_token": "tok",
			"refresh_token": "ref",
			"token_url": "https://example.com/token",
			"expires_at": "2026-04-07T12:00:00Z"
		}`)
		if !IsOAuth(data) {
			t.Error("expected IsOAuth to return true for full OAuth JSON")
		}
	})

	t.Run("missing access_token", func(t *testing.T) {
		data := []byte(`{"token_url": "https://example.com/token"}`)
		if IsOAuth(data) {
			t.Error("expected IsOAuth to return false without access_token")
		}
	})

	t.Run("missing token_url", func(t *testing.T) {
		data := []byte(`{"access_token": "tok"}`)
		if IsOAuth(data) {
			t.Error("expected IsOAuth to return false without token_url")
		}
	})

	t.Run("static credential", func(t *testing.T) {
		data := []byte(`ghp_abc123secrettoken456`)
		if IsOAuth(data) {
			t.Error("expected IsOAuth to return false for non-JSON data")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		data := []byte(`{invalid json}`)
		if IsOAuth(data) {
			t.Error("expected IsOAuth to return false for invalid JSON")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if IsOAuth([]byte{}) {
			t.Error("expected IsOAuth to return false for empty input")
		}
	})

	t.Run("empty fields", func(t *testing.T) {
		data := []byte(`{"access_token": "", "token_url": ""}`)
		if IsOAuth(data) {
			t.Error("expected IsOAuth to return false for empty field values")
		}
	})

	t.Run("unrelated JSON", func(t *testing.T) {
		data := []byte(`{"name": "foo", "value": "bar"}`)
		if IsOAuth(data) {
			t.Error("expected IsOAuth to return false for unrelated JSON")
		}
	})
}

func TestOAuthCredentialJSONFields(t *testing.T) {
	// Verify the JSON field names match the expected format.
	cred := &OAuthCredential{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenURL:     "https://example.com/token",
		ExpiresAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data, err := cred.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	requiredFields := []string{"access_token", "token_url"}
	for _, f := range requiredFields {
		if _, ok := raw[f]; !ok {
			t.Errorf("missing required JSON field %q", f)
		}
	}

	optionalFields := []string{"refresh_token", "expires_at"}
	for _, f := range optionalFields {
		if _, ok := raw[f]; !ok {
			t.Errorf("missing optional JSON field %q", f)
		}
	}
}
