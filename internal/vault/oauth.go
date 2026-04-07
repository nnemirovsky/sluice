package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// OAuthCredential represents an OAuth credential stored in the vault.
// The vault stores only real token values. Phantom tokens are deterministic,
// derived from the credential name at runtime.
type OAuthCredential struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenURL     string    `json:"token_url"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// ParseOAuth parses a JSON blob from the vault into an OAuthCredential.
func ParseOAuth(data []byte) (*OAuthCredential, error) {
	var cred OAuthCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("parse oauth credential: %w", err)
	}
	if cred.AccessToken == "" {
		return nil, fmt.Errorf("parse oauth credential: missing access_token")
	}
	if cred.TokenURL == "" {
		return nil, fmt.Errorf("parse oauth credential: missing token_url")
	}
	return &cred, nil
}

// Marshal serializes the OAuthCredential to JSON.
func (c *OAuthCredential) Marshal() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal oauth credential: %w", err)
	}
	return data, nil
}

// UpdateTokens updates the real tokens and computes ExpiresAt from expiresIn
// seconds. If refresh is empty, the existing RefreshToken is preserved.
func (c *OAuthCredential) UpdateTokens(access, refresh string, expiresIn int) {
	c.AccessToken = access
	if refresh != "" {
		c.RefreshToken = refresh
	}
	if expiresIn > 0 {
		c.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
}

// IsOAuth checks if credential content is valid OAuth JSON.
// Returns true if the data contains both access_token and token_url fields.
func IsOAuth(data []byte) bool {
	var probe struct {
		AccessToken string `json:"access_token"`
		TokenURL    string `json:"token_url"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.AccessToken != "" && probe.TokenURL != ""
}
