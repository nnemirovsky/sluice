package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// BitwardenConfig holds configuration for the Bitwarden Secrets Manager provider.
type BitwardenConfig struct {
	// Token is the BWS access token. Falls back to BWS_ACCESS_TOKEN env var if empty.
	Token string

	// OrgID is the Bitwarden organization UUID.
	OrgID string
}

// bwClient abstracts Bitwarden Secrets Manager operations needed by the provider.
// This enables mock-based testing without the real bws CLI or native SDK.
type bwClient interface {
	listSecrets(orgID string) ([]bwSecretOverview, error)
	getSecret(id string) (*bwSecretDetail, error)
}

type bwSecretOverview struct {
	ID  string
	Key string // secret name
}

type bwSecretDetail struct {
	ID    string
	Key   string
	Value string
}

// bwsCLIClient wraps the bws CLI for real Bitwarden Secrets Manager access.
type bwsCLIClient struct {
	token string
}

// bwsCLIListItem matches the JSON output of `bws secret list`.
type bwsCLIListItem struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	OrganizationID string `json:"organizationId"`
}

// bwsCLISecretItem matches the JSON output of `bws secret get`.
type bwsCLISecretItem struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (c *bwsCLIClient) listSecrets(orgID string) ([]bwSecretOverview, error) {
	cmd := exec.Command("bws", "secret", "list", orgID, "--output", "json")
	cmd.Env = append(os.Environ(), "BWS_ACCESS_TOKEN="+c.token)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bws secret list: %w", err)
	}

	var items []bwsCLIListItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("bws secret list: parse output: %w", err)
	}

	result := make([]bwSecretOverview, len(items))
	for i, item := range items {
		result[i] = bwSecretOverview{ID: item.ID, Key: item.Key}
	}
	return result, nil
}

func (c *bwsCLIClient) getSecret(id string) (*bwSecretDetail, error) {
	cmd := exec.Command("bws", "secret", "get", id, "--output", "json")
	cmd.Env = append(os.Environ(), "BWS_ACCESS_TOKEN="+c.token)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bws secret get: %w", err)
	}

	var item bwsCLISecretItem
	if err := json.Unmarshal(out, &item); err != nil {
		return nil, fmt.Errorf("bws secret get: parse output: %w", err)
	}

	return &bwSecretDetail{ID: item.ID, Key: item.Key, Value: item.Value}, nil
}

// BitwardenProvider retrieves credentials from Bitwarden Secrets Manager.
type BitwardenProvider struct {
	client bwClient
	orgID  string

	mu        sync.Mutex
	cache     []bwSecretOverview
	cacheTime time.Time
	cacheTTL  time.Duration
}

// NewBitwardenProvider creates a provider that reads secrets from Bitwarden Secrets Manager.
// Uses the bws CLI under the hood (pure Go, no CGO dependency).
func NewBitwardenProvider(token, orgID string) (*BitwardenProvider, error) {
	if token == "" {
		token = os.Getenv("BWS_ACCESS_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("bitwarden: no token provided (set BWS_ACCESS_TOKEN or config token)")
	}
	if orgID == "" {
		return nil, fmt.Errorf("bitwarden: organization ID is required")
	}

	if _, err := exec.LookPath("bws"); err != nil {
		return nil, fmt.Errorf("bitwarden: bws CLI not found in PATH (install from https://bitwarden.com/help/secrets-manager-cli/)")
	}

	return &BitwardenProvider{
		client:   &bwsCLIClient{token: token},
		orgID:    orgID,
		cacheTTL: 30 * time.Second,
	}, nil
}

// newBitwardenProviderWithClient creates a provider with an injected client (for testing).
func newBitwardenProviderWithClient(client bwClient, orgID string) *BitwardenProvider {
	return &BitwardenProvider{
		client:   client,
		orgID:    orgID,
		cacheTTL: 30 * time.Second,
	}
}

// Get retrieves a credential from Bitwarden by secret name (key).
// Lists secrets to find the ID, then fetches the secret value.
func (p *BitwardenProvider) Get(name string) (SecureBytes, error) {
	if err := validateCredentialName(name); err != nil {
		return SecureBytes{}, err
	}

	id, err := p.resolveSecretID(name)
	if err != nil {
		return SecureBytes{}, err
	}

	detail, err := p.client.getSecret(id)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("bitwarden: get %q: %w", name, err)
	}

	return NewSecureBytes(detail.Value), nil
}

// List returns all secret names in the configured organization.
func (p *BitwardenProvider) List() ([]string, error) {
	secrets, err := p.cachedList()
	if err != nil {
		return nil, fmt.Errorf("bitwarden: list: %w", err)
	}

	names := make([]string, len(secrets))
	for i, s := range secrets {
		names[i] = s.Key
	}
	return names, nil
}

// Name returns "bitwarden".
func (p *BitwardenProvider) Name() string { return "bitwarden" }

// resolveSecretID finds the secret ID by matching the name (key) in the list.
func (p *BitwardenProvider) resolveSecretID(name string) (string, error) {
	secrets, err := p.cachedList()
	if err != nil {
		return "", fmt.Errorf("bitwarden: resolve %q: %w", name, err)
	}

	for _, s := range secrets {
		if s.Key == name {
			return s.ID, nil
		}
	}
	return "", fmt.Errorf("bitwarden: secret %q not found", name)
}

// cachedList returns the secret list from cache if fresh, otherwise fetches from Bitwarden.
func (p *BitwardenProvider) cachedList() ([]bwSecretOverview, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cache != nil && time.Since(p.cacheTime) < p.cacheTTL {
		return p.cache, nil
	}

	secrets, err := p.client.listSecrets(p.orgID)
	if err != nil {
		return nil, err
	}

	p.cache = secrets
	p.cacheTime = time.Now()
	return secrets, nil
}

// invalidateCache forces the next cachedList call to fetch fresh data.
// Exported for testing only via the unexported provider constructor.
func (p *BitwardenProvider) invalidateCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = nil
	p.cacheTime = time.Time{}
}

// setCacheTTL overrides the cache duration (for testing).
func (p *BitwardenProvider) setCacheTTL(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cacheTTL = d
}
