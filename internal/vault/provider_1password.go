package vault

import (
	"context"
	"fmt"
	"os"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// OnePasswordConfig holds configuration for the 1Password provider.
type OnePasswordConfig struct {
	// Token is the Service Account token. Falls back to
	// OP_SERVICE_ACCOUNT_TOKEN env var if empty.
	Token string

	// Vault is the 1Password vault name to read from.
	Vault string

	// Field is the item field name to read (default "credential").
	Field string
}

// opClient abstracts the 1Password SDK operations needed by the provider.
// This enables mock-based testing without the real WASM runtime.
type opClient interface {
	resolve(ctx context.Context, ref string) (string, error)
	listItems(ctx context.Context, vaultID string) ([]opItemOverview, error)
	listVaults(ctx context.Context) ([]opVaultOverview, error)
}

type opItemOverview struct {
	ID    string
	Title string
}

type opVaultOverview struct {
	ID    string
	Title string
}

// realOPClient wraps the real 1Password SDK client.
type realOPClient struct {
	client *onepassword.Client
}

func (r *realOPClient) resolve(ctx context.Context, ref string) (string, error) {
	return r.client.Secrets().Resolve(ctx, ref)
}

func (r *realOPClient) listItems(ctx context.Context, vaultID string) ([]opItemOverview, error) {
	items, err := r.client.Items().List(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	result := make([]opItemOverview, len(items))
	for i, item := range items {
		result[i] = opItemOverview{ID: item.ID, Title: item.Title}
	}
	return result, nil
}

func (r *realOPClient) listVaults(ctx context.Context) ([]opVaultOverview, error) {
	vaults, err := r.client.Vaults().List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]opVaultOverview, len(vaults))
	for i, v := range vaults {
		result[i] = opVaultOverview{ID: v.ID, Title: v.Title}
	}
	return result, nil
}

// OnePasswordProvider retrieves credentials from 1Password via Service Account token.
type OnePasswordProvider struct {
	client    opClient
	vaultName string
	field     string
}

// NewOnePasswordProvider creates a provider that reads secrets from 1Password.
// The token authenticates via Service Account. vaultName selects the vault.
// field is the item field to read (defaults to "credential").
func NewOnePasswordProvider(token, vaultName, field string) (*OnePasswordProvider, error) {
	if token == "" {
		token = os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("1password: no token provided (set OP_SERVICE_ACCOUNT_TOKEN or config token)")
	}
	if vaultName == "" {
		return nil, fmt.Errorf("1password: vault name is required")
	}
	if field == "" {
		field = "credential"
	}

	client, err := onepassword.NewClient(context.Background(),
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("Sluice", "v1.0.0"),
	)
	if err != nil {
		return nil, fmt.Errorf("1password: create client: %w", err)
	}

	return &OnePasswordProvider{
		client:    &realOPClient{client: client},
		vaultName: vaultName,
		field:     field,
	}, nil
}

// newOnePasswordProviderWithClient creates a provider with an injected client (for testing).
func newOnePasswordProviderWithClient(client opClient, vaultName, field string) *OnePasswordProvider {
	if field == "" {
		field = "credential"
	}
	return &OnePasswordProvider{
		client:    client,
		vaultName: vaultName,
		field:     field,
	}
}

// Get retrieves a credential from 1Password by resolving op://<vault>/<name>/<field>.
func (p *OnePasswordProvider) Get(name string) (SecureBytes, error) {
	if err := validateCredentialName(name); err != nil {
		return SecureBytes{}, err
	}

	ref := fmt.Sprintf("op://%s/%s/%s", p.vaultName, name, p.field)
	secret, err := p.client.resolve(context.Background(), ref)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("1password: resolve %q: %w", name, err)
	}

	return NewSecureBytes(secret), nil
}

// List returns all item titles in the configured vault.
func (p *OnePasswordProvider) List() ([]string, error) {
	vaultID, err := p.resolveVaultID()
	if err != nil {
		return nil, err
	}

	items, err := p.client.listItems(context.Background(), vaultID)
	if err != nil {
		return nil, fmt.Errorf("1password: list items: %w", err)
	}

	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.Title
	}
	return names, nil
}

// Name returns "1password".
func (p *OnePasswordProvider) Name() string { return "1password" }

// resolveVaultID finds the vault ID by matching the configured vault name.
func (p *OnePasswordProvider) resolveVaultID() (string, error) {
	vaults, err := p.client.listVaults(context.Background())
	if err != nil {
		return "", fmt.Errorf("1password: list vaults: %w", err)
	}

	for _, v := range vaults {
		if v.Title == p.vaultName {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("1password: vault %q not found", p.vaultName)
}
