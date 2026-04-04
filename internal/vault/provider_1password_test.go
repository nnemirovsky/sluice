package vault

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// mockOPClient implements opClient for testing without the real 1Password SDK.
type mockOPClient struct {
	// secrets maps secret reference URIs to their values.
	secrets map[string]string

	// vaults is the list of vaults returned by listVaults.
	vaults []opVaultOverview

	// items maps vault ID to item overviews returned by listItems.
	items map[string][]opItemOverview

	// resolveErr, if set, is returned by resolve regardless of input.
	resolveErr error

	// listItemsErr, if set, is returned by listItems.
	listItemsErr error

	// listVaultsErr, if set, is returned by listVaults.
	listVaultsErr error
}

func (m *mockOPClient) resolve(_ context.Context, ref string) (string, error) {
	if m.resolveErr != nil {
		return "", m.resolveErr
	}
	val, ok := m.secrets[ref]
	if !ok {
		return "", fmt.Errorf("secret reference %q not found", ref)
	}
	return val, nil
}

func (m *mockOPClient) listItems(_ context.Context, vaultID string) ([]opItemOverview, error) {
	if m.listItemsErr != nil {
		return nil, m.listItemsErr
	}
	return m.items[vaultID], nil
}

func (m *mockOPClient) listVaults(_ context.Context) ([]opVaultOverview, error) {
	if m.listVaultsErr != nil {
		return nil, m.listVaultsErr
	}
	return m.vaults, nil
}

func TestOnePasswordProviderGet(t *testing.T) {
	mock := &mockOPClient{
		secrets: map[string]string{
			"op://my-vault/anthropic_api_key/credential": "sk-ant-real-key-123",
			"op://my-vault/openai_key/credential":        "sk-openai-456",
		},
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	if p.Name() != "1password" {
		t.Errorf("Name() = %q, want \"1password\"", p.Name())
	}

	sb, err := p.Get("anthropic_api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "sk-ant-real-key-123" {
		t.Errorf("Get value = %q, want \"sk-ant-real-key-123\"", sb.String())
	}

	sb2, err := p.Get("openai_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "sk-openai-456" {
		t.Errorf("Get value = %q, want \"sk-openai-456\"", sb2.String())
	}
}

func TestOnePasswordProviderGetCustomField(t *testing.T) {
	mock := &mockOPClient{
		secrets: map[string]string{
			"op://my-vault/db_password/password": "s3cret",
		},
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "password")

	sb, err := p.Get("db_password")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "s3cret" {
		t.Errorf("Get value = %q, want \"s3cret\"", sb.String())
	}
}

func TestOnePasswordProviderGetDefaultField(t *testing.T) {
	mock := &mockOPClient{
		secrets: map[string]string{
			"op://vault1/key1/credential": "val1",
		},
	}

	// Empty field should default to "credential".
	p := newOnePasswordProviderWithClient(mock, "vault1", "")

	sb, err := p.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "val1" {
		t.Errorf("Get value = %q, want \"val1\"", sb.String())
	}
}

func TestOnePasswordProviderGetNotFound(t *testing.T) {
	mock := &mockOPClient{
		secrets: map[string]string{},
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	_, err := p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent item")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain \"not found\"", err.Error())
	}
}

func TestOnePasswordProviderGetResolveError(t *testing.T) {
	mock := &mockOPClient{
		resolveErr: fmt.Errorf("authentication failed"),
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	_, err := p.Get("any_key")
	if err == nil {
		t.Fatal("expected error when resolve fails")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error = %q, want it to contain \"authentication failed\"", err.Error())
	}
}

func TestOnePasswordProviderList(t *testing.T) {
	mock := &mockOPClient{
		vaults: []opVaultOverview{
			{ID: "vault-id-1", Title: "my-vault"},
			{ID: "vault-id-2", Title: "other-vault"},
		},
		items: map[string][]opItemOverview{
			"vault-id-1": {
				{ID: "item-1", Title: "anthropic_api_key"},
				{ID: "item-2", Title: "openai_key"},
				{ID: "item-3", Title: "github_token"},
			},
		},
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("List returned %d names, want 3", len(names))
	}
	expected := []string{"anthropic_api_key", "openai_key", "github_token"}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("names[%d] = %q, want %q", i, names[i], want)
		}
	}
}

func TestOnePasswordProviderListEmpty(t *testing.T) {
	mock := &mockOPClient{
		vaults: []opVaultOverview{
			{ID: "vault-id-1", Title: "empty-vault"},
		},
		items: map[string][]opItemOverview{},
	}

	p := newOnePasswordProviderWithClient(mock, "empty-vault", "credential")

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("List returned %d names, want 0", len(names))
	}
}

func TestOnePasswordProviderListVaultNotFound(t *testing.T) {
	mock := &mockOPClient{
		vaults: []opVaultOverview{
			{ID: "vault-id-1", Title: "other-vault"},
		},
	}

	p := newOnePasswordProviderWithClient(mock, "nonexistent-vault", "credential")

	_, err := p.List()
	if err == nil {
		t.Fatal("expected error when vault not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain \"not found\"", err.Error())
	}
}

func TestOnePasswordProviderListVaultsError(t *testing.T) {
	mock := &mockOPClient{
		listVaultsErr: fmt.Errorf("network error"),
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	_, err := p.List()
	if err == nil {
		t.Fatal("expected error when listVaults fails")
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Errorf("error = %q, want it to contain \"network error\"", err.Error())
	}
}

func TestOnePasswordProviderListItemsError(t *testing.T) {
	mock := &mockOPClient{
		vaults: []opVaultOverview{
			{ID: "vault-id-1", Title: "my-vault"},
		},
		listItemsErr: fmt.Errorf("permission denied"),
	}

	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	_, err := p.List()
	if err == nil {
		t.Fatal("expected error when listItems fails")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %q, want it to contain \"permission denied\"", err.Error())
	}
}

func TestOnePasswordProviderPathTraversal(t *testing.T) {
	mock := &mockOPClient{}
	p := newOnePasswordProviderWithClient(mock, "my-vault", "credential")

	for _, name := range []string{"../../etc/passwd", "../secret", "foo/bar", "foo\\bar", "..", "."} {
		_, err := p.Get(name)
		if err == nil {
			t.Errorf("Get(%q) should have returned an error for path traversal", name)
		}
	}
}

func TestOnePasswordProviderInterfaceCompliance(t *testing.T) {
	mock := &mockOPClient{
		secrets: map[string]string{
			"op://v/test/credential": "val",
		},
	}
	p := newOnePasswordProviderWithClient(mock, "v", "credential")

	var provider Provider = p
	sb, err := provider.Get("test")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()
	if sb.String() != "val" {
		t.Errorf("via Provider interface: got %q, want \"val\"", sb.String())
	}
}

func TestNewOnePasswordProviderNoToken(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")

	_, err := NewOnePasswordProvider("", "my-vault", "credential")
	if err == nil {
		t.Fatal("expected error when no token is provided")
	}
	if !strings.Contains(err.Error(), "no token") {
		t.Errorf("error = %q, want it to contain \"no token\"", err.Error())
	}
}

func TestNewOnePasswordProviderNoVault(t *testing.T) {
	_, err := NewOnePasswordProvider("some-token", "", "credential")
	if err == nil {
		t.Fatal("expected error when no vault name")
	}
	if !strings.Contains(err.Error(), "vault name is required") {
		t.Errorf("error = %q, want it to contain \"vault name is required\"", err.Error())
	}
}

func TestOnePasswordProviderSecureBytesRelease(t *testing.T) {
	mock := &mockOPClient{
		secrets: map[string]string{
			"op://v/key/credential": "sensitive-value",
		},
	}
	p := newOnePasswordProviderWithClient(mock, "v", "credential")

	sb, err := p.Get("key")
	if err != nil {
		t.Fatal(err)
	}
	if sb.String() != "sensitive-value" {
		t.Errorf("before release: got %q", sb.String())
	}

	sb.Release()
	if !sb.IsReleased() {
		t.Error("expected IsReleased() to be true after Release()")
	}
}
