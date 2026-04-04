package vault

import (
	"testing"
)

// Compile-time interface checks.
var (
	_ Provider = (*Store)(nil)
	_ Provider = (*EnvProvider)(nil)
	_ Provider = (*HashiCorpProvider)(nil)
	_ Provider = (*ChainProvider)(nil)
	_ Provider = (*OnePasswordProvider)(nil)
	_ Provider = (*BitwardenProvider)(nil)
	_ Provider = (*KeePassProvider)(nil)
	_ Provider = (*GopassProvider)(nil)
)

func TestStoreImplementsProvider(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if store.Name() != "age" {
		t.Errorf("expected name 'age', got %q", store.Name())
	}

	// Use through Provider interface.
	var p Provider = store
	if _, err := store.Add("test_key", "test_value"); err != nil {
		t.Fatal(err)
	}

	sb, err := p.Get("test_key")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()
	if sb.String() != "test_value" {
		t.Errorf("expected 'test_value', got %q", sb.String())
	}

	names, err := p.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "test_key" {
		t.Errorf("expected [test_key], got %v", names)
	}
}

func TestEnvProvider(t *testing.T) {
	t.Setenv("SLUICE_TEST_CRED", "env-secret-value")

	p := &EnvProvider{}
	if p.Name() != "env" {
		t.Errorf("expected name 'env', got %q", p.Name())
	}

	sb, err := p.Get("SLUICE_TEST_CRED")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()
	if sb.String() != "env-secret-value" {
		t.Errorf("expected 'env-secret-value', got %q", sb.String())
	}

	_, err = p.Get("SLUICE_NONEXISTENT_VAR")
	if err == nil {
		t.Error("expected error for unset env var")
	}

	names, err := p.List()
	if err != nil {
		t.Fatal(err)
	}
	if names != nil {
		t.Errorf("expected nil list, got %v", names)
	}
}

func TestHashiCorpProviderMissingConfig(t *testing.T) {
	// No addr, no token, no env vars: should fail with a clear error.
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_ADDR", "")
	_, err := NewHashiCorpProvider(HashiCorpConfig{})
	if err == nil {
		t.Error("expected error when no token is configured")
	}
}

func TestChainProvider(t *testing.T) {
	t.Setenv("CHAIN_TEST_KEY", "from-env")

	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("age_only_key", "from-age"); err != nil {
		t.Fatal(err)
	}

	chain := NewChainProvider(&EnvProvider{}, store)
	if chain.Name() != "chain" {
		t.Errorf("expected name 'chain', got %q", chain.Name())
	}

	// Env provider resolves this one.
	sb, err := chain.Get("CHAIN_TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()
	if sb.String() != "from-env" {
		t.Errorf("expected 'from-env', got %q", sb.String())
	}

	// Falls through to age provider.
	sb2, err := chain.Get("age_only_key")
	if err != nil {
		t.Fatal(err)
	}
	defer sb2.Release()
	if sb2.String() != "from-age" {
		t.Errorf("expected 'from-age', got %q", sb2.String())
	}

	// Neither provider has this.
	_, err = chain.Get("missing_key")
	if err == nil {
		t.Error("expected error for missing credential")
	}
}

func TestChainProviderList(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("key_a", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("key_b", "b"); err != nil {
		t.Fatal(err)
	}

	chain := NewChainProvider(&EnvProvider{}, store)
	names, err := chain.List()
	if err != nil {
		t.Fatal(err)
	}
	// EnvProvider returns nil, Store returns key_a and key_b.
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}

func TestNewProviderFromConfigDefault(t *testing.T) {
	dir := t.TempDir()
	p, err := NewProviderFromConfig(VaultConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "age" {
		t.Errorf("expected default provider 'age', got %q", p.Name())
	}
}

func TestNewProviderFromConfigEnv(t *testing.T) {
	p, err := NewProviderFromConfig(VaultConfig{Provider: "env"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "env" {
		t.Errorf("expected provider 'env', got %q", p.Name())
	}
}

func TestNewProviderFromConfigChain(t *testing.T) {
	dir := t.TempDir()
	p, err := NewProviderFromConfig(VaultConfig{
		Dir:       dir,
		Providers: []string{"env", "age"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "chain" {
		t.Errorf("expected chain provider, got %q", p.Name())
	}
}

func TestNewProviderFromConfigUnknown(t *testing.T) {
	_, err := NewProviderFromConfig(VaultConfig{Provider: "bogus"})
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestNewProviderFromConfigOnePasswordMissingToken(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")
	_, err := NewProviderFromConfig(VaultConfig{
		Provider: "1password",
		OnePassword: OnePasswordConfig{
			Vault: "my-vault",
		},
	})
	if err == nil {
		t.Error("expected error for 1password without token")
	}
}

func TestNewProviderFromConfigBitwardenMissingToken(t *testing.T) {
	t.Setenv("BWS_ACCESS_TOKEN", "")
	_, err := NewProviderFromConfig(VaultConfig{
		Provider: "bitwarden",
		Bitwarden: BitwardenConfig{
			OrgID: "org-123",
		},
	})
	if err == nil {
		t.Error("expected error for bitwarden without token")
	}
}

func TestNewProviderFromConfigKeePassMissingPath(t *testing.T) {
	_, err := NewProviderFromConfig(VaultConfig{
		Provider: "keepass",
		KeePass: KeePassConfig{
			Password: "test",
		},
	})
	if err == nil {
		t.Error("expected error for keepass without path")
	}
}

func TestNewProviderFromConfigKeePassProvider(t *testing.T) {
	// Create a real .kdbx file for the factory test.
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "factorypass", map[string]string{"factory_key": "factory_val"})
	p, err := NewProviderFromConfig(VaultConfig{
		Provider: "keepass",
		KeePass: KeePassConfig{
			Path:     dbPath,
			Password: "factorypass",
		},
	})
	if err != nil {
		t.Fatalf("NewProviderFromConfig(keepass): %v", err)
	}
	if p.Name() != "keepass" {
		t.Errorf("expected provider name 'keepass', got %q", p.Name())
	}
	sb, err := p.Get("factory_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "factory_val" {
		t.Errorf("expected 'factory_val', got %q", sb.String())
	}
}

func TestNewProviderFromConfigChainWithKeePass(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "chainpass", map[string]string{"kp_key": "kp_val"})
	t.Setenv("CHAIN_KP_ENV_KEY", "env_val")

	p, err := NewProviderFromConfig(VaultConfig{
		Providers: []string{"env", "keepass"},
		KeePass: KeePassConfig{
			Path:     dbPath,
			Password: "chainpass",
		},
	})
	if err != nil {
		t.Fatalf("NewProviderFromConfig(chain): %v", err)
	}
	if p.Name() != "chain" {
		t.Errorf("expected 'chain', got %q", p.Name())
	}

	// Env provider resolves this one.
	sb, err := p.Get("CHAIN_KP_ENV_KEY")
	if err != nil {
		t.Fatalf("Get env key: %v", err)
	}
	defer sb.Release()
	if sb.String() != "env_val" {
		t.Errorf("expected 'env_val', got %q", sb.String())
	}

	// Falls through to KeePass.
	sb2, err := p.Get("kp_key")
	if err != nil {
		t.Fatalf("Get keepass key: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "kp_val" {
		t.Errorf("expected 'kp_val', got %q", sb2.String())
	}
}

func TestNewProviderFromConfigChainErrorOnBadProvider(t *testing.T) {
	_, err := NewProviderFromConfig(VaultConfig{
		Providers: []string{"env", "bogus"},
	})
	if err == nil {
		t.Error("expected error for chain with unknown provider")
	}
}

func TestChainProviderWithMockOnePasswordAndAge(t *testing.T) {
	// Mock 1Password provider.
	mock := &mockOPClient{
		secrets: map[string]string{
			"op://test-vault/api_key/credential": "op-secret-123",
		},
	}
	opProvider := newOnePasswordProviderWithClient(mock, "test-vault", "credential")

	// Real age provider.
	dir := t.TempDir()
	ageStore, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ageStore.Add("local_key", "age-secret"); err != nil {
		t.Fatal(err)
	}

	chain := NewChainProvider(opProvider, ageStore)

	// 1Password resolves this.
	sb, err := chain.Get("api_key")
	if err != nil {
		t.Fatalf("Get api_key: %v", err)
	}
	defer sb.Release()
	if sb.String() != "op-secret-123" {
		t.Errorf("expected 'op-secret-123', got %q", sb.String())
	}

	// Falls through to age.
	sb2, err := chain.Get("local_key")
	if err != nil {
		t.Fatalf("Get local_key: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "age-secret" {
		t.Errorf("expected 'age-secret', got %q", sb2.String())
	}
}

func TestChainProviderWithMockBitwardenAndEnv(t *testing.T) {
	t.Setenv("FALLBACK_KEY", "from-env")

	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "bw_key"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "bw_key", Value: "bw-secret"},
		},
	}
	bwProvider := newBitwardenProviderWithClient(mock, "org-123")

	chain := NewChainProvider(bwProvider, &EnvProvider{})

	// Bitwarden resolves this.
	sb, err := chain.Get("bw_key")
	if err != nil {
		t.Fatalf("Get bw_key: %v", err)
	}
	defer sb.Release()
	if sb.String() != "bw-secret" {
		t.Errorf("expected 'bw-secret', got %q", sb.String())
	}

	// Falls through to env.
	sb2, err := chain.Get("FALLBACK_KEY")
	if err != nil {
		t.Fatalf("Get FALLBACK_KEY: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "from-env" {
		t.Errorf("expected 'from-env', got %q", sb2.String())
	}
}

func TestChainProviderWithMockGopassAndAge(t *testing.T) {
	mockGP := &mockGopassClient{
		entries: map[string]string{
			"services/api_key": "gopass-secret",
		},
	}
	gpProvider := newGopassProviderWithClient(mockGP)

	dir := t.TempDir()
	ageStore, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ageStore.Add("local_only", "from-age"); err != nil {
		t.Fatal(err)
	}

	chain := NewChainProvider(gpProvider, ageStore)

	// Gopass resolves this.
	sb, err := chain.Get("services/api_key")
	if err != nil {
		t.Fatalf("Get gopass key: %v", err)
	}
	defer sb.Release()
	if sb.String() != "gopass-secret" {
		t.Errorf("expected 'gopass-secret', got %q", sb.String())
	}

	// Falls through to age.
	sb2, err := chain.Get("local_only")
	if err != nil {
		t.Fatalf("Get age key: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "from-age" {
		t.Errorf("expected 'from-age', got %q", sb2.String())
	}
}
