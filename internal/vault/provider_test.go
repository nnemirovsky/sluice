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
	if err := store.Add("test_key", "test_value"); err != nil {
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
	if err := store.Add("age_only_key", "from-age"); err != nil {
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
	if err := store.Add("key_a", "a"); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("key_b", "b"); err != nil {
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
