package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMockVaultServer creates an httptest.Server that simulates HashiCorp Vault
// KV v2 endpoints. secrets maps path -> key -> value for GET requests.
// listKeys maps path -> list of key names for LIST requests.
// If approleToken is non-empty, POST to auth/approle/login returns that token.
func newMockVaultServer(t *testing.T, secrets map[string]map[string]string, listKeys map[string][]string, approleToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// AppRole login. The Vault SDK sends PUT for write operations.
		if (r.Method == http.MethodPut || r.Method == http.MethodPost) && strings.HasSuffix(r.URL.Path, "/v1/auth/approle/login") {
			if approleToken == "" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"permission denied"},
				})
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] == "" || body["secret_id"] == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"missing role_id or secret_id"},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": approleToken,
					"policies":     []string{"default"},
				},
			})
			return
		}

		// Check for token in header.
		token := r.Header.Get("X-Vault-Token")
		if token == "" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"missing client token"},
			})
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/v1/")

		// LIST request (Vault SDK sends GET with list=true query param).
		if r.Method == http.MethodGet && r.URL.Query().Get("list") == "true" || r.Method == "LIST" {
			// Try with and without trailing slash since net/http cleans URLs.
			keys, ok := listKeys[path]
			if !ok {
				keys, ok = listKeys[path+"/"]
			}
			if ok {
				ikeys := make([]interface{}, len(keys))
				for i, k := range keys {
					ikeys[i] = k
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"keys": ikeys,
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{},
			})
			return
		}

		// GET request for secret data.
		if r.Method == http.MethodGet {
			if data, ok := secrets[path]; ok {
				// Convert to interface map for JSON encoding.
				idata := make(map[string]interface{}, len(data))
				for k, v := range data {
					idata[k] = v
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"data": idata,
						"metadata": map[string]interface{}{
							"version": 1,
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{},
			})
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
}

func TestHashiCorpProviderTokenAuth(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/my_api_key": {"value": "sk-secret-12345"},
	}
	listKeys := map[string][]string{
		"secret/metadata/": {"my_api_key", "other_key"},
	}

	srv := newMockVaultServer(t, secrets, listKeys, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}
	if p.Name() != "hashicorp" {
		t.Errorf("Name() = %q, want \"hashicorp\"", p.Name())
	}

	// Get existing secret.
	sb, err := p.Get("my_api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "sk-secret-12345" {
		t.Errorf("Get value = %q, want \"sk-secret-12345\"", sb.String())
	}

	// List secrets.
	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List returned %d names, want 2", len(names))
	}
}

func TestHashiCorpProviderAppRoleAuth(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/db_password": {"value": "p@ssw0rd"},
	}

	srv := newMockVaultServer(t, secrets, nil, "approle-client-token")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:     srv.URL,
		Auth:     "approle",
		RoleID:   "test-role-id",
		SecretID: "test-secret-id",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider with AppRole: %v", err)
	}

	sb, err := p.Get("db_password")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "p@ssw0rd" {
		t.Errorf("Get value = %q, want \"p@ssw0rd\"", sb.String())
	}
}

func TestHashiCorpProviderAppRoleFromEnv(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/cred": {"value": "env-cred"},
	}

	srv := newMockVaultServer(t, secrets, nil, "approle-token-env")
	defer srv.Close()

	t.Setenv("TEST_ROLE_ID", "role-from-env")
	t.Setenv("TEST_SECRET_ID", "secret-from-env")

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:        srv.URL,
		Auth:        "approle",
		RoleIDEnv:   "TEST_ROLE_ID",
		SecretIDEnv: "TEST_SECRET_ID",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider with AppRole env: %v", err)
	}

	sb, err := p.Get("cred")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "env-cred" {
		t.Errorf("Get value = %q, want \"env-cred\"", sb.String())
	}
}

func TestHashiCorpProviderCustomMount(t *testing.T) {
	secrets := map[string]map[string]string{
		"sluice/data/api_key": {"value": "custom-mount-value"},
	}

	srv := newMockVaultServer(t, secrets, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
		Mount: "sluice",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	sb, err := p.Get("api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "custom-mount-value" {
		t.Errorf("Get value = %q, want \"custom-mount-value\"", sb.String())
	}
}

func TestHashiCorpProviderPrefix(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/sluice/my_key": {"value": "prefixed-value"},
	}
	listKeys := map[string][]string{
		"secret/metadata/sluice/": {"my_key"},
	}

	srv := newMockVaultServer(t, secrets, listKeys, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:   srv.URL,
		Token:  "test-token",
		Prefix: "sluice/",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	sb, err := p.Get("my_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "prefixed-value" {
		t.Errorf("Get value = %q, want \"prefixed-value\"", sb.String())
	}

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "my_key" {
		t.Errorf("List = %v, want [\"my_key\"]", names)
	}
}

func TestHashiCorpProviderSecretNotFound(t *testing.T) {
	srv := newMockVaultServer(t, nil, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	_, err = p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain \"not found\"", err.Error())
	}
}

func TestHashiCorpProviderNoValueKey(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/bad_secret": {"username": "admin"},
	}

	srv := newMockVaultServer(t, secrets, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	_, err = p.Get("bad_secret")
	if err == nil {
		t.Fatal("expected error for secret without \"value\" key")
	}
	if !strings.Contains(err.Error(), "no \"value\" key") {
		t.Errorf("error = %q, want it to contain 'no \"value\" key'", err.Error())
	}
}

func TestHashiCorpProviderListEmpty(t *testing.T) {
	srv := newMockVaultServer(t, nil, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if names != nil {
		t.Errorf("List = %v, want nil for empty vault", names)
	}
}

func TestHashiCorpProviderListSkipsDirectories(t *testing.T) {
	listKeys := map[string][]string{
		"secret/metadata/": {"key1", "subdir/", "key2"},
	}

	srv := newMockVaultServer(t, nil, listKeys, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("List returned %d names, want 2", len(names))
	}
	if names[0] != "key1" || names[1] != "key2" {
		t.Errorf("List = %v, want [\"key1\", \"key2\"]", names)
	}
}

func TestHashiCorpProviderNoToken(t *testing.T) {
	// Unset VAULT_TOKEN to ensure the provider can't find one.
	t.Setenv("VAULT_TOKEN", "")

	_, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr: "http://localhost:8200",
	})
	if err == nil {
		t.Fatal("expected error when no token is provided")
	}
	if !strings.Contains(err.Error(), "no token") {
		t.Errorf("error = %q, want it to contain \"no token\"", err.Error())
	}
}

func TestHashiCorpProviderNoRoleID(t *testing.T) {
	_, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr: "http://localhost:8200",
		Auth: "approle",
	})
	if err == nil {
		t.Fatal("expected error when no role_id")
	}
	if !strings.Contains(err.Error(), "no role_id") {
		t.Errorf("error = %q, want it to contain \"no role_id\"", err.Error())
	}
}

func TestHashiCorpProviderNoSecretID(t *testing.T) {
	_, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:   "http://localhost:8200",
		Auth:   "approle",
		RoleID: "some-role",
	})
	if err == nil {
		t.Fatal("expected error when no secret_id")
	}
	if !strings.Contains(err.Error(), "no secret_id") {
		t.Errorf("error = %q, want it to contain \"no secret_id\"", err.Error())
	}
}

func TestHashiCorpProviderUnknownAuth(t *testing.T) {
	_, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr: "http://localhost:8200",
		Auth: "kerberos",
	})
	if err == nil {
		t.Fatal("expected error for unknown auth method")
	}
	if !strings.Contains(err.Error(), "unknown auth method") {
		t.Errorf("error = %q, want it to contain \"unknown auth method\"", err.Error())
	}
}

func TestHashiCorpProviderConnectionRefused(t *testing.T) {
	// Use a port that nothing is listening on.
	_, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:     "http://127.0.0.1:1",
		Auth:     "approle",
		RoleID:   "role",
		SecretID: "secret",
	})
	if err == nil {
		t.Fatal("expected error when Vault is unreachable")
	}
}

func TestHashiCorpProviderAppRoleDenied(t *testing.T) {
	// Server returns 403 for approle login (approleToken is empty).
	srv := newMockVaultServer(t, nil, nil, "")
	defer srv.Close()

	_, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:     srv.URL,
		Auth:     "approle",
		RoleID:   "bad-role",
		SecretID: "bad-secret",
	})
	if err == nil {
		t.Fatal("expected error for denied approle auth")
	}
}

func TestHashiCorpProviderTokenFromEnv(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/env_key": {"value": "from-env-token"},
	}

	srv := newMockVaultServer(t, secrets, nil, "")
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "env-vault-token")

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	sb, err := p.Get("env_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "from-env-token" {
		t.Errorf("Get value = %q, want \"from-env-token\"", sb.String())
	}
}

func TestHashiCorpProviderInterfaceCompliance(t *testing.T) {
	// Verify compile-time interface check still passes (already in provider_test.go
	// but verify the real implementation satisfies Provider).
	secrets := map[string]map[string]string{
		"secret/data/test": {"value": "val"},
	}
	srv := newMockVaultServer(t, secrets, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "t",
	})
	if err != nil {
		t.Fatal(err)
	}

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

func TestHashiCorpProviderMalformedResponse(t *testing.T) {
	// Server returns data where "data" nested key is not a map.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data":     "not-a-map",
				"metadata": map[string]interface{}{"version": 1},
			},
		})
	}))
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	_, err = p.Get("malformed")
	if err == nil {
		t.Fatal("expected error for malformed data field")
	}
	if !strings.Contains(err.Error(), "not a map") {
		t.Errorf("error = %q, want it to contain 'not a map'", err.Error())
	}
}

func TestHashiCorpProviderValueNotString(t *testing.T) {
	// Server returns a "value" key that is not a string.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data":     map[string]interface{}{"value": 12345},
				"metadata": map[string]interface{}{"version": 1},
			},
		})
	}))
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	_, err = p.Get("numeric_value")
	if err == nil {
		t.Fatal("expected error for non-string value")
	}
	if !strings.Contains(err.Error(), "not a string") {
		t.Errorf("error = %q, want it to contain 'not a string'", err.Error())
	}
}

func TestHashiCorpProviderNoDataField(t *testing.T) {
	// Server returns data without the nested "data" key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"metadata": map[string]interface{}{"version": 1},
			},
		})
	}))
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	_, err = p.Get("no_data_key")
	if err == nil {
		t.Fatal("expected error for missing data field")
	}
	if !strings.Contains(err.Error(), "no data field") {
		t.Errorf("error = %q, want it to contain 'no data field'", err.Error())
	}
}

func TestHashiCorpProviderListKeysNotList(t *testing.T) {
	// Server returns "keys" that is not a list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": "not-a-list",
			},
		})
	}))
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	_, err = p.List()
	if err == nil {
		t.Fatal("expected error for non-list keys")
	}
	if !strings.Contains(err.Error(), "not a list") {
		t.Errorf("error = %q, want it to contain 'not a list'", err.Error())
	}
}

func TestHashiCorpProviderConnectionTimeout(t *testing.T) {
	// Server that never responds (sleeps longer than HTTP client timeout).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The provider sets a 30s client timeout, so we can't wait that long
		// in a test. Instead, test against a closed server.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	// Close immediately so connections are refused.
	srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewHashiCorpProvider: %v", err)
	}

	// Get should fail with a connection error.
	_, err = p.Get("some_key")
	if err == nil {
		t.Fatal("expected error when server is down")
	}
}

func TestHashiCorpProviderEmptyCredentialName(t *testing.T) {
	secrets := map[string]map[string]string{
		"secret/data/test": {"value": "val"},
	}
	srv := newMockVaultServer(t, secrets, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "test-token",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Get("")
	if err == nil {
		t.Fatal("expected error for empty credential name")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %q, want it to contain 'must not be empty'", err.Error())
	}
}

func TestHashiCorpProviderPathTraversal(t *testing.T) {
	secrets := map[string]map[string]string{
		"test": {"value": "val"},
	}
	srv := newMockVaultServer(t, secrets, nil, "")
	defer srv.Close()

	p, err := NewHashiCorpProvider(HashiCorpConfig{
		Addr:  srv.URL,
		Token: "t",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"../../etc/passwd", "../secret", "foo/bar", "foo\\bar", "..", "."} {
		_, err := p.Get(name)
		if err == nil {
			t.Errorf("Get(%q) should have returned an error for path traversal", name)
		}
	}
}
