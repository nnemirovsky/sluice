package vault

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// mockBWClient implements bwClient for testing.
type mockBWClient struct {
	secrets   []bwSecretOverview
	details   map[string]*bwSecretDetail
	listErr   error
	getErr    error
	listCalls int
	getCalls  int
}

func (m *mockBWClient) listSecrets(_ string) ([]bwSecretOverview, error) {
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.secrets, nil
}

func (m *mockBWClient) getSecret(id string) (*bwSecretDetail, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	detail, ok := m.details[id]
	if !ok {
		return nil, fmt.Errorf("secret %q not found", id)
	}
	return detail, nil
}

func TestBitwardenProviderGet(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "anthropic_api_key"},
			{ID: "id-2", Key: "openai_key"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "anthropic_api_key", Value: "sk-ant-real-123"},
			"id-2": {ID: "id-2", Key: "openai_key", Value: "sk-openai-456"},
		},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	if p.Name() != "bitwarden" {
		t.Errorf("Name() = %q, want \"bitwarden\"", p.Name())
	}

	sb, err := p.Get("anthropic_api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "sk-ant-real-123" {
		t.Errorf("Get value = %q, want \"sk-ant-real-123\"", sb.String())
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

func TestBitwardenProviderGetNotFound(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "existing_key"},
		},
		details: map[string]*bwSecretDetail{},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	_, err := p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain \"not found\"", err.Error())
	}
}

func TestBitwardenProviderGetAuthFailure(t *testing.T) {
	mock := &mockBWClient{
		listErr: fmt.Errorf("authentication failed: invalid access token"),
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	_, err := p.Get("any_key")
	if err == nil {
		t.Fatal("expected error when auth fails")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error = %q, want it to contain \"authentication failed\"", err.Error())
	}
}

func TestBitwardenProviderGetSecretFetchError(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "my_secret"},
		},
		getErr: fmt.Errorf("network error: connection refused"),
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	_, err := p.Get("my_secret")
	if err == nil {
		t.Fatal("expected error when get fails")
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Errorf("error = %q, want it to contain \"network error\"", err.Error())
	}
}

func TestBitwardenProviderList(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "anthropic_api_key"},
			{ID: "id-2", Key: "openai_key"},
			{ID: "id-3", Key: "github_token"},
		},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

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

func TestBitwardenProviderListEmpty(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("List returned %d names, want 0", len(names))
	}
}

func TestBitwardenProviderListError(t *testing.T) {
	mock := &mockBWClient{
		listErr: fmt.Errorf("permission denied"),
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	_, err := p.List()
	if err == nil {
		t.Fatal("expected error when list fails")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %q, want it to contain \"permission denied\"", err.Error())
	}
}

func TestBitwardenProviderCache(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "key1"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "key1", Value: "val1"},
		},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	// First Get triggers a list call.
	sb1, err := p.Get("key1")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	defer sb1.Release()
	if mock.listCalls != 1 {
		t.Errorf("after first Get: listCalls = %d, want 1", mock.listCalls)
	}

	// Second Get should use cache (no additional list call).
	sb2, err := p.Get("key1")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	defer sb2.Release()
	if mock.listCalls != 1 {
		t.Errorf("after second Get: listCalls = %d, want 1 (cached)", mock.listCalls)
	}

	// getSecret is called each time (we only cache the list, not values).
	if mock.getCalls != 2 {
		t.Errorf("getCalls = %d, want 2", mock.getCalls)
	}
}

func TestBitwardenProviderCacheExpiry(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "key1"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "key1", Value: "val1"},
		},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")
	p.setCacheTTL(10 * time.Millisecond)

	// First Get populates cache.
	sb, err := p.Get("key1")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	sb.Release()
	if mock.listCalls != 1 {
		t.Errorf("after first Get: listCalls = %d, want 1", mock.listCalls)
	}

	// Wait for cache to expire.
	time.Sleep(20 * time.Millisecond)

	// Next Get should trigger a fresh list.
	sb2, err := p.Get("key1")
	if err != nil {
		t.Fatalf("Get after expiry: %v", err)
	}
	sb2.Release()
	if mock.listCalls != 2 {
		t.Errorf("after cache expiry: listCalls = %d, want 2", mock.listCalls)
	}
}

func TestBitwardenProviderCacheInvalidate(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "key1"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "key1", Value: "val1"},
		},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	// Populate cache.
	_, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if mock.listCalls != 1 {
		t.Fatalf("listCalls = %d, want 1", mock.listCalls)
	}

	// Invalidate and list again.
	p.invalidateCache()

	_, err = p.List()
	if err != nil {
		t.Fatalf("List after invalidate: %v", err)
	}
	if mock.listCalls != 2 {
		t.Errorf("after invalidate: listCalls = %d, want 2", mock.listCalls)
	}
}

func TestBitwardenProviderPathTraversal(t *testing.T) {
	mock := &mockBWClient{}
	p := newBitwardenProviderWithClient(mock, "org-uuid")

	for _, name := range []string{"../../etc/passwd", "../secret", "foo/bar", "foo\\bar", "..", "."} {
		_, err := p.Get(name)
		if err == nil {
			t.Errorf("Get(%q) should have returned an error for path traversal", name)
		}
	}
}

func TestBitwardenProviderInterfaceCompliance(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "test"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "test", Value: "val"},
		},
	}
	p := newBitwardenProviderWithClient(mock, "org-uuid")

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

func TestBitwardenProviderSecureBytesRelease(t *testing.T) {
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "key"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "key", Value: "sensitive-value"},
		},
	}
	p := newBitwardenProviderWithClient(mock, "org-uuid")

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

func TestNewBitwardenProviderNoToken(t *testing.T) {
	t.Setenv("BWS_ACCESS_TOKEN", "")

	_, err := NewBitwardenProvider("", "org-uuid")
	if err == nil {
		t.Fatal("expected error when no token is provided")
	}
	if !strings.Contains(err.Error(), "no token") {
		t.Errorf("error = %q, want it to contain \"no token\"", err.Error())
	}
}

func TestNewBitwardenProviderNoOrgID(t *testing.T) {
	_, err := NewBitwardenProvider("some-token", "")
	if err == nil {
		t.Fatal("expected error when no org ID")
	}
	if !strings.Contains(err.Error(), "organization ID is required") {
		t.Errorf("error = %q, want it to contain \"organization ID is required\"", err.Error())
	}
}

func TestBitwardenProviderDuplicateNames(t *testing.T) {
	// When multiple secrets share the same name, Get returns the first match.
	mock := &mockBWClient{
		secrets: []bwSecretOverview{
			{ID: "id-1", Key: "dup_key"},
			{ID: "id-2", Key: "dup_key"},
		},
		details: map[string]*bwSecretDetail{
			"id-1": {ID: "id-1", Key: "dup_key", Value: "first-value"},
			"id-2": {ID: "id-2", Key: "dup_key", Value: "second-value"},
		},
	}

	p := newBitwardenProviderWithClient(mock, "org-uuid")

	sb, err := p.Get("dup_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "first-value" {
		t.Errorf("Get value = %q, want \"first-value\" (first match)", sb.String())
	}
}

func TestBitwardenProviderEmptyName(t *testing.T) {
	mock := &mockBWClient{}
	p := newBitwardenProviderWithClient(mock, "org-uuid")

	_, err := p.Get("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}
