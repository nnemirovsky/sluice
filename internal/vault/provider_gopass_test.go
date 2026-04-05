package vault

import (
	"fmt"
	"strings"
	"testing"
)

// mockGopassClient implements gopassClient for testing.
type mockGopassClient struct {
	entries   map[string]string // name -> secret value
	listNames []string
	showErr   error
	listErr   error
	showCalls int
	listCalls int
}

func (m *mockGopassClient) show(name string) (string, error) {
	m.showCalls++
	if m.showErr != nil {
		return "", m.showErr
	}
	val, ok := m.entries[name]
	if !ok {
		return "", fmt.Errorf("gopass show %q: entry not found", name)
	}
	return val, nil
}

func (m *mockGopassClient) list() ([]string, error) {
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listNames != nil {
		return m.listNames, nil
	}
	// Derive names from entries if listNames not explicitly set.
	names := make([]string, 0, len(m.entries))
	for k := range m.entries {
		names = append(names, k)
	}
	return names, nil
}

func TestGopassProviderGet(t *testing.T) {
	mock := &mockGopassClient{
		entries: map[string]string{
			"anthropic_api_key": "sk-ant-real-123",
			"openai_key":        "sk-openai-456",
		},
	}

	p := newGopassProviderWithClient(mock)

	if p.Name() != "gopass" {
		t.Errorf("Name() = %q, want \"gopass\"", p.Name())
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

func TestGopassProviderGetNotFound(t *testing.T) {
	mock := &mockGopassClient{
		entries: map[string]string{
			"existing_key": "val",
		},
	}

	p := newGopassProviderWithClient(mock)

	_, err := p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain \"not found\"", err.Error())
	}
}

func TestGopassProviderGetCLIError(t *testing.T) {
	mock := &mockGopassClient{
		showErr: fmt.Errorf("Error: failed to decrypt"),
	}

	p := newGopassProviderWithClient(mock)

	_, err := p.Get("any_key")
	if err == nil {
		t.Fatal("expected error when CLI fails")
	}
	if !strings.Contains(err.Error(), "failed to decrypt") {
		t.Errorf("error = %q, want it to contain \"failed to decrypt\"", err.Error())
	}
}

func TestGopassProviderGetEmptyName(t *testing.T) {
	mock := &mockGopassClient{}
	p := newGopassProviderWithClient(mock)

	_, err := p.Get("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %q, want it to contain \"must not be empty\"", err.Error())
	}
	if mock.showCalls != 0 {
		t.Errorf("showCalls = %d, want 0 (should not call CLI for empty name)", mock.showCalls)
	}
}

func TestGopassProviderList(t *testing.T) {
	mock := &mockGopassClient{
		listNames: []string{"anthropic_api_key", "openai_key", "email/work"},
	}

	p := newGopassProviderWithClient(mock)

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("List returned %d names, want 3", len(names))
	}
	expected := []string{"anthropic_api_key", "openai_key", "email/work"}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("names[%d] = %q, want %q", i, names[i], want)
		}
	}
}

func TestGopassProviderListEmpty(t *testing.T) {
	mock := &mockGopassClient{
		listNames: nil,
	}

	p := newGopassProviderWithClient(mock)

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("List returned %d names, want 0", len(names))
	}
}

func TestGopassProviderListError(t *testing.T) {
	mock := &mockGopassClient{
		listErr: fmt.Errorf("permission denied"),
	}

	p := newGopassProviderWithClient(mock)

	_, err := p.List()
	if err == nil {
		t.Fatal("expected error when list fails")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %q, want it to contain \"permission denied\"", err.Error())
	}
}

func TestGopassProviderInterfaceCompliance(t *testing.T) {
	mock := &mockGopassClient{
		entries: map[string]string{
			"test": "val",
		},
	}
	p := newGopassProviderWithClient(mock)

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

func TestGopassProviderSecureBytesRelease(t *testing.T) {
	mock := &mockGopassClient{
		entries: map[string]string{
			"key": "sensitive-value",
		},
	}
	p := newGopassProviderWithClient(mock)

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

func TestGopassProviderHierarchicalNames(t *testing.T) {
	// Gopass natively supports hierarchical names (folder/entry).
	mock := &mockGopassClient{
		entries: map[string]string{
			"email/work":    "work-password",
			"cloud/aws/key": "AKIAIOSFODNN7EXAMPLE",
		},
	}

	p := newGopassProviderWithClient(mock)

	sb, err := p.Get("email/work")
	if err != nil {
		t.Fatalf("Get hierarchical: %v", err)
	}
	defer sb.Release()
	if sb.String() != "work-password" {
		t.Errorf("Get value = %q, want \"work-password\"", sb.String())
	}

	sb2, err := p.Get("cloud/aws/key")
	if err != nil {
		t.Fatalf("Get deep hierarchical: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Get value = %q, want \"AKIAIOSFODNN7EXAMPLE\"", sb2.String())
	}
}

func TestNewGopassProviderBinaryNotFound(t *testing.T) {
	// Save and clear PATH to simulate gopass not being installed.
	t.Setenv("PATH", "")

	_, err := NewGopassProvider("")
	if err == nil {
		t.Fatal("expected error when gopass binary is not found")
	}
	if !strings.Contains(err.Error(), "binary not found") {
		t.Errorf("error = %q, want it to contain \"binary not found\"", err.Error())
	}
}
