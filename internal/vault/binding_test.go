package vault

import "testing"

func TestResolveBinding(t *testing.T) {
	bindings := []Binding{
		{Destination: "api.anthropic.com", Ports: []int{443}, Credential: "anthropic_key", InjectHeader: "x-api-key"},
		{Destination: "api.github.com", Ports: []int{443}, Credential: "github_token", InjectHeader: "Authorization", Template: "Bearer {value}"},
		{Destination: "*.openai.com", Ports: []int{443}, Credential: "openai_key", InjectHeader: "Authorization", Template: "Bearer {value}"},
	}

	resolver := NewBindingResolver(bindings)

	b, ok := resolver.Resolve("api.anthropic.com", 443)
	if !ok {
		t.Fatal("expected match for api.anthropic.com:443")
	}
	if b.Credential != "anthropic_key" {
		t.Errorf("expected anthropic_key, got %q", b.Credential)
	}

	b, ok = resolver.Resolve("api.openai.com", 443)
	if !ok {
		t.Fatal("expected match for api.openai.com:443")
	}
	if b.Credential != "openai_key" {
		t.Errorf("expected openai_key, got %q", b.Credential)
	}

	_, ok = resolver.Resolve("random.com", 443)
	if ok {
		t.Error("expected no match for random.com")
	}
}

func TestResolveBindingPortMismatch(t *testing.T) {
	bindings := []Binding{
		{Destination: "api.anthropic.com", Ports: []int{443}, Credential: "anthropic_key", InjectHeader: "x-api-key"},
	}

	resolver := NewBindingResolver(bindings)

	_, ok := resolver.Resolve("api.anthropic.com", 80)
	if ok {
		t.Error("expected no match for port 80")
	}
}

func TestFormatValue(t *testing.T) {
	b := Binding{Template: "Bearer {value}"}
	got := b.FormatValue("my-token")
	if got != "Bearer my-token" {
		t.Errorf("expected 'Bearer my-token', got %q", got)
	}

	b2 := Binding{}
	got2 := b2.FormatValue("raw-value")
	if got2 != "raw-value" {
		t.Errorf("expected 'raw-value', got %q", got2)
	}
}
