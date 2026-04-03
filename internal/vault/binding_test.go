package vault

import "testing"

func TestResolveBinding(t *testing.T) {
	bindings := []Binding{
		{Destination: "api.anthropic.com", Ports: []int{443}, Credential: "anthropic_key", Header: "x-api-key"},
		{Destination: "api.github.com", Ports: []int{443}, Credential: "github_token", Header: "Authorization", Template: "Bearer {value}"},
		{Destination: "*.openai.com", Ports: []int{443}, Credential: "openai_key", Header: "Authorization", Template: "Bearer {value}"},
	}

	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

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
		{Destination: "api.anthropic.com", Ports: []int{443}, Credential: "anthropic_key", Header: "x-api-key"},
	}

	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := resolver.Resolve("api.anthropic.com", 80)
	if ok {
		t.Error("expected no match for port 80")
	}
}

func TestResolveForProtocol(t *testing.T) {
	bindings := []Binding{
		{Destination: "example.com", Ports: []int{443}, Credential: "ssh_key", Protocols: []string{"ssh"}},
		{Destination: "example.com", Ports: []int{443}, Credential: "api_key", Header: "Authorization", Protocols: []string{"https"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// HTTPS protocol should match the second binding, not the first.
	b, ok := resolver.ResolveForProtocol("example.com", 443, "https")
	if !ok {
		t.Fatal("expected match for example.com:443 with https protocol")
	}
	if b.Credential != "api_key" {
		t.Errorf("expected api_key, got %q", b.Credential)
	}

	// SSH protocol should match the first binding.
	b, ok = resolver.ResolveForProtocol("example.com", 443, "ssh")
	if !ok {
		t.Fatal("expected match for example.com:443 with ssh protocol")
	}
	if b.Credential != "ssh_key" {
		t.Errorf("expected ssh_key, got %q", b.Credential)
	}

	// No binding with imap protocol for this host.
	_, ok = resolver.ResolveForProtocol("example.com", 443, "imap")
	if ok {
		t.Error("expected no match for imap protocol")
	}

	// Empty protocol string should behave like Resolve (first match).
	b, ok = resolver.ResolveForProtocol("example.com", 443, "")
	if !ok {
		t.Fatal("expected match for empty protocol")
	}
	if b.Credential != "ssh_key" {
		t.Errorf("expected ssh_key (first match), got %q", b.Credential)
	}
}

func TestResolveForProtocolFallback(t *testing.T) {
	// A protocol-agnostic binding (empty Protocols) should be returned
	// as fallback when no protocol-specific binding matches.
	bindings := []Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: "ssh_key", Protocols: []string{"ssh"}},
		{Destination: "api.example.com", Ports: []int{443}, Credential: "generic_key", Header: "Authorization"},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// HTTPS has no protocol-specific match, should fall back to the generic binding.
	b, ok := resolver.ResolveForProtocol("api.example.com", 443, "https")
	if !ok {
		t.Fatal("expected fallback match for https protocol")
	}
	if b.Credential != "generic_key" {
		t.Errorf("expected generic_key (fallback), got %q", b.Credential)
	}

	// SSH has a protocol-specific match, should return it (not the fallback).
	b, ok = resolver.ResolveForProtocol("api.example.com", 443, "ssh")
	if !ok {
		t.Fatal("expected match for ssh protocol")
	}
	if b.Credential != "ssh_key" {
		t.Errorf("expected ssh_key, got %q", b.Credential)
	}
}

func TestResolveProtocolHint(t *testing.T) {
	bindings := []Binding{
		{Destination: "service.example.com", Ports: []int{8000}, Credential: "generic_key"},
		{Destination: "service.example.com", Ports: []int{8000}, Credential: "http_key", Header: "Authorization", Protocols: []string{"http"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// Should find the single-protocol "http" hint from the second binding.
	hint, ok := resolver.ResolveProtocolHint("service.example.com", 8000)
	if !ok {
		t.Fatal("expected protocol hint for service.example.com:8000")
	}
	if hint != "http" {
		t.Errorf("expected http hint, got %q", hint)
	}

	// No binding for this destination.
	_, ok = resolver.ResolveProtocolHint("other.com", 8000)
	if ok {
		t.Error("expected no hint for other.com")
	}

	// Port mismatch.
	_, ok = resolver.ResolveProtocolHint("service.example.com", 9000)
	if ok {
		t.Error("expected no hint for port 9000")
	}
}

func TestResolveProtocolHintSkipsMultiProtocol(t *testing.T) {
	bindings := []Binding{
		{Destination: "mail.example.com", Ports: []int{2525}, Credential: "mail_key", Protocols: []string{"imap", "smtp"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// Multi-protocol bindings should not be returned as hints
	// because the protocol is ambiguous.
	_, ok := resolver.ResolveProtocolHint("mail.example.com", 2525)
	if ok {
		t.Error("expected no hint for multi-protocol binding")
	}
}

func TestResolveForProtocolGenericWithMixedBindings(t *testing.T) {
	// Reproduces the scenario where a protocol-agnostic binding masks
	// a protocol-specific binding on non-standard ports. Without the
	// ResolveProtocolHint check in server.go, the agnostic binding
	// would be returned and the protocol would remain "generic",
	// causing the connection to bypass the injector.
	bindings := []Binding{
		{Destination: "service.example.com", Ports: []int{8000}, Credential: "generic_key"},
		{Destination: "service.example.com", Ports: []int{8000}, Credential: "http_key", Header: "Authorization", Protocols: []string{"http"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// ResolveForProtocol with "generic" returns the agnostic fallback.
	b, ok := resolver.ResolveForProtocol("service.example.com", 8000, "generic")
	if !ok {
		t.Fatal("expected fallback match")
	}
	if b.Credential != "generic_key" {
		t.Errorf("expected generic_key as fallback, got %q", b.Credential)
	}

	// But ResolveProtocolHint reveals the real protocol.
	hint, hok := resolver.ResolveProtocolHint("service.example.com", 8000)
	if !hok {
		t.Fatal("expected protocol hint")
	}
	if hint != "http" {
		t.Errorf("expected http, got %q", hint)
	}

	// Re-resolving with the hinted protocol gives the specific binding.
	b, ok = resolver.ResolveForProtocol("service.example.com", 8000, hint)
	if !ok {
		t.Fatal("expected match for hinted protocol")
	}
	if b.Credential != "http_key" {
		t.Errorf("expected http_key, got %q", b.Credential)
	}
}

func TestResolveProtocolHintConflictingSingleProtocol(t *testing.T) {
	// When multiple single-protocol bindings exist for the same dest+port
	// with different protocols, the hint is ambiguous and should not be
	// returned. Without this check, whichever binding is listed first
	// would hijack all traffic on that port.
	bindings := []Binding{
		{Destination: "host.example.com", Ports: []int{8000}, Credential: "http_key", Protocols: []string{"http"}},
		{Destination: "host.example.com", Ports: []int{8000}, Credential: "ssh_key", Protocols: []string{"ssh"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := resolver.ResolveProtocolHint("host.example.com", 8000)
	if ok {
		t.Error("expected no hint when multiple conflicting single-protocol bindings exist")
	}
}

func TestResolveProtocolHintConsistentSingleProtocol(t *testing.T) {
	// When multiple single-protocol bindings exist but all agree on the
	// same protocol, the hint should be returned.
	bindings := []Binding{
		{Destination: "host.example.com", Ports: []int{8000}, Credential: "key1", Protocols: []string{"http"}},
		{Destination: "host.example.com", Ports: []int{8000}, Credential: "key2", Protocols: []string{"http"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	hint, ok := resolver.ResolveProtocolHint("host.example.com", 8000)
	if !ok {
		t.Fatal("expected hint when all single-protocol bindings agree")
	}
	if hint != "http" {
		t.Errorf("expected http, got %q", hint)
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
