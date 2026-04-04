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

func TestProtoMatchesBinding(t *testing.T) {
	tests := []struct {
		binding string
		caller  string
		want    bool
	}{
		// Exact matches.
		{"https", "https", true},
		{"ssh", "ssh", true},
		{"dns", "dns", true},

		// TCP meta-protocol matches TCP-based protocols.
		{"tcp", "http", true},
		{"tcp", "https", true},
		{"tcp", "ssh", true},
		{"tcp", "imap", true},
		{"tcp", "smtp", true},
		{"tcp", "ws", true},
		{"tcp", "wss", true},
		{"tcp", "grpc", true},
		{"tcp", "apns", true},
		{"tcp", "generic", true},
		{"tcp", "tcp", true},

		// TCP meta-protocol must NOT match UDP-family protocols.
		{"tcp", "udp", false},
		{"tcp", "dns", false},
		{"tcp", "quic", false},
		// TCP meta-protocol must not match empty caller.
		{"tcp", "", false},

		// UDP meta-protocol matches UDP-family protocols.
		{"udp", "udp", true},
		{"udp", "dns", true},
		{"udp", "quic", true},

		// UDP meta-protocol must NOT match TCP-based protocols.
		{"udp", "http", false},
		{"udp", "https", false},
		{"udp", "ssh", false},

		// Non-meta mismatches.
		{"https", "http", false},
		{"ssh", "https", false},
	}
	for _, tt := range tests {
		t.Run(tt.binding+"_"+tt.caller, func(t *testing.T) {
			if got := protoMatchesBinding(tt.binding, tt.caller); got != tt.want {
				t.Errorf("protoMatchesBinding(%q, %q) = %v, want %v",
					tt.binding, tt.caller, got, tt.want)
			}
		})
	}
}

func TestResolveForProtocolTCPMeta(t *testing.T) {
	bindings := []Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: "tcp_key", Header: "Authorization", Protocols: []string{"tcp"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// TCP meta-protocol binding should match HTTPS.
	b, ok := resolver.ResolveForProtocol("api.example.com", 443, "https")
	if !ok {
		t.Fatal("expected tcp binding to match https protocol")
	}
	if b.Credential != "tcp_key" {
		t.Errorf("expected tcp_key, got %q", b.Credential)
	}

	// TCP meta-protocol binding should NOT match DNS.
	_, ok = resolver.ResolveForProtocol("api.example.com", 443, "dns")
	if ok {
		t.Error("expected tcp binding to NOT match dns protocol")
	}
}

func TestResolveForProtocolExactBeforeMeta(t *testing.T) {
	// An exact protocol binding must win over a meta-protocol (tcp) binding
	// for the same host:port, regardless of ordering.
	bindings := []Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: "tcp_key", Header: "X-Generic", Protocols: []string{"tcp"}},
		{Destination: "api.example.com", Ports: []int{443}, Credential: "https_key", Header: "Authorization", Protocols: []string{"https"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// HTTPS should pick the exact "https" binding, not the earlier "tcp" one.
	b, ok := resolver.ResolveForProtocol("api.example.com", 443, "https")
	if !ok {
		t.Fatal("expected match for https")
	}
	if b.Credential != "https_key" {
		t.Errorf("expected https_key (exact match), got %q", b.Credential)
	}

	// SSH has no exact binding but matches tcp meta-protocol.
	b, ok = resolver.ResolveForProtocol("api.example.com", 443, "ssh")
	if !ok {
		t.Fatal("expected tcp meta-match for ssh")
	}
	if b.Credential != "tcp_key" {
		t.Errorf("expected tcp_key (meta match), got %q", b.Credential)
	}

	// DNS should not match either binding.
	_, ok = resolver.ResolveForProtocol("api.example.com", 443, "dns")
	if ok {
		t.Error("expected no match for dns (UDP-family)")
	}
}

func TestCredentialsForDestinationTCPMeta(t *testing.T) {
	bindings := []Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: "tcp_key", Header: "Authorization", Protocols: []string{"tcp"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// Should include tcp_key when caller protocol is https (TCP-based).
	creds := resolver.CredentialsForDestination("api.example.com", 443, "https")
	if len(creds) != 1 || creds[0] != "tcp_key" {
		t.Errorf("expected [tcp_key] for https, got %v", creds)
	}

	// Should NOT include tcp_key when caller protocol is dns (UDP-based).
	creds = resolver.CredentialsForDestination("api.example.com", 443, "dns")
	if len(creds) != 0 {
		t.Errorf("expected empty for dns, got %v", creds)
	}
}

func TestResolveForProtocolTCPMetaShadowsSpecific(t *testing.T) {
	// Reproduces the Codex-reported issue: on a non-standard port, the
	// initial ResolveForProtocol call uses "generic" (protocol unknown).
	// A protocols=["tcp"] binding matches via meta-protocol, shadowing a
	// more specific protocols=["ssh"] binding. After byte detection reveals
	// SSH, a second ResolveForProtocol with "ssh" must return the specific
	// binding, not the tcp meta-match.
	bindings := []Binding{
		{Destination: "git.example.com", Ports: []int{2222}, Credential: "tcp_key", Header: "X-Generic", Protocols: []string{"tcp"}},
		{Destination: "git.example.com", Ports: []int{2222}, Credential: "ssh_key", Protocols: []string{"ssh"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: initial resolution with "generic" picks the tcp meta-match.
	b, ok := resolver.ResolveForProtocol("git.example.com", 2222, "generic")
	if !ok {
		t.Fatal("expected meta-match for generic")
	}
	if b.Credential != "tcp_key" {
		t.Errorf("step 1: expected tcp_key (meta-match), got %q", b.Credential)
	}

	// Step 2: re-resolution with "ssh" (after byte detection) picks the
	// exact ssh binding, not the tcp meta-match.
	b, ok = resolver.ResolveForProtocol("git.example.com", 2222, "ssh")
	if !ok {
		t.Fatal("expected exact match for ssh")
	}
	if b.Credential != "ssh_key" {
		t.Errorf("step 2: expected ssh_key (exact match), got %q", b.Credential)
	}

	// Same pattern for SMTP on a non-standard port.
	smtpBindings := []Binding{
		{Destination: "mail.example.com", Ports: []int{9025}, Credential: "tcp_key", Protocols: []string{"tcp"}},
		{Destination: "mail.example.com", Ports: []int{9025}, Credential: "smtp_key", Protocols: []string{"smtp"}},
	}
	smtpResolver, err := NewBindingResolver(smtpBindings)
	if err != nil {
		t.Fatal(err)
	}

	b, ok = smtpResolver.ResolveForProtocol("mail.example.com", 9025, "generic")
	if !ok {
		t.Fatal("expected meta-match for generic")
	}
	if b.Credential != "tcp_key" {
		t.Errorf("smtp step 1: expected tcp_key, got %q", b.Credential)
	}

	b, ok = smtpResolver.ResolveForProtocol("mail.example.com", 9025, "smtp")
	if !ok {
		t.Fatal("expected exact match for smtp")
	}
	if b.Credential != "smtp_key" {
		t.Errorf("smtp step 2: expected smtp_key (exact), got %q", b.Credential)
	}
}

func TestResolveProtocolHintSkipsMetaProtocol(t *testing.T) {
	// When a TCP meta-binding and a specific SSH binding exist for the same
	// dest+port, ResolveProtocolHint should skip the meta-binding and return
	// the specific protocol. This lets the dial() fast path resolve the
	// exact binding without falling back to timeout-sensitive byte detection.
	bindings := []Binding{
		{Destination: "git.example.com", Ports: []int{2222}, Credential: "tcp_key", Protocols: []string{"tcp"}},
		{Destination: "git.example.com", Ports: []int{2222}, Credential: "ssh_key", Protocols: []string{"ssh"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	hint, ok := resolver.ResolveProtocolHint("git.example.com", 2222)
	if !ok {
		t.Fatal("expected hint: tcp meta-binding should be skipped, leaving ssh as unambiguous")
	}
	if hint != "ssh" {
		t.Errorf("expected ssh hint, got %q", hint)
	}
}

func TestResolveProtocolHintMetaOnly(t *testing.T) {
	// When the only binding is a meta-protocol (tcp), ResolveProtocolHint
	// should return false because no specific protocol can be determined.
	bindings := []Binding{
		{Destination: "host.example.com", Ports: []int{8000}, Credential: "tcp_key", Protocols: []string{"tcp"}},
	}
	resolver, err := NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := resolver.ResolveProtocolHint("host.example.com", 8000)
	if ok {
		t.Error("expected no hint when only meta-protocol bindings exist")
	}
}

func TestIsMetaProtocol(t *testing.T) {
	if !IsMetaProtocol("tcp") {
		t.Error("expected tcp to be meta-protocol")
	}
	if !IsMetaProtocol("udp") {
		t.Error("expected udp to be meta-protocol")
	}
	if IsMetaProtocol("ssh") {
		t.Error("expected ssh to NOT be meta-protocol")
	}
	if IsMetaProtocol("https") {
		t.Error("expected https to NOT be meta-protocol")
	}
	if IsMetaProtocol("") {
		t.Error("expected empty string to NOT be meta-protocol")
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
