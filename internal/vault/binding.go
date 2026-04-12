package vault

import (
	"fmt"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
)

// IsMetaProtocol returns true for transport-level meta-protocols (tcp, udp)
// that match families of specific protocols rather than a single protocol.
func IsMetaProtocol(proto string) bool {
	return proto == "tcp" || proto == "udp"
}

// protoMatchesBinding checks if a caller's detected protocol matches a binding
// protocol entry, with meta-protocol support. "tcp" in a binding matches any
// TCP-based protocol (http, https, ssh, ws, wss, grpc, imap, smtp, apns).
// "udp" in a binding matches any UDP-based protocol (dns, quic).
func protoMatchesBinding(bindingProto, callerProto string) bool {
	if bindingProto == callerProto {
		return true
	}
	switch bindingProto {
	case "tcp":
		switch callerProto {
		case "udp", "dns", "quic":
			return false
		default:
			return callerProto != ""
		}
	case "udp":
		return callerProto == "dns" || callerProto == "quic"
	}
	return false
}

// Binding maps a destination pattern to a credential and injection strategy.
type Binding struct {
	Destination string
	Ports       []int
	Credential  string
	Header      string
	Template    string
	Protocols   []string
}

type compiledBinding struct {
	glob    *policy.Glob
	ports   map[int]bool
	binding Binding
}

// BindingResolver resolves destinations to credential bindings using glob matching.
type BindingResolver struct {
	bindings []compiledBinding
}

// NewBindingResolver compiles glob patterns and creates a resolver.
// Returns an error if any binding has an invalid glob pattern.
func NewBindingResolver(bindings []Binding) (*BindingResolver, error) {
	compiled := make([]compiledBinding, 0, len(bindings))
	for _, b := range bindings {
		g, err := policy.CompileGlob(b.Destination)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %q: %w", b.Destination, err)
		}
		ports := make(map[int]bool, len(b.Ports))
		for _, p := range b.Ports {
			ports[p] = true
		}
		compiled = append(compiled, compiledBinding{glob: g, ports: ports, binding: b})
	}
	return &BindingResolver{bindings: compiled}, nil
}

// Resolve finds the first binding that matches the given destination and port.
func (r *BindingResolver) Resolve(dest string, port int) (Binding, bool) {
	for _, cb := range r.bindings {
		if !cb.glob.Match(dest) {
			continue
		}
		if len(cb.ports) > 0 && !cb.ports[port] {
			continue
		}
		return cb.binding, true
	}
	return Binding{}, false
}

// ResolveForProtocol finds the first binding matching destination, port, and
// protocol. A binding with an empty Protocols list matches any protocol. If
// proto is empty, this behaves like Resolve. When no protocol-specific binding
// matches, falls back to the first binding with an empty Protocols list
// (protocol-agnostic binding).
func (r *BindingResolver) ResolveForProtocol(dest string, port int, proto string) (Binding, bool) {
	if proto == "" {
		return r.Resolve(dest, port)
	}
	var metaFallback *Binding
	var agnosticFallback *Binding
	for _, cb := range r.bindings {
		if !cb.glob.Match(dest) {
			continue
		}
		if len(cb.ports) > 0 && !cb.ports[port] {
			continue
		}
		if len(cb.binding.Protocols) == 0 {
			if agnosticFallback == nil {
				b := cb.binding
				agnosticFallback = &b
			}
			continue
		}
		for _, bp := range cb.binding.Protocols {
			if bp == proto {
				// Exact protocol match wins over meta-protocol.
				return cb.binding, true
			}
			if metaFallback == nil && protoMatchesBinding(bp, proto) {
				b := cb.binding
				metaFallback = &b
			}
		}
	}
	if metaFallback != nil {
		return *metaFallback, true
	}
	if agnosticFallback != nil {
		return *agnosticFallback, true
	}
	return Binding{}, false
}

// ResolveProtocolHint scans bindings matching dest+port and returns the
// protocol from a single-protocol binding, but only when unambiguous.
// If multiple single-protocol bindings exist for the same dest+port with
// different protocols, no hint is returned because the correct protocol
// cannot be determined without inspecting actual traffic. This helps
// determine the correct protocol on non-standard ports where port-based
// detection returns "generic" but a binding carries an explicit protocol
// annotation.
//
// Meta-protocol bindings (protocols=["tcp"] or ["udp"]) are skipped because
// they match entire protocol families rather than identifying a specific
// protocol. Without this, a TCP meta-binding would shadow a more specific
// binding (e.g. protocols=["ssh"]) and prevent the fast path from resolving
// the exact protocol, forcing the connection onto the timeout-sensitive
// byte-detection path.
func (r *BindingResolver) ResolveProtocolHint(dest string, port int) (string, bool) {
	hint := ""
	for _, cb := range r.bindings {
		if !cb.glob.Match(dest) {
			continue
		}
		if len(cb.ports) > 0 && !cb.ports[port] {
			continue
		}
		if len(cb.binding.Protocols) == 1 {
			p := cb.binding.Protocols[0]
			if IsMetaProtocol(p) {
				continue
			}
			if hint == "" {
				hint = p
			} else if hint != p {
				// Multiple single-protocol bindings with different
				// protocols. Ambiguous, so return no hint.
				return "", false
			}
		}
	}
	if hint != "" {
		return hint, true
	}
	return "", false
}

// CredentialsForDestination returns all unique credential names from bindings
// matching the given destination, port, and protocol. Used by the MITM addon
// to scope phantom token replacement to bound credentials only, preventing
// cross-credential exfiltration to unintended destinations.
func (r *BindingResolver) CredentialsForDestination(dest string, port int, proto string) []string {
	var creds []string
	seen := make(map[string]bool)
	for _, cb := range r.bindings {
		if !cb.glob.Match(dest) {
			continue
		}
		if len(cb.ports) > 0 && !cb.ports[port] {
			continue
		}
		// Match protocol: if binding specifies protocols, require a match.
		// Bindings without protocols are protocol-agnostic (match any).
		if proto != "" && len(cb.binding.Protocols) > 0 {
			matched := false
			for _, bp := range cb.binding.Protocols {
				if protoMatchesBinding(bp, proto) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if !seen[cb.binding.Credential] {
			seen[cb.binding.Credential] = true
			creds = append(creds, cb.binding.Credential)
		}
	}
	return creds
}

// FormatValue applies the binding's template to a secret value.
// If no template is set, the raw secret is returned.
//
// Binding templates use the `{value}` placeholder because the binding
// already owns a specific credential (via the Credential field); the
// template only needs to say where to place it.
//
// Note: this is a deliberately different template syntax from MCP
// upstream env/header templates (internal/mcp/upstream.go), which use
// `{vault:<name>}` because they can reference any credential by name and
// need an explicit reference. Do not attempt to unify the two: they
// solve different problems.
func (b Binding) FormatValue(secret string) string {
	if b.Template == "" {
		return secret
	}
	return strings.Replace(b.Template, "{value}", secret, 1)
}
