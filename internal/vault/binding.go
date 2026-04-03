package vault

import (
	"fmt"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
)

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
	var fallback *Binding
	for _, cb := range r.bindings {
		if !cb.glob.Match(dest) {
			continue
		}
		if len(cb.ports) > 0 && !cb.ports[port] {
			continue
		}
		if len(cb.binding.Protocols) == 0 {
			if fallback == nil {
				b := cb.binding
				fallback = &b
			}
			continue
		}
		for _, bp := range cb.binding.Protocols {
			if bp == proto {
				return cb.binding, true
			}
		}
	}
	if fallback != nil {
		return *fallback, true
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
			if hint == "" {
				hint = cb.binding.Protocols[0]
			} else if hint != cb.binding.Protocols[0] {
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

// FormatValue applies the binding's template to a secret value.
// If no template is set, the raw secret is returned.
func (b Binding) FormatValue(secret string) string {
	if b.Template == "" {
		return secret
	}
	return strings.Replace(b.Template, "{value}", secret, 1)
}
