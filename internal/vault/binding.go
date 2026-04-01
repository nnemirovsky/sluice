package vault

import (
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
)

// Binding maps a destination pattern to a credential and injection strategy.
type Binding struct {
	Destination  string `toml:"destination"`
	Ports        []int  `toml:"ports"`
	Credential   string `toml:"credential"`
	InjectHeader string `toml:"inject_header"`
	Template     string `toml:"template"`
	Protocol     string `toml:"protocol"`
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
// Bindings with invalid glob patterns are silently skipped.
func NewBindingResolver(bindings []Binding) *BindingResolver {
	compiled := make([]compiledBinding, 0, len(bindings))
	for _, b := range bindings {
		g, err := policy.CompileGlob(b.Destination)
		if err != nil {
			continue
		}
		ports := make(map[int]bool, len(b.Ports))
		for _, p := range b.Ports {
			ports[p] = true
		}
		compiled = append(compiled, compiledBinding{glob: g, ports: ports, binding: b})
	}
	return &BindingResolver{bindings: compiled}
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

// FormatValue applies the binding's template to a secret value.
// If no template is set, the raw secret is returned.
func (b Binding) FormatValue(secret string) string {
	if b.Template == "" {
		return secret
	}
	return strings.Replace(b.Template, "{value}", secret, 1)
}
