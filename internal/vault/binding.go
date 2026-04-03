package vault

import (
	"fmt"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
)

// Binding maps a destination pattern to a credential and injection strategy.
type Binding struct {
	Destination  string
	Ports        []int
	Credential   string
	InjectHeader string
	Template     string
	Protocol     string
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

// FormatValue applies the binding's template to a secret value.
// If no template is set, the raw secret is returned.
func (b Binding) FormatValue(secret string) string {
	if b.Template == "" {
		return secret
	}
	return strings.Replace(b.Template, "{value}", secret, 1)
}
