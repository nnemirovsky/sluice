package policy

import "testing"

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{"api.anthropic.com", "api.anthropic.com", true},
		{"api.anthropic.com", "api.openai.com", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "raw.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "evil.com", false},
		{"169.254.169.254", "169.254.169.254", true},
		{"*.crypto-mining.*", "pool.crypto-mining.io", true},
		{"*", "anything.at.all", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.input, func(t *testing.T) {
			g, err := CompileGlob(tt.pattern)
			if err != nil {
				t.Fatalf("compile glob %q: %v", tt.pattern, err)
			}
			got := g.Match(tt.input)
			if got != tt.want {
				t.Errorf("Glob(%q).Match(%q) = %v, want %v",
					tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}
