package mcp

import (
	"testing"

	"github.com/nemirovsky/sluice/internal/policy"
)

func TestToolPolicyEvaluate(t *testing.T) {
	tp := NewToolPolicy([]policy.ToolRule{
		{Tool: "github__list_*", Verdict: "allow"},
		{Tool: "github__delete_*", Verdict: "deny"},
		{Tool: "filesystem__write_*", Verdict: "ask"},
		{Tool: "exec__*", Verdict: "deny"},
	}, policy.Ask)

	tests := []struct {
		tool string
		want policy.Verdict
	}{
		{"github__list_repositories", policy.Allow},
		{"github__list_issues", policy.Allow},
		{"github__delete_repository", policy.Deny},
		{"filesystem__write_file", policy.Ask},
		{"filesystem__read_file", policy.Ask}, // default
		{"exec__run", policy.Deny},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			got := tp.Evaluate(tt.tool)
			if got != tt.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}
