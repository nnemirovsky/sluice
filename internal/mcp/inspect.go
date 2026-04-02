package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/nemirovsky/sluice/internal/policy"
)

// InspectionResult holds the outcome of inspecting tool arguments.
type InspectionResult struct {
	Blocked  bool
	Reason   string
	Findings []Finding
}

// Finding represents a single content inspection match.
type Finding struct {
	RuleName string
	Match    string
	Location string // "args" or "response"
}

type compiledBlockRule struct {
	re   *regexp.Regexp
	name string
}

type compiledRedactRule struct {
	re          *regexp.Regexp
	replacement string
	name        string
}

// ContentInspector checks tool arguments for blocked patterns and redacts
// sensitive content in tool responses.
type ContentInspector struct {
	blockRules  []compiledBlockRule
	redactRules []compiledRedactRule
}

// NewContentInspector compiles block and redact rules into a ready-to-use inspector.
func NewContentInspector(blockRules []policy.InspectBlockRule, redactRules []policy.InspectRedactRule) (*ContentInspector, error) {
	ci := &ContentInspector{}
	for _, r := range blockRules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile block pattern %q: %w", r.Name, err)
		}
		ci.blockRules = append(ci.blockRules, compiledBlockRule{re: re, name: r.Name})
	}
	for _, r := range redactRules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile redact pattern %q: %w", r.Name, err)
		}
		ci.redactRules = append(ci.redactRules, compiledRedactRule{re: re, replacement: r.Replacement, name: r.Name})
	}
	return ci, nil
}

// InspectArguments checks tool arguments for blocked patterns.
// Returns a result with Blocked=true if any block rule matches.
func (ci *ContentInspector) InspectArguments(args json.RawMessage) InspectionResult {
	argsStr := string(args)
	var findings []Finding
	for _, r := range ci.blockRules {
		if match := r.re.FindString(argsStr); match != "" {
			findings = append(findings, Finding{
				RuleName: r.name,
				Match:    match,
				Location: "args",
			})
		}
	}
	if len(findings) > 0 {
		return InspectionResult{
			Blocked:  true,
			Reason:   fmt.Sprintf("blocked by rule %q", findings[0].RuleName),
			Findings: findings,
		}
	}
	return InspectionResult{}
}

// RedactResponse sanitizes tool response content by replacing matches
// with configured replacement strings.
func (ci *ContentInspector) RedactResponse(content string) string {
	for _, r := range ci.redactRules {
		content = r.re.ReplaceAllString(content, r.replacement)
	}
	return content
}
