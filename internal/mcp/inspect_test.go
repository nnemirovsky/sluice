package mcp

import (
	"encoding/json"
	"testing"

	"github.com/nemirovsky/sluice/internal/policy"
)

func TestInspectBlocksAPIKeyInArgs(t *testing.T) {
	ci, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Name: "api_key_leak"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{"content": "use key sk-abcdefghijklmnopqrstuvwxyz1234 to authenticate"}`)
	result := ci.InspectArguments(args)
	if !result.Blocked {
		t.Error("expected arguments to be blocked for API key pattern")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleName != "api_key_leak" {
		t.Errorf("expected rule name %q, got %q", "api_key_leak", result.Findings[0].RuleName)
	}
	if result.Findings[0].Location != "args" {
		t.Errorf("expected location %q, got %q", "args", result.Findings[0].Location)
	}
}

func TestInspectBlocksCredentialInArgs(t *testing.T) {
	ci, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(password|passwd|secret)\s*[:=]\s*\S+`, Name: "credential_in_args"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{"cmd": "curl -u user password=hunter2 http://example.com"}`)
	result := ci.InspectArguments(args)
	if !result.Blocked {
		t.Error("expected arguments to be blocked for credential pattern")
	}
}

func TestInspectAllowsCleanArgs(t *testing.T) {
	ci, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Name: "api_key_leak"},
			{Pattern: `(?i)(password|passwd|secret)\s*[:=]\s*\S+`, Name: "credential_in_args"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{"path": "/home/user/documents", "content": "Hello, world!"}`)
	result := ci.InspectArguments(args)
	if result.Blocked {
		t.Error("expected clean arguments to pass inspection")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestInspectMultipleBlockFindings(t *testing.T) {
	ci, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Name: "api_key_leak"},
			{Pattern: `(?i)(password|passwd|secret)\s*[:=]\s*\S+`, Name: "credential_in_args"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	args := json.RawMessage(`{"cmd": "export password=hunter2 && use sk-abcdefghijklmnopqrstuvwxyz1234"}`)
	result := ci.InspectArguments(args)
	if !result.Blocked {
		t.Error("expected arguments to be blocked")
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestRedactAPIKeyInResponse(t *testing.T) {
	ci, err := NewContentInspector(
		nil,
		[]policy.InspectRedactRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Replacement: "[REDACTED_API_KEY]", Name: "api_key_in_response"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	input := "The API key is sk-abcdefghijklmnopqrstuvwxyz1234 and it works"
	got := ci.RedactResponse(input)
	want := "The API key is [REDACTED_API_KEY] and it works"
	if got != want {
		t.Errorf("RedactResponse = %q, want %q", got, want)
	}
}

func TestRedactEmailInResponse(t *testing.T) {
	ci, err := NewContentInspector(
		nil,
		[]policy.InspectRedactRule{
			{Pattern: `(?i)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`, Replacement: "[REDACTED_EMAIL]", Name: "email_in_response"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	input := "Contact user@example.com for details"
	got := ci.RedactResponse(input)
	want := "Contact [REDACTED_EMAIL] for details"
	if got != want {
		t.Errorf("RedactResponse = %q, want %q", got, want)
	}
}

func TestRedactPreservesCleanContent(t *testing.T) {
	ci, err := NewContentInspector(
		nil,
		[]policy.InspectRedactRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Replacement: "[REDACTED_API_KEY]", Name: "api_key_in_response"},
			{Pattern: `(?i)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`, Replacement: "[REDACTED_EMAIL]", Name: "email_in_response"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	input := "This is a normal response with no sensitive data. File count: 42."
	got := ci.RedactResponse(input)
	if got != input {
		t.Errorf("RedactResponse modified clean content: %q", got)
	}
}

func TestRedactMultiplePatterns(t *testing.T) {
	ci, err := NewContentInspector(
		nil,
		[]policy.InspectRedactRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Replacement: "[REDACTED_API_KEY]", Name: "api_key"},
			{Pattern: `(?i)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`, Replacement: "[REDACTED_EMAIL]", Name: "email"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	input := "Key: sk-abcdefghijklmnopqrstuvwxyz1234, email: admin@corp.io"
	got := ci.RedactResponse(input)
	want := "Key: [REDACTED_API_KEY], email: [REDACTED_EMAIL]"
	if got != want {
		t.Errorf("RedactResponse = %q, want %q", got, want)
	}
}

func TestNewContentInspectorInvalidBlockPattern(t *testing.T) {
	_, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?P<bad`, Name: "broken"},
		},
		nil,
	)
	if err == nil {
		t.Error("expected error for invalid block regex pattern")
	}
}

func TestNewContentInspectorInvalidRedactPattern(t *testing.T) {
	_, err := NewContentInspector(
		nil,
		[]policy.InspectRedactRule{
			{Pattern: `[invalid`, Replacement: "x", Name: "broken"},
		},
	)
	if err == nil {
		t.Error("expected error for invalid redact regex pattern")
	}
}

func TestNilArgsInspection(t *testing.T) {
	ci, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Name: "api_key_leak"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	result := ci.InspectArguments(nil)
	if result.Blocked {
		t.Error("nil args should not be blocked")
	}
}
