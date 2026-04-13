package telegram

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/channel"
)

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		check func(string) bool
		desc  string
	}{
		{
			name:  "network error with token URL",
			err:   fmt.Errorf("Post \"https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage\": dial tcp: lookup api.telegram.org: no such host"),
			check: func(s string) bool { return !strings.Contains(s, "123456:ABC") && strings.Contains(s, "<REDACTED>") },
			desc:  "should redact token from URL",
		},
		{
			name:  "error without token",
			err:   fmt.Errorf("connection refused"),
			check: func(s string) bool { return s == "connection refused" },
			desc:  "should leave non-token errors unchanged",
		},
		{
			name:  "TLS error with token",
			err:   fmt.Errorf("Post \"https://api.telegram.org/bot9876543210:AAHW_some-Long-Token-Value/sendMessage\": tls: handshake failure"),
			check: func(s string) bool { return !strings.Contains(s, "9876543210:") && strings.Contains(s, "<REDACTED>") },
			desc:  "should redact token from TLS error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeError(tt.err)
			if !tt.check(result) {
				t.Errorf("%s: got %q", tt.desc, result)
			}
		})
	}
}

func TestFormatApprovalMessage(t *testing.T) {
	t.Run("network connection", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "api.evil.com",
			Port:        443,
			Protocol:    "https",
		}
		msg := FormatApprovalMessage(req)
		if msg == "" {
			t.Fatal("expected non-empty message")
		}
		if !strings.Contains(msg, "api.evil.com") {
			t.Error("message should contain destination")
		}
		if !strings.Contains(msg, "443") {
			t.Error("message should contain port")
		}
		if !strings.Contains(msg, "HTTPS ") {
			t.Error("message should contain protocol display name")
		}
		if !strings.Contains(msg, "OpenClaw wants to connect") {
			t.Error("message should use network connection wording")
		}
	})

	t.Run("network connection with protocol", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "example.com",
			Port:        8080,
			Protocol:    "http",
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, "HTTP <code>example.com:8080</code>") {
			t.Errorf("expected 'HTTP <code>example.com:8080</code>' in message, got: %s", msg)
		}
	})

	t.Run("mcp tool call with valid json args", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "github__delete_repository",
			Port:        0,
			Protocol:    "mcp",
			ToolArgs:    `{"owner":"test","repo":"my-repo"}`,
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, "github__delete_repository") {
			t.Error("message should contain tool name")
		}
		if !strings.Contains(msg, "OpenClaw wants to call tool") {
			t.Error("message should use MCP tool call wording")
		}
		// Args should be pretty-printed inside an HTML <pre><code> block.
		if !strings.Contains(msg, `<pre><code class="language-json">`) {
			t.Error("args should be wrapped in <pre><code> block")
		}
		if !strings.Contains(msg, "\"owner\": \"test\"") {
			t.Errorf("args should be pretty-printed with 2-space indent, got: %s", msg)
		}
		if !strings.Contains(msg, "</code></pre>") {
			t.Error("args code block should be closed")
		}
		if !strings.Contains(msg, "Allow this tool call?") {
			t.Error("message should ask about tool call, not connection")
		}
	})

	t.Run("mcp tool call with invalid json args falls back to raw", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "github__search_repositories",
			Port:        0,
			Protocol:    "mcp",
			// Truncated JSON as produced when the gateway enforces the
			// 200-char limit mid-object.
			ToolArgs: `{"query": "is:private", "perPage": 10, "sor...`,
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, `<pre><code class="language-json">`) {
			t.Error("args should still be wrapped in code block")
		}
		// Raw string preserved when it cannot be parsed.
		if !strings.Contains(msg, "is:private") {
			t.Error("raw args should appear when JSON parse fails")
		}
	})

	t.Run("mcp tool call args with html special chars are escaped", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "shell__exec",
			Port:        0,
			Protocol:    "mcp",
			ToolArgs:    `{"cmd":"<script>alert('xss')</script>"}`,
		}
		msg := FormatApprovalMessage(req)
		if strings.Contains(msg, "<script>") {
			t.Error("html special chars in args must be escaped")
		}
		if !strings.Contains(msg, "&lt;script&gt;") {
			t.Error("expected escaped <script> tag")
		}
	})

	t.Run("mcp tool call without args", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "github__list_repos",
			Port:        0,
			Protocol:    "mcp",
		}
		msg := FormatApprovalMessage(req)
		if strings.Contains(msg, "Arguments:") {
			t.Error("message should not contain Arguments section when ToolArgs is empty")
		}
	})

	t.Run("per-request https approval", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "api.example.com",
			Port:        443,
			Protocol:    "https",
			Method:      "GET",
			Path:        "/users/me",
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, "HTTPS <code>api.example.com:443</code>") {
			t.Errorf("expected destination line in message, got: %s", msg)
		}
		if !strings.Contains(msg, "GET <code>https://api.example.com/users/me</code>") {
			t.Errorf("expected request line in message, got: %s", msg)
		}
		if !strings.Contains(msg, "Allow this request?") {
			t.Errorf("expected 'Allow this request?' wording, got: %s", msg)
		}
	})

	t.Run("per-request http non-standard port", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "localhost",
			Port:        8080,
			Protocol:    "http",
			Method:      "POST",
			Path:        "/api/submit",
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, "POST <code>http://localhost:8080/api/submit</code>") {
			t.Errorf("expected URL with explicit port, got: %s", msg)
		}
	})

	t.Run("per-request approval with empty path defaults to slash", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "example.com",
			Port:        443,
			Protocol:    "https",
			Method:      "HEAD",
			Path:        "",
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, "HEAD <code>https://example.com/</code>") {
			t.Errorf("expected URL with default path '/', got: %s", msg)
		}
	})

	t.Run("per-request approval escapes html special chars", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "evil.com",
			Port:        443,
			Protocol:    "https",
			Method:      "GET",
			Path:        "/<script>alert(1)</script>",
		}
		msg := FormatApprovalMessage(req)
		if strings.Contains(msg, "<script>") {
			t.Errorf("unescaped <script> tag in message: %s", msg)
		}
		if !strings.Contains(msg, "&lt;script&gt;") {
			t.Errorf("expected escaped <script> tag in message, got: %s", msg)
		}
	})

	t.Run("connection-level approval without method does not use per-request format", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "example.com",
			Port:        443,
			Protocol:    "https",
		}
		msg := FormatApprovalMessage(req)
		if strings.Contains(msg, "per-request") {
			t.Errorf("connection-level approval should not include per-request label: %s", msg)
		}
		if !strings.Contains(msg, "Allow this connection?") {
			t.Errorf("expected connection wording, got: %s", msg)
		}
	})
}
