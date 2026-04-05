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
		if !strings.Contains(msg, "https://") {
			t.Error("message should contain protocol scheme")
		}
		if !strings.Contains(msg, "OpenClaw wants to connect") {
			t.Error("message should use network connection wording")
		}
	})

	t.Run("network connection with empty protocol", func(t *testing.T) {
		req := channel.ApprovalRequest{
			Destination: "example.com",
			Port:        8080,
		}
		msg := FormatApprovalMessage(req)
		if !strings.Contains(msg, "tcp://") {
			t.Error("empty protocol should default to tcp")
		}
	})

	t.Run("mcp tool call", func(t *testing.T) {
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
		if !strings.Contains(msg, `{"owner":"test","repo":"my-repo"}`) {
			t.Error("message should contain tool arguments")
		}
		if !strings.Contains(msg, "Allow this tool call?") {
			t.Error("message should ask about tool call, not connection")
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
}
