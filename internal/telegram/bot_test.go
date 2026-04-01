package telegram

import (
	"fmt"
	"strings"
	"testing"
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
	msg := FormatApprovalMessage("api.evil.com", 443)
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
	// Should contain the destination
	if !strings.Contains(msg, "api.evil.com") {
		t.Error("message should contain destination")
	}
	if !strings.Contains(msg, "443") {
		t.Error("message should contain port")
	}
}
