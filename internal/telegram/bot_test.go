package telegram

import (
	"strings"
	"testing"
)

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
