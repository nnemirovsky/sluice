package proxy

import (
	"fmt"
	"testing"
)

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		dest string
		port int
		want Protocol
	}{
		{"example.com", 80, ProtoHTTP},
		{"example.com", 8080, ProtoHTTP},
		{"api.anthropic.com", 443, ProtoHTTPS},
		{"api.anthropic.com", 8443, ProtoHTTPS},
		{"github.com", 22, ProtoSSH},
		{"imap.gmail.com", 143, ProtoIMAP},
		{"imap.gmail.com", 993, ProtoIMAP},
		{"smtp.gmail.com", 25, ProtoSMTP},
		{"smtp.gmail.com", 587, ProtoSMTP},
		{"smtp.gmail.com", 465, ProtoSMTP},
		{"random.com", 9999, ProtoGeneric},
		{"random.com", 3306, ProtoGeneric},
		{"random.com", 5432, ProtoGeneric},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			got := DetectProtocol(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("DetectProtocol(%q, %d) = %q, want %q",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}
