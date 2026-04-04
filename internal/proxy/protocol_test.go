package proxy

import (
	"fmt"
	"testing"
)

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		port int
		want Protocol
	}{
		{80, ProtoHTTP},
		{8080, ProtoHTTP},
		{443, ProtoHTTPS},
		{8443, ProtoHTTPS},
		{22, ProtoSSH},
		{143, ProtoIMAP},
		{993, ProtoIMAP},
		{25, ProtoSMTP},
		{587, ProtoSMTP},
		{465, ProtoSMTP},
		{5223, ProtoAPNS},
		{9999, ProtoGeneric},
		{3306, ProtoGeneric},
		{5432, ProtoGeneric},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("port_%d", tt.port), func(t *testing.T) {
			got := DetectProtocol(tt.port)
			if got != tt.want {
				t.Errorf("DetectProtocol(%d) = %q, want %q",
					tt.port, got, tt.want)
			}
		})
	}
}
