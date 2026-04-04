package proxy

import (
	"fmt"
	"net/http"
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

func TestDetectUDPProtocol(t *testing.T) {
	tests := []struct {
		port int
		want Protocol
	}{
		{53, ProtoDNS},
		{443, ProtoQUIC},
		{8443, ProtoQUIC},
		{12345, ProtoGeneric},
		{80, ProtoGeneric},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("port_%d", tt.port), func(t *testing.T) {
			got := DetectUDPProtocol(tt.port)
			if got != tt.want {
				t.Errorf("DetectUDPProtocol(%d) = %q, want %q",
					tt.port, got, tt.want)
			}
		})
	}
}

func TestDetectProtocolFromHeaders(t *testing.T) {
	tests := []struct {
		name  string
		hdr   http.Header
		isTLS bool
		want  Protocol
	}{
		{
			name: "websocket_plaintext",
			hdr: http.Header{
				"Connection": {"Upgrade"},
				"Upgrade":    {"websocket"},
			},
			isTLS: false,
			want:  ProtoWS,
		},
		{
			name: "websocket_tls",
			hdr: http.Header{
				"Connection": {"Upgrade"},
				"Upgrade":    {"websocket"},
			},
			isTLS: true,
			want:  ProtoWSS,
		},
		{
			name: "websocket_case_insensitive",
			hdr: http.Header{
				"Connection": {"upgrade"},
				"Upgrade":    {"WebSocket"},
			},
			isTLS: false,
			want:  ProtoWS,
		},
		{
			name: "websocket_connection_multi_value",
			hdr: http.Header{
				"Connection": {"keep-alive, Upgrade"},
				"Upgrade":    {"websocket"},
			},
			isTLS: true,
			want:  ProtoWSS,
		},
		{
			name: "grpc",
			hdr: http.Header{
				"Content-Type": {"application/grpc"},
			},
			isTLS: true,
			want:  ProtoGRPC,
		},
		{
			name: "grpc_with_encoding",
			hdr: http.Header{
				"Content-Type": {"application/grpc+proto"},
			},
			isTLS: false,
			want:  ProtoGRPC,
		},
		{
			name:  "plain_http",
			hdr:   http.Header{},
			isTLS: false,
			want:  ProtoGeneric,
		},
		{
			name: "upgrade_without_websocket",
			hdr: http.Header{
				"Connection": {"Upgrade"},
				"Upgrade":    {"h2c"},
			},
			isTLS: false,
			want:  ProtoGeneric,
		},
		{
			name: "json_content_type",
			hdr: http.Header{
				"Content-Type": {"application/json"},
			},
			isTLS: false,
			want:  ProtoGeneric,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectProtocolFromHeaders(tt.hdr, tt.isTLS)
			if got != tt.want {
				t.Errorf("DetectProtocolFromHeaders() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsQUICPacket(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "quic_v1",
			data: func() []byte {
				b := make([]byte, 20)
				b[0] = 0xC0 // long header: form=1, fixed=1
				b[1] = 0x00
				b[2] = 0x00
				b[3] = 0x00
				b[4] = 0x01 // version 1
				return b
			}(),
			want: true,
		},
		{
			name: "quic_v2",
			data: func() []byte {
				b := make([]byte, 20)
				b[0] = 0xC3 // long header with other bits set
				b[1] = 0x6b
				b[2] = 0x33
				b[3] = 0x43
				b[4] = 0xcf // version 0x6b3343cf
				return b
			}(),
			want: true,
		},
		{
			name: "short_header",
			data: func() []byte {
				b := make([]byte, 20)
				b[0] = 0x40 // short header: form=0, fixed=1
				return b
			}(),
			want: false,
		},
		{
			name: "unknown_version",
			data: func() []byte {
				b := make([]byte, 20)
				b[0] = 0xC0
				b[1] = 0xFF
				b[2] = 0xFF
				b[3] = 0xFF
				b[4] = 0xFF
				return b
			}(),
			want: false,
		},
		{
			name: "too_short",
			data: []byte{0xC0, 0x00, 0x00},
			want: false,
		},
		{
			name: "empty",
			data: []byte{},
			want: false,
		},
		{
			name: "non_quic_udp",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			want: false,
		},
		{
			name: "only_form_bit_set",
			data: func() []byte {
				b := make([]byte, 20)
				b[0] = 0x80 // form=1, fixed=0
				b[1] = 0x00
				b[2] = 0x00
				b[3] = 0x00
				b[4] = 0x01
				return b
			}(),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsQUICPacket(tt.data)
			if got != tt.want {
				t.Errorf("IsQUICPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}
