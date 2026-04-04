package proxy

import (
	"fmt"
	"net/http"
	"testing"
)

func TestProtocolStringRoundTrip(t *testing.T) {
	// All Protocol values should round-trip through String() and ParseProtocol().
	allProtocols := []struct {
		proto Protocol
		name  string
	}{
		{ProtoGeneric, "generic"},
		{ProtoHTTP, "http"},
		{ProtoHTTPS, "https"},
		{ProtoSSH, "ssh"},
		{ProtoIMAP, "imap"},
		{ProtoSMTP, "smtp"},
		{ProtoWS, "ws"},
		{ProtoWSS, "wss"},
		{ProtoGRPC, "grpc"},
		{ProtoDNS, "dns"},
		{ProtoQUIC, "quic"},
		{ProtoAPNS, "apns"},
	}

	for _, tt := range allProtocols {
		t.Run(tt.name, func(t *testing.T) {
			// String() returns the expected display name.
			if got := tt.proto.String(); got != tt.name {
				t.Errorf("Protocol(%d).String() = %q, want %q", int(tt.proto), got, tt.name)
			}

			// ParseProtocol() recovers the original Protocol value.
			parsed, err := ParseProtocol(tt.name)
			if err != nil {
				t.Fatalf("ParseProtocol(%q) error: %v", tt.name, err)
			}
			if parsed != tt.proto {
				t.Errorf("ParseProtocol(%q) = %d, want %d", tt.name, int(parsed), int(tt.proto))
			}
		})
	}
}

func TestParseProtocolCaseInsensitive(t *testing.T) {
	parsed, err := ParseProtocol("HTTPS")
	if err != nil {
		t.Fatalf("ParseProtocol(\"HTTPS\") error: %v", err)
	}
	if parsed != ProtoHTTPS {
		t.Errorf("ParseProtocol(\"HTTPS\") = %d, want %d", int(parsed), int(ProtoHTTPS))
	}
}

func TestParseProtocolUnknown(t *testing.T) {
	_, err := ParseProtocol("ftp")
	if err == nil {
		t.Error("ParseProtocol(\"ftp\") should return error for unknown protocol")
	}
}

func TestProtocolStringUnknownValue(t *testing.T) {
	p := Protocol(999)
	if got := p.String(); got != "unknown" {
		t.Errorf("Protocol(999).String() = %q, want \"unknown\"", got)
	}
}

func TestProtocolIntegerValues(t *testing.T) {
	// Verify explicit integer assignments match the plan.
	tests := []struct {
		proto Protocol
		value int
	}{
		{ProtoGeneric, 0},
		{ProtoHTTP, 1},
		{ProtoHTTPS, 2},
		{ProtoSSH, 3},
		{ProtoIMAP, 4},
		{ProtoSMTP, 5},
		{ProtoWS, 6},
		{ProtoWSS, 7},
		{ProtoGRPC, 8},
		{ProtoDNS, 9},
		{ProtoQUIC, 10},
		{ProtoAPNS, 11},
	}
	for _, tt := range tests {
		if int(tt.proto) != tt.value {
			t.Errorf("Protocol %s = %d, want %d", tt.proto, int(tt.proto), tt.value)
		}
	}
}

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
				t.Errorf("DetectProtocol(%d) = %s, want %s",
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
				t.Errorf("DetectUDPProtocol(%d) = %s, want %s",
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
				t.Errorf("DetectProtocolFromHeaders() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDetectFromClientBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Protocol
	}{
		// TLS/HTTPS detection
		{
			name: "tls_1_2",
			data: []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00},
			want: ProtoHTTPS,
		},
		{
			name: "tls_1_1",
			data: []byte{0x16, 0x03, 0x02, 0x00, 0x05},
			want: ProtoHTTPS,
		},
		{
			name: "tls_1_0",
			data: []byte{0x16, 0x03, 0x01, 0x00, 0x05},
			want: ProtoHTTPS,
		},
		// SSH detection
		{
			name: "ssh_banner",
			data: []byte("SSH-2.0-OpenSSH_8.9\r\n"),
			want: ProtoSSH,
		},
		{
			name: "ssh_banner_short",
			data: []byte("SSH-"),
			want: ProtoSSH,
		},
		// HTTP method detection
		{
			name: "http_get",
			data: []byte("GET / HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_post",
			data: []byte("POST /api/v1 HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_put",
			data: []byte("PUT /resource HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_head",
			data: []byte("HEAD / HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_delete",
			data: []byte("DELE /resource HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_patch",
			data: []byte("PATC /resource HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_options",
			data: []byte("OPTI / HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		{
			name: "http_connect",
			data: []byte("CONN example.com:443 HTTP/1.1\r\n"),
			want: ProtoHTTP,
		},
		// No match / generic
		{
			name: "binary_data",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			want: ProtoGeneric,
		},
		{
			name: "empty",
			data: []byte{},
			want: ProtoGeneric,
		},
		{
			name: "nil",
			data: nil,
			want: ProtoGeneric,
		},
		{
			name: "short_tls_incomplete",
			data: []byte{0x16, 0x03},
			want: ProtoGeneric,
		},
		{
			name: "tls_wrong_version",
			data: []byte{0x16, 0x03, 0x00, 0x00, 0x05},
			want: ProtoGeneric,
		},
		{
			name: "tls_ssl3",
			data: []byte{0x16, 0x03, 0x00, 0x00, 0x05},
			want: ProtoGeneric,
		},
		{
			name: "short_ssh",
			data: []byte("SSH"),
			want: ProtoGeneric,
		},
		{
			name: "partial_method",
			data: []byte("GE"),
			want: ProtoGeneric,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectFromClientBytes(tt.data)
			if got != tt.want {
				t.Errorf("DetectFromClientBytes(%v) = %s, want %s", tt.data, got, tt.want)
			}
		})
	}
}

func TestTwoPhaseDetection(t *testing.T) {
	// Two-phase detection: port-based guess + byte-level confirmation.
	tests := []struct {
		name     string
		port     int
		data     []byte
		wantFinal Protocol
	}{
		{
			name:      "https_on_port_8000",
			port:      8000,
			data:      []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00},
			wantFinal: ProtoHTTPS,
		},
		{
			name:      "ssh_on_port_2222",
			port:      2222,
			data:      []byte("SSH-2.0-OpenSSH_8.9\r\n"),
			wantFinal: ProtoSSH,
		},
		{
			name:      "http_on_port_9090",
			port:      9090,
			data:      []byte("GET / HTTP/1.1\r\n"),
			wantFinal: ProtoHTTP,
		},
		{
			name:      "binary_on_standard_port_443_keeps_port_guess",
			port:      443,
			data:      []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			wantFinal: ProtoHTTPS, // byte detection returns generic -> keep port guess
		},
		{
			name:      "standard_port_443_with_tls",
			port:      443,
			data:      []byte{0x16, 0x03, 0x03, 0x00, 0x05},
			wantFinal: ProtoHTTPS,
		},
		{
			name:      "standard_port_22_with_ssh",
			port:      22,
			data:      []byte("SSH-2.0-OpenSSH_8.9\r\n"),
			wantFinal: ProtoSSH,
		},
		{
			name:      "unknown_data_on_non_standard_port",
			port:      12345,
			data:      []byte{0xFF, 0xFE, 0xFD, 0xFC},
			wantFinal: ProtoGeneric,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portGuess := DetectProtocol(tt.port)
			byteDetect := DetectFromClientBytes(tt.data)

			// Two-phase logic: byte detection overrides port guess when
			// it returns a specific protocol (not generic).
			final := portGuess
			if byteDetect != ProtoGeneric {
				final = byteDetect
			}

			if final != tt.wantFinal {
				t.Errorf("two-phase(%d, bytes) = %s (port=%s, bytes=%s), want %s",
					tt.port, final, portGuess, byteDetect, tt.wantFinal)
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
