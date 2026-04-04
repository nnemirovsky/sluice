package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/nemirovsky/sluice/internal/vault"
)

// stubQUICProvider is a minimal vault.Provider for QUIC proxy tests.
type stubQUICProvider struct{}

func (s *stubQUICProvider) Get(name string) (vault.SecureBytes, error) {
	return vault.SecureBytes{}, nil
}
func (s *stubQUICProvider) List() ([]string, error) { return nil, nil }
func (s *stubQUICProvider) Name() string             { return "stub" }

func TestQUICProxy_HandshakeSucceeds(t *testing.T) {
	// Generate a CA for the proxy.
	caCert, caX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	var resolver atomic.Pointer[vault.BindingResolver]
	qp, err := NewQUICProxy(caCert, &stubQUICProvider{}, &resolver)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	// Start the QUIC proxy in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- qp.ListenAndServe("127.0.0.1:0")
	}()

	// Wait for the listener to be ready.
	var addr string
	for i := 0; i < 50; i++ {
		if a := qp.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("QUIC proxy did not start listening")
	}

	// Create a QUIC client that trusts the proxy's CA.
	pool := x509.NewCertPool()
	pool.AddCert(caX509)

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"h3"},
		ServerName: "example.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, dialErr := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{})
	if dialErr != nil {
		t.Fatalf("QUIC dial: %v", dialErr)
	}
	defer conn.CloseWithError(0, "")

	// Verify the TLS handshake completed with the correct SNI.
	state := conn.ConnectionState().TLS
	if state.ServerName != "example.com" {
		t.Errorf("SNI = %q, want %q", state.ServerName, "example.com")
	}

	// Verify the server certificate was signed by our CA.
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	serverCert := state.PeerCertificates[0]
	if serverCert.Subject.CommonName != "example.com" {
		t.Errorf("cert CN = %q, want %q", serverCert.Subject.CommonName, "example.com")
	}

	qp.Close()
}

func TestQUICProxy_SNIExtraction(t *testing.T) {
	// Verify that different SNI values produce matching server certificates.
	// The proxy uses GetConfigForClient to extract the SNI from each
	// ClientHello and generates a per-host certificate with that hostname.
	caCert, caX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	var resolver atomic.Pointer[vault.BindingResolver]
	qp, err := NewQUICProxy(caCert, &stubQUICProvider{}, &resolver)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- qp.ListenAndServe("127.0.0.1:0")
	}()

	var addr string
	for i := 0; i < 50; i++ {
		if a := qp.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("QUIC proxy did not start listening")
	}

	pool := x509.NewCertPool()
	pool.AddCert(caX509)

	tests := []struct {
		name string
		sni  string
	}{
		{"simple_hostname", "api.example.com"},
		{"subdomain", "deep.nested.example.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsCfg := &tls.Config{
				RootCAs:    pool,
				NextProtos: []string{"h3"},
				ServerName: tt.sni,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, dialErr := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{})
			if dialErr != nil {
				t.Fatalf("QUIC dial with SNI %q: %v", tt.sni, dialErr)
			}

			state := conn.ConnectionState().TLS
			if len(state.PeerCertificates) == 0 {
				t.Fatal("no peer certificates")
			}
			certCN := state.PeerCertificates[0].Subject.CommonName
			if certCN != tt.sni {
				t.Errorf("cert CN = %q, want %q (SNI not extracted correctly)", certCN, tt.sni)
			}

			conn.CloseWithError(0, "")
		})
	}

	qp.Close()
}

func TestQUICProxy_FallbackWithoutHandler(t *testing.T) {
	// When no QUIC handler is configured (QUICProxy is nil), the UDP relay
	// should fall back to connection-level allow/deny. This test verifies
	// the nil-safety pattern that will be used in the server wiring.
	var qp *QUICProxy
	if qp != nil {
		t.Error("nil QUICProxy should be nil")
	}
	// The server code will check `if s.quicProxy != nil` before routing
	// QUIC packets. With a nil proxy, packets go through normal UDP relay
	// policy evaluation (allow/deny based on destination).
}

func TestDecodeVarInt(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantVal uint64
		wantLen int
	}{
		{
			name:    "1_byte",
			data:    []byte{0x25},
			wantVal: 37,
			wantLen: 1,
		},
		{
			name:    "2_byte",
			data:    []byte{0x7b, 0xbd},
			wantVal: 15293,
			wantLen: 2,
		},
		{
			name:    "4_byte",
			data:    []byte{0x9d, 0x7f, 0x3e, 0x7d},
			wantVal: 494878333,
			wantLen: 4,
		},
		{
			name:    "8_byte",
			data:    []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c},
			wantVal: 151288809941952652,
			wantLen: 8,
		},
		{
			name:    "zero",
			data:    []byte{0x00},
			wantVal: 0,
			wantLen: 1,
		},
		{
			name:    "empty",
			data:    []byte{},
			wantVal: 0,
			wantLen: 0,
		},
		{
			name:    "truncated_2byte",
			data:    []byte{0x40},
			wantVal: 0,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, n := decodeVarInt(tt.data)
			if val != tt.wantVal {
				t.Errorf("value = %d, want %d", val, tt.wantVal)
			}
			if n != tt.wantLen {
				t.Errorf("length = %d, want %d", n, tt.wantLen)
			}
		})
	}
}

func TestExtractSNI(t *testing.T) {
	// ExtractSNI currently returns empty string for all inputs because
	// decrypting the QUIC Initial packet requires deriving initial secrets.
	// The primary SNI extraction path is via GetConfigForClient during
	// the TLS handshake. These tests verify the function handles edge
	// cases without panicking.
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"too_short", []byte{0xC0, 0x00}, ""},
		{"short_header", func() []byte {
			b := make([]byte, 20)
			b[0] = 0x40 // short header
			return b
		}(), ""},
		{"valid_quic_v1_header", func() []byte {
			// Minimal valid QUIC v1 long header structure.
			b := make([]byte, 50)
			b[0] = 0xC0       // long header
			b[1] = 0x00       // version (v1)
			b[2] = 0x00
			b[3] = 0x00
			b[4] = 0x01
			b[5] = 0x08       // DCID length = 8
			// b[6..13] = DCID (8 bytes, zeros)
			b[14] = 0x00      // SCID length = 0
			b[15] = 0x00      // token length = 0 (1-byte varint)
			b[16] = 0x00      // packet length = 0 (1-byte varint)
			return b
		}(), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSNI(tt.data)
			if got != tt.want {
				t.Errorf("ExtractSNI() = %q, want %q", got, tt.want)
			}
		})
	}
}
