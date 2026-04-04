package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/nemirovsky/sluice/internal/vault"
)

// QUICProxy terminates QUIC connections from the agent using sluice's CA
// certificate. It generates per-host TLS certificates based on the SNI
// from the TLS ClientHello, enabling HTTP/3 MITM credential injection.
type QUICProxy struct {
	caCert   tls.Certificate
	caX509   *x509.Certificate
	provider vault.Provider
	resolver *atomic.Pointer[vault.BindingResolver]

	// mu protects listener lifecycle.
	mu       sync.Mutex
	listener *quic.Listener
	addr     net.Addr
	closed   bool
}

// NewQUICProxy creates a QUIC proxy that terminates agent QUIC connections.
// The caCert is used to sign per-host TLS certificates derived from the SNI.
func NewQUICProxy(
	caCert tls.Certificate,
	provider vault.Provider,
	resolver *atomic.Pointer[vault.BindingResolver],
) (*QUICProxy, error) {
	caX509 := caCert.Leaf
	if caX509 == nil {
		var err error
		caX509, err = x509.ParseCertificate(caCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse CA cert: %w", err)
		}
	}
	return &QUICProxy{
		caCert:   caCert,
		caX509:   caX509,
		provider: provider,
		resolver: resolver,
	}, nil
}

// ListenAndServe starts the QUIC listener on the given UDP address and
// accepts connections. It blocks until Close is called or an unrecoverable
// error occurs.
func (q *QUICProxy) ListenAndServe(addr string) error {
	tlsCfg := &tls.Config{
		GetConfigForClient: q.getConfigForClient,
		NextProtos:         []string{"h3"},
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{})
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}

	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		ln.Close()
		return fmt.Errorf("quic proxy already closed")
	}
	q.listener = ln
	q.addr = ln.Addr()
	q.mu.Unlock()

	log.Printf("[QUIC] listening on %s", ln.Addr())
	for {
		conn, acceptErr := ln.Accept(context.Background())
		if acceptErr != nil {
			q.mu.Lock()
			closed := q.closed
			q.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("quic accept: %w", acceptErr)
		}
		go q.handleConnection(conn)
	}
}

// Addr returns the local address the QUIC proxy is listening on.
// Returns nil if not yet listening.
func (q *QUICProxy) Addr() net.Addr {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.addr
}

// Close shuts down the QUIC listener.
func (q *QUICProxy) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	if q.listener != nil {
		return q.listener.Close()
	}
	return nil
}

// getConfigForClient returns a per-connection TLS config that generates a
// certificate matching the SNI from the ClientHello.
func (q *QUICProxy) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	host := hello.ServerName
	if host == "" {
		host = "localhost"
	}

	cert, err := GenerateHostCert(q.caCert, host)
	if err != nil {
		return nil, fmt.Errorf("generate cert for %s: %w", host, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, nil
}

// handleConnection processes a single accepted QUIC connection.
// HTTP/3 request interception will be added in Task 10.
func (q *QUICProxy) handleConnection(conn *quic.Conn) {
	defer func() {
		conn.CloseWithError(0, "")
	}()

	sni := conn.ConnectionState().TLS.ServerName
	log.Printf("[QUIC] accepted connection from %s (SNI: %s)", conn.RemoteAddr(), sni)

	// Task 10 will add HTTP/3 request interception here.
	// For now, the connection is accepted and immediately closed.
	// This proves TLS termination works with the per-host cert.
}

// ExtractSNI extracts the Server Name Indication from a QUIC Initial packet
// by parsing the TLS ClientHello embedded in the CRYPTO frame. This is used
// for logging and routing before the QUIC handshake completes.
//
// The function parses the minimal QUIC long header structure to reach the
// TLS payload. Returns empty string if the packet cannot be parsed.
func ExtractSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// Must be a long header (form bit set).
	if data[0]&0x80 == 0 {
		return ""
	}

	offset := 5 // skip first byte + 4-byte version

	// DCID length + DCID
	if offset >= len(data) {
		return ""
	}
	dcidLen := int(data[offset])
	offset += 1 + dcidLen

	// SCID length + SCID
	if offset >= len(data) {
		return ""
	}
	scidLen := int(data[offset])
	offset += 1 + scidLen

	// Token length (variable-length integer)
	if offset >= len(data) {
		return ""
	}
	tokenLen, tokenLenSize := decodeVarInt(data[offset:])
	if tokenLenSize == 0 {
		return ""
	}
	offset += tokenLenSize + int(tokenLen)

	// Packet length (variable-length integer)
	if offset >= len(data) {
		return ""
	}
	_, pktLenSize := decodeVarInt(data[offset:])
	if pktLenSize == 0 {
		return ""
	}
	offset += pktLenSize

	// The rest is encrypted packet number + payload. We cannot decrypt it
	// without knowing the initial keys derived from the DCID.
	// For SNI extraction before handshake we need to derive QUIC initial
	// secrets, which is complex. Return empty for now.
	// The TLS ClientHello SNI is available after the handshake via
	// GetConfigForClient, which is the primary extraction path.
	_ = offset
	return ""
}

// decodeVarInt decodes a QUIC variable-length integer (RFC 9000, Section 16).
// Returns the value and the number of bytes consumed. Returns 0,0 on error.
func decodeVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	prefix := data[0] >> 6
	length := 1 << prefix
	if len(data) < length {
		return 0, 0
	}
	var val uint64
	switch length {
	case 1:
		val = uint64(data[0] & 0x3F)
	case 2:
		val = uint64(data[0]&0x3F)<<8 | uint64(data[1])
	case 4:
		val = uint64(data[0]&0x3F)<<24 | uint64(data[1])<<16 |
			uint64(data[2])<<8 | uint64(data[3])
	case 8:
		val = uint64(data[0]&0x3F)<<56 | uint64(data[1])<<48 |
			uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 |
			uint64(data[6])<<8 | uint64(data[7])
	}
	return val, length
}
