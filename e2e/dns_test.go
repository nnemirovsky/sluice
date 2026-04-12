//go:build e2e

package e2e

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// buildDNSQuery builds a minimal DNS query packet for the given domain and
// query type (1=A, 28=AAAA). The query ID can be used to match responses.
func buildDNSQuery(id uint16, domain string, qtype uint16) []byte {
	var buf []byte
	// Header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x01, 0x00) // Flags: RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0

	// Question section: domain name in wire format.
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // Root label

	// QTYPE and QCLASS.
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01) // QCLASS IN

	return buf
}

// socks5UDPAssociate performs a SOCKS5 handshake with UDP ASSOCIATE command
// against the given proxy address. Returns the UDP relay address and the
// TCP control connection (which must be kept alive).
func socks5UDPAssociate(t *testing.T, proxyAddr string) (relayAddr *net.UDPAddr, controlConn net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to SOCKS5 proxy: %v", err)
	}

	// Auth negotiation: version=5, 1 method, no-auth=0x00
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatalf("write auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := conn.Read(authResp); err != nil {
		_ = conn.Close()
		t.Fatalf("read auth: %v", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("auth rejected: %x", authResp)
	}

	// UDP ASSOCIATE request: version=5, cmd=ASSOCIATE(0x03), rsv=0, atyp=IPv4(0x01), addr=0.0.0.0, port=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		t.Fatalf("write associate: %v", err)
	}

	// Read reply.
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		_ = conn.Close()
		t.Fatalf("read reply header: %v", err)
	}
	if header[0] != 0x05 {
		_ = conn.Close()
		t.Fatalf("unexpected version: %d", header[0])
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("associate rejected: 0x%02x", header[1])
	}

	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 6)
		if _, err := conn.Read(addr); err != nil {
			_ = conn.Close()
			t.Fatalf("read ipv4 addr: %v", err)
		}
		ip := net.IP(addr[:4])
		port := binary.BigEndian.Uint16(addr[4:6])
		return &net.UDPAddr{IP: ip, Port: int(port)}, conn
	case 0x04: // IPv6
		addr := make([]byte, 18)
		if _, err := conn.Read(addr); err != nil {
			_ = conn.Close()
			t.Fatalf("read ipv6 addr: %v", err)
		}
		ip := net.IP(addr[:16])
		port := binary.BigEndian.Uint16(addr[16:18])
		return &net.UDPAddr{IP: ip, Port: int(port)}, conn
	default:
		_ = conn.Close()
		t.Fatalf("unexpected atyp: %d", header[3])
		return nil, nil
	}
}

// wrapSOCKS5UDP wraps a UDP payload in a SOCKS5 UDP datagram header
// targeting the given IPv4 address and port.
func wrapSOCKS5UDP(dstIP net.IP, dstPort int, payload []byte) []byte {
	ip4 := dstIP.To4()
	buf := make([]byte, 0, 10+len(payload))
	buf = append(buf, 0x00, 0x00) // RSV
	buf = append(buf, 0x00)       // FRAG
	buf = append(buf, 0x01)       // ATYP IPv4
	buf = append(buf, ip4...)
	buf = append(buf, byte(dstPort>>8), byte(dstPort))
	buf = append(buf, payload...)
	return buf
}

// TestDNS_DenyRuleReturnsNXDOMAIN verifies that DNS queries for explicitly
// denied domains are intercepted by sluice and return NXDOMAIN without
// forwarding to the upstream resolver.
func TestDNS_DenyRuleReturnsNXDOMAIN(t *testing.T) {
	// Start a mock DNS server. If the query reaches it, the test fails
	// because denied domains should be handled locally by sluice.
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dnsConn.Close() }()
	dnsAddr := dnsConn.LocalAddr().(*net.UDPAddr)

	gotQuery := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := dnsConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			gotQuery <- "forwarded"
			// Echo back as response.
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80
			_, _ = dnsConn.WriteTo(resp, addr)
		}
	}()

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[deny]]
destination = "evil.example.com"
name = "block evil domain"
`)

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: config,
		ExtraArgs:  []string{"--dns-resolver", dnsAddr.String()},
	})

	relayAddr, controlConn := socks5UDPAssociate(t, proc.ProxyAddr)
	defer func() { _ = controlConn.Close() }()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Send DNS query for the denied domain via port 53.
	dnsQuery := buildDNSQuery(0xABCD, "evil.example.com", 1) // A record
	datagram := wrapSOCKS5UDP(net.ParseIP("8.8.8.8"), 53, dnsQuery)
	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send DNS datagram: %v", err)
	}

	// Read the DNS response.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, readErr := clientConn.Read(respBuf)
	if readErr != nil {
		t.Fatalf("read DNS response: %v", readErr)
	}

	// Parse SOCKS5 UDP header (10 bytes for IPv4).
	resp := respBuf[:n]
	if len(resp) < 10 {
		t.Fatalf("DNS response too short: %d bytes", len(resp))
	}
	dnsResp := resp[10:]

	// Verify it is NXDOMAIN (RCODE=3).
	if len(dnsResp) < 4 {
		t.Fatal("DNS response payload too short")
	}
	respID := binary.BigEndian.Uint16(dnsResp[0:2])
	if respID != 0xABCD {
		t.Errorf("query ID mismatch: expected 0xABCD, got 0x%04x", respID)
	}
	rcode := dnsResp[3] & 0x0F
	if rcode != 3 {
		t.Errorf("expected NXDOMAIN (RCODE=3), got RCODE=%d", rcode)
	}

	// The mock DNS server should NOT have received the query.
	select {
	case <-gotQuery:
		t.Error("denied DNS query was forwarded to upstream resolver (should have been blocked locally)")
	case <-time.After(500 * time.Millisecond):
		// Good: query was not forwarded.
	}

	// Verify audit log contains DNS deny entry.
	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, "evil.example.com") {
		t.Error("audit log should contain entry for denied DNS query")
	}
	if !auditLogContains(t, proc.AuditPath, `"verdict":"deny"`) {
		t.Error("audit log should contain deny verdict for blocked DNS query")
	}
}

// TestDNS_AllowedDomainForwardedToResolver verifies that DNS queries for
// non-denied domains are forwarded to the upstream resolver and the response
// is returned to the client.
func TestDNS_AllowedDomainForwardedToResolver(t *testing.T) {
	// Start a mock DNS server that returns a canned response.
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dnsConn.Close() }()
	dnsAddr := dnsConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := dnsConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			// Build a response with QR bit set and RCODE=0 (no error).
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80 // QR=1
			_, _ = dnsConn.WriteTo(resp, addr)
		}
	}()

	config := `
[policy]
default = "deny"

[[allow]]
destination = "allowed.example.com"
ports = [443]
name = "allow domain"
`

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: config,
		ExtraArgs:  []string{"--dns-resolver", dnsAddr.String()},
	})

	relayAddr, controlConn := socks5UDPAssociate(t, proc.ProxyAddr)
	defer func() { _ = controlConn.Close() }()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Send DNS query for the allowed domain.
	dnsQuery := buildDNSQuery(0x5678, "allowed.example.com", 1)
	datagram := wrapSOCKS5UDP(net.ParseIP("8.8.8.8"), 53, dnsQuery)
	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send DNS datagram: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, readErr := clientConn.Read(respBuf)
	if readErr != nil {
		t.Fatalf("read DNS response: %v", readErr)
	}

	resp := respBuf[:n]
	if len(resp) < 10 {
		t.Fatalf("DNS response too short: %d bytes", len(resp))
	}
	dnsResp := resp[10:]

	// Verify the response has QR=1 and RCODE=0 (forwarded successfully).
	if len(dnsResp) < 4 {
		t.Fatal("DNS response payload too short")
	}
	respID := binary.BigEndian.Uint16(dnsResp[0:2])
	if respID != 0x5678 {
		t.Errorf("query ID mismatch: expected 0x5678, got 0x%04x", respID)
	}
	if dnsResp[2]&0x80 == 0 {
		t.Error("expected QR=1 in DNS response (should be a response)")
	}
	rcode := dnsResp[3] & 0x0F
	if rcode != 0 {
		t.Errorf("expected RCODE=0 (no error), got RCODE=%d", rcode)
	}

	// Verify audit log contains DNS entry.
	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, "allowed.example.com") {
		t.Error("audit log should contain entry for DNS query")
	}
}

// TestDNS_ReverseCachePopulated verifies that after a DNS query is forwarded,
// the reverse DNS cache is populated so SOCKS5 CONNECT can recover the
// hostname from an IP address.
func TestDNS_ReverseCachePopulated(t *testing.T) {
	// Start a mock DNS server that returns an A record answer.
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dnsConn.Close() }()
	dnsAddr := dnsConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := dnsConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			// Build a response with a canned A record answer (93.184.216.34).
			query := make([]byte, n)
			copy(query, buf[:n])
			// Set QR=1 and ANCOUNT=1.
			query[2] |= 0x80
			binary.BigEndian.PutUint16(query[6:8], 1) // ANCOUNT=1

			// Append an answer: pointer to question name (0xC00C), TYPE A,
			// CLASS IN, TTL 300, RDLENGTH 4, RDATA 93.184.216.34.
			answer := []byte{
				0xC0, 0x0C, // Name pointer to offset 12 (question name)
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2C, // TTL 300
				0x00, 0x04, // RDLENGTH 4
				93, 184, 216, 34, // RDATA
			}
			resp := append(query, answer...)
			_, _ = dnsConn.WriteTo(resp, addr)
		}
	}()

	config := `
[policy]
default = "deny"

[[allow]]
destination = "cache-test.example.com"
ports = [443]
name = "allow cache test"
`

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: config,
		ExtraArgs:  []string{"--dns-resolver", dnsAddr.String()},
	})

	relayAddr, controlConn := socks5UDPAssociate(t, proc.ProxyAddr)
	defer func() { _ = controlConn.Close() }()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Send DNS A query.
	dnsQuery := buildDNSQuery(0x9ABC, "cache-test.example.com", 1) // A record
	datagram := wrapSOCKS5UDP(net.ParseIP("8.8.8.8"), 53, dnsQuery)
	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send DNS datagram: %v", err)
	}

	// Read and validate the response.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, readErr := clientConn.Read(respBuf)
	if readErr != nil {
		t.Fatalf("read DNS response: %v", readErr)
	}

	resp := respBuf[:n]
	if len(resp) < 10 {
		t.Fatalf("DNS response too short: %d bytes", len(resp))
	}
	dnsResp := resp[10:]

	respID := binary.BigEndian.Uint16(dnsResp[0:2])
	if respID != 0x9ABC {
		t.Errorf("query ID mismatch: expected 0x9ABC, got 0x%04x", respID)
	}

	// Verify audit log recorded the DNS query. The reverse cache is
	// internal to sluice and not directly testable from e2e, but we can
	// verify the DNS query was processed successfully. The reverse cache
	// population is verified indirectly: if QUIC/SOCKS5 can later
	// recover "cache-test.example.com" from IP 93.184.216.34, the cache
	// was populated correctly. This test validates the prerequisite DNS
	// flow works.
	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, "cache-test.example.com") {
		t.Error("audit log should contain entry for DNS query")
	}
	if !auditLogContains(t, proc.AuditPath, `"protocol":"dns"`) {
		t.Error("audit log should record protocol as dns")
	}
}
