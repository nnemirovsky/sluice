package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/policy"
)

// --- ParseSOCKS5UDPHeader tests ---

func TestParseSOCKS5UDPHeader_IPv4(t *testing.T) {
	data := []byte{
		0x00, 0x00, // RSV
		0x00,             // FRAG
		0x01,             // ATYP IPv4
		192, 168, 1, 1,   // IP
		0x00, 0x50,       // Port 80
		'h', 'e', 'l', 'l', 'o',
	}
	addr, port, payload, err := ParseSOCKS5UDPHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "192.168.1.1" {
		t.Errorf("addr = %q, want 192.168.1.1", addr)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
	if string(payload) != "hello" {
		t.Errorf("payload = %q, want hello", string(payload))
	}
}

func TestParseSOCKS5UDPHeader_IPv6(t *testing.T) {
	ipv6 := net.ParseIP("::1").To16()
	data := make([]byte, 0, 26)
	data = append(data, 0x00, 0x00) // RSV
	data = append(data, 0x00)       // FRAG
	data = append(data, 0x04)       // ATYP IPv6
	data = append(data, ipv6...)
	data = append(data, 0x01, 0xBB) // Port 443
	data = append(data, []byte("data")...)

	addr, port, payload, err := ParseSOCKS5UDPHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "::1" {
		t.Errorf("addr = %q, want ::1", addr)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if string(payload) != "data" {
		t.Errorf("payload = %q, want data", string(payload))
	}
}

func TestParseSOCKS5UDPHeader_Domain(t *testing.T) {
	domain := "example.com"
	data := make([]byte, 0, 5+len(domain)+2+3)
	data = append(data, 0x00, 0x00)        // RSV
	data = append(data, 0x00)              // FRAG
	data = append(data, 0x03)              // ATYP Domain
	data = append(data, byte(len(domain))) // domain length
	data = append(data, []byte(domain)...)
	data = append(data, 0x00, 0x35) // Port 53
	data = append(data, []byte("dns")...)

	addr, port, payload, err := ParseSOCKS5UDPHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "example.com" {
		t.Errorf("addr = %q, want example.com", addr)
	}
	if port != 53 {
		t.Errorf("port = %d, want 53", port)
	}
	if string(payload) != "dns" {
		t.Errorf("payload = %q, want dns", string(payload))
	}
}

func TestParseSOCKS5UDPHeader_TooShort(t *testing.T) {
	_, _, _, err := ParseSOCKS5UDPHeader([]byte{0x00, 0x00})
	if err == nil {
		t.Error("expected error for short datagram")
	}
}

func TestParseSOCKS5UDPHeader_Fragmented(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50}
	_, _, _, err := ParseSOCKS5UDPHeader(data)
	if err == nil {
		t.Error("expected error for fragmented datagram")
	}
}

func TestParseSOCKS5UDPHeader_UnsupportedATYP(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0}
	_, _, _, err := ParseSOCKS5UDPHeader(data)
	if err == nil {
		t.Error("expected error for unsupported ATYP")
	}
}

func TestParseSOCKS5UDPHeader_EmptyPayload(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50}
	addr, port, payload, err := ParseSOCKS5UDPHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "10.0.0.1" {
		t.Errorf("addr = %q, want 10.0.0.1", addr)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
	if len(payload) != 0 {
		t.Errorf("payload len = %d, want 0", len(payload))
	}
}

// --- BuildSOCKS5UDPResponse tests ---

func TestBuildSOCKS5UDPResponse_IPv4(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	payload := []byte("response")
	resp := BuildSOCKS5UDPResponse(ip, 8080, payload)

	if len(resp) != 10+len(payload) {
		t.Fatalf("len = %d, want %d", len(resp), 10+len(payload))
	}
	if resp[0] != 0 || resp[1] != 0 {
		t.Error("RSV bytes should be 0")
	}
	if resp[2] != 0 {
		t.Error("FRAG should be 0")
	}
	if resp[3] != 0x01 {
		t.Errorf("ATYP = 0x%02x, want 0x01", resp[3])
	}
	if !net.IP(resp[4:8]).Equal(ip.To4()) {
		t.Error("IP mismatch")
	}
	port := binary.BigEndian.Uint16(resp[8:10])
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
	if string(resp[10:]) != "response" {
		t.Errorf("payload = %q, want response", string(resp[10:]))
	}
}

func TestBuildSOCKS5UDPResponse_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	payload := []byte("v6")
	resp := BuildSOCKS5UDPResponse(ip, 443, payload)

	if len(resp) != 22+len(payload) {
		t.Fatalf("len = %d, want %d", len(resp), 22+len(payload))
	}
	if resp[3] != 0x04 {
		t.Errorf("ATYP = 0x%02x, want 0x04", resp[3])
	}
	if !net.IP(resp[4:20]).Equal(ip.To16()) {
		t.Error("IPv6 mismatch")
	}
	port := binary.BigEndian.Uint16(resp[20:22])
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

func TestBuildSOCKS5UDPResponse_RoundTrip(t *testing.T) {
	// Build a response and parse it back to verify consistency.
	ip := net.ParseIP("172.16.0.1")
	payload := []byte("round-trip")
	resp := BuildSOCKS5UDPResponse(ip, 9999, payload)

	addr, port, data, err := ParseSOCKS5UDPHeader(resp)
	if err != nil {
		t.Fatalf("parse round-trip: %v", err)
	}
	if addr != "172.16.0.1" {
		t.Errorf("addr = %q, want 172.16.0.1", addr)
	}
	if port != 9999 {
		t.Errorf("port = %d, want 9999", port)
	}
	if string(data) != "round-trip" {
		t.Errorf("payload = %q, want round-trip", string(data))
	}
}

// --- UDP policy evaluation tests ---

func TestUDPPolicyEvaluation_Allow(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "8.8.8.8"
ports = [53]
protocols = ["udp"]
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateUDP("8.8.8.8", 53); v != policy.Allow {
		t.Errorf("EvaluateUDP(8.8.8.8, 53) = %v, want Allow", v)
	}
}

func TestUDPPolicyEvaluation_Deny(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "10.0.0.1"
protocols = ["udp"]
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateUDP("10.0.0.1", 80); v != policy.Deny {
		t.Errorf("EvaluateUDP(10.0.0.1, 80) = %v, want Deny", v)
	}
}

func TestUDPPolicyEvaluation_AskTreatedAsDeny(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "ask.example.com"
protocols = ["udp"]
`))
	if err != nil {
		t.Fatal(err)
	}

	// Ask rules are not checked by EvaluateUDP, so the result is Deny.
	if v := eng.EvaluateUDP("ask.example.com", 443); v != policy.Deny {
		t.Errorf("EvaluateUDP(ask.example.com, 443) = %v, want Deny (ask treated as deny)", v)
	}
}

func TestUDPPolicyEvaluation_DefaultDeny(t *testing.T) {
	// Engine default is allow, but EvaluateUDP should still deny
	// when no explicit allow rule matches.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateUDP("any.example.com", 80); v != policy.Deny {
		t.Errorf("EvaluateUDP = %v, want Deny (UDP default-deny overrides engine default)", v)
	}
}

func TestUDPPolicyEvaluation_ProtocolMatching(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "udp-only.example.com"
protocols = ["udp"]

[[allow]]
destination = "tcp-only.example.com"
protocols = ["https"]
`))
	if err != nil {
		t.Fatal(err)
	}

	// protocols=["udp"] matches for UDP evaluation.
	if v := eng.EvaluateUDP("udp-only.example.com", 443); v != policy.Allow {
		t.Errorf("udp-only.example.com = %v, want Allow", v)
	}

	// protocols=["https"] does NOT match for UDP evaluation.
	if v := eng.EvaluateUDP("tcp-only.example.com", 443); v != policy.Deny {
		t.Errorf("tcp-only.example.com = %v, want Deny", v)
	}
}

func TestUDPPolicyEvaluation_NoProtocolField(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "any-proto.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Rule without protocols field matches any protocol including UDP.
	if v := eng.EvaluateUDP("any-proto.example.com", 80); v != policy.Allow {
		t.Errorf("any-proto.example.com = %v, want Allow (no protocol restriction)", v)
	}
}

// --- UDP relay integration tests ---

func TestUDPRelay_Allow(t *testing.T) {
	// Start a UDP echo server.
	echoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%d]
protocols = ["udp"]
`, echoAddr.IP.String(), echoAddr.Port)))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)
	relay := NewUDPRelay(enginePtr, nil)

	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.Serve(ctx, relayConn, clientConn.LocalAddr())

	// Build SOCKS5 UDP datagram targeting echo server.
	echoIP := echoAddr.IP.To4()
	payload := []byte("test-udp-allow")
	datagram := make([]byte, 0, 10+len(payload))
	datagram = append(datagram, 0x00, 0x00) // RSV
	datagram = append(datagram, 0x00)       // FRAG
	datagram = append(datagram, 0x01)       // ATYP IPv4
	datagram = append(datagram, echoIP...)
	datagram = append(datagram, byte(echoAddr.Port>>8), byte(echoAddr.Port))
	datagram = append(datagram, payload...)

	if _, err := clientConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	// Read response.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	_, _, respPayload, err := ParseSOCKS5UDPHeader(respBuf[:n])
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if string(respPayload) != "test-udp-allow" {
		t.Errorf("response = %q, want test-udp-allow", string(respPayload))
	}
}

func TestUDPRelay_Deny(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "10.0.0.1"
protocols = ["udp"]
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)
	relay := NewUDPRelay(enginePtr, nil)

	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.Serve(ctx, relayConn, clientConn.LocalAddr())

	// Send datagram to denied destination.
	datagram := []byte{
		0x00, 0x00,       // RSV
		0x00,             // FRAG
		0x01,             // ATYP IPv4
		10, 0, 0, 1,     // 10.0.0.1
		0x00, 0x50,       // Port 80
		'b', 'l', 'o', 'c', 'k', 'e', 'd',
	}

	if _, err := clientConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	// Should NOT receive a response (datagram was dropped silently).
	clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	respBuf := make([]byte, 65535)
	_, _, err = clientConn.ReadFrom(respBuf)
	if err == nil {
		t.Error("expected timeout (no response for denied datagram)")
	}
}

func TestUDPRelay_AskTreatedAsDeny(t *testing.T) {
	// Start a UDP echo server to verify that the datagram is NOT relayed.
	echoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%d]
protocols = ["udp"]
`, echoAddr.IP.String(), echoAddr.Port)))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)
	relay := NewUDPRelay(enginePtr, nil)

	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.Serve(ctx, relayConn, clientConn.LocalAddr())

	// Send datagram to ask destination (should be treated as deny).
	echoIP := echoAddr.IP.To4()
	datagram := make([]byte, 0, 14)
	datagram = append(datagram, 0x00, 0x00)
	datagram = append(datagram, 0x00)
	datagram = append(datagram, 0x01)
	datagram = append(datagram, echoIP...)
	datagram = append(datagram, byte(echoAddr.Port>>8), byte(echoAddr.Port))
	datagram = append(datagram, []byte("ask-denied")...)

	if _, err := clientConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	respBuf := make([]byte, 65535)
	_, _, err = clientConn.ReadFrom(respBuf)
	if err == nil {
		t.Error("expected timeout (ask treated as deny for UDP)")
	}
}

func TestUDPRelay_DefaultDeny(t *testing.T) {
	// Start a UDP echo server.
	echoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	// Engine default is "allow", but UDP should still deny
	// because no explicit allow rule matches.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Verify EvaluateUDP returns Deny even when engine default is Allow.
	if v := eng.EvaluateUDP(echoAddr.IP.String(), echoAddr.Port); v != policy.Deny {
		t.Fatalf("EvaluateUDP = %v, want Deny (default-deny for UDP)", v)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)
	relay := NewUDPRelay(enginePtr, nil)

	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.Serve(ctx, relayConn, clientConn.LocalAddr())

	// Send datagram. Even though engine default is allow, UDP
	// should deny because no explicit allow rule matches.
	echoIP := echoAddr.IP.To4()
	datagram := make([]byte, 0, 14)
	datagram = append(datagram, 0x00, 0x00)
	datagram = append(datagram, 0x00)
	datagram = append(datagram, 0x01)
	datagram = append(datagram, echoIP...)
	datagram = append(datagram, byte(echoAddr.Port>>8), byte(echoAddr.Port))
	datagram = append(datagram, []byte("default-denied")...)

	if _, err := clientConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	respBuf := make([]byte, 65535)
	_, _, err = clientConn.ReadFrom(respBuf)
	if err == nil {
		t.Error("expected timeout (UDP default-deny overrides engine default=allow)")
	}
}
