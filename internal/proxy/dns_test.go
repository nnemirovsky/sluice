package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/policy"
)

// buildDNSQuery constructs a minimal DNS query packet for testing.
func buildDNSQuery(id uint16, domain string, qtype uint16) []byte {
	buf := make([]byte, 0, 512)

	// Header: ID, Flags (standard query, RD=1), QDCOUNT=1, rest=0.
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x01, 0x00) // Flags: RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0

	// Question: QNAME + QTYPE + QCLASS.
	buf = appendDNSName(buf, domain)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01) // QCLASS=IN

	return buf
}

// appendDNSName encodes a domain name into DNS wire format.
func appendDNSName(buf []byte, domain string) []byte {
	if domain == "" {
		return append(buf, 0x00)
	}
	labels := splitDNSLabels(domain)
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label
	return buf
}

func splitDNSLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}

// --- ParseDNSQuery tests ---

func TestParseDNSQuery_A(t *testing.T) {
	query := buildDNSQuery(0x1234, "example.com", dnsTypeA)

	id, questions, err := ParseDNSQuery(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 0x1234 {
		t.Errorf("id = 0x%04x, want 0x1234", id)
	}
	if len(questions) != 1 {
		t.Fatalf("questions count = %d, want 1", len(questions))
	}
	if questions[0].Name != "example.com" {
		t.Errorf("name = %q, want example.com", questions[0].Name)
	}
	if questions[0].Type != dnsTypeA {
		t.Errorf("type = %d, want %d (A)", questions[0].Type, dnsTypeA)
	}
	if questions[0].Class != 1 {
		t.Errorf("class = %d, want 1 (IN)", questions[0].Class)
	}
}

func TestParseDNSQuery_AAAA(t *testing.T) {
	query := buildDNSQuery(0xABCD, "ipv6.example.com", dnsTypeAAAA)

	_, questions, err := ParseDNSQuery(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(questions) != 1 {
		t.Fatalf("questions count = %d, want 1", len(questions))
	}
	if questions[0].Name != "ipv6.example.com" {
		t.Errorf("name = %q, want ipv6.example.com", questions[0].Name)
	}
	if questions[0].Type != dnsTypeAAAA {
		t.Errorf("type = %d, want %d (AAAA)", questions[0].Type, dnsTypeAAAA)
	}
}

func TestParseDNSQuery_CNAME(t *testing.T) {
	query := buildDNSQuery(0x5678, "www.example.com", dnsTypeCNAME)

	_, questions, err := ParseDNSQuery(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(questions) != 1 {
		t.Fatalf("questions count = %d, want 1", len(questions))
	}
	if questions[0].Name != "www.example.com" {
		t.Errorf("name = %q, want www.example.com", questions[0].Name)
	}
	if questions[0].Type != dnsTypeCNAME {
		t.Errorf("type = %d, want %d (CNAME)", questions[0].Type, dnsTypeCNAME)
	}
}

func TestParseDNSQuery_TooShort(t *testing.T) {
	_, _, err := ParseDNSQuery([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for short packet")
	}
}

func TestParseDNSQuery_ResponseBit(t *testing.T) {
	query := buildDNSQuery(0x1111, "example.com", dnsTypeA)
	// Set QR bit to 1 (response).
	query[2] |= 0x80
	_, _, err := ParseDNSQuery(query)
	if err == nil {
		t.Error("expected error for response packet (QR=1)")
	}
}

func TestParseDNSQuery_NoQuestions(t *testing.T) {
	query := buildDNSQuery(0x2222, "example.com", dnsTypeA)
	// Set QDCOUNT to 0.
	binary.BigEndian.PutUint16(query[4:6], 0)

	id, questions, err := ParseDNSQuery(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 0x2222 {
		t.Errorf("id = 0x%04x, want 0x2222", id)
	}
	if len(questions) != 0 {
		t.Errorf("questions count = %d, want 0", len(questions))
	}
}

func TestParseDNSQuery_TruncatedQuestion(t *testing.T) {
	query := buildDNSQuery(0x3333, "example.com", dnsTypeA)
	// Truncate in the middle of the question.
	_, _, err := ParseDNSQuery(query[:dnsHeaderLen+5])
	if err == nil {
		t.Error("expected error for truncated question")
	}
}

func TestParseDNSQuery_SingleLabel(t *testing.T) {
	query := buildDNSQuery(0x4444, "localhost", dnsTypeA)

	_, questions, err := ParseDNSQuery(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(questions) != 1 {
		t.Fatalf("questions count = %d, want 1", len(questions))
	}
	if questions[0].Name != "localhost" {
		t.Errorf("name = %q, want localhost", questions[0].Name)
	}
}

func TestParseDNSQuery_DeepSubdomain(t *testing.T) {
	query := buildDNSQuery(0x5555, "a.b.c.d.example.com", dnsTypeA)

	_, questions, err := ParseDNSQuery(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if questions[0].Name != "a.b.c.d.example.com" {
		t.Errorf("name = %q, want a.b.c.d.example.com", questions[0].Name)
	}
}

// --- BuildNXDOMAIN tests ---

func TestBuildNXDOMAIN(t *testing.T) {
	query := buildDNSQuery(0xAAAA, "blocked.example.com", dnsTypeA)

	resp, err := BuildNXDOMAIN(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check ID is preserved.
	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != 0xAAAA {
		t.Errorf("response ID = 0x%04x, want 0xAAAA", respID)
	}

	// Check flags.
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&dnsFlagQR == 0 {
		t.Error("QR bit not set in response")
	}
	rcode := flags & 0x000F
	if rcode != dnsRcodeNXDomain {
		t.Errorf("RCODE = %d, want %d (NXDOMAIN)", rcode, dnsRcodeNXDomain)
	}
	if flags&dnsFlagRA == 0 {
		t.Error("RA bit not set in response")
	}
	// RD should be preserved from query.
	if flags&dnsFlagRD == 0 {
		t.Error("RD bit not preserved from query")
	}

	// QDCOUNT should be preserved (1).
	qdcount := binary.BigEndian.Uint16(resp[4:6])
	if qdcount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdcount)
	}

	// ANCOUNT, NSCOUNT, ARCOUNT should be 0.
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Error("ANCOUNT not zero")
	}
	if binary.BigEndian.Uint16(resp[8:10]) != 0 {
		t.Error("NSCOUNT not zero")
	}
	if binary.BigEndian.Uint16(resp[10:12]) != 0 {
		t.Error("ARCOUNT not zero")
	}

	// Question section should be preserved.
	if len(resp) != len(query) {
		t.Errorf("response length = %d, want %d", len(resp), len(query))
	}
}

func TestBuildNXDOMAIN_TooShort(t *testing.T) {
	_, err := BuildNXDOMAIN([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for short query")
	}
}

func TestBuildNXDOMAIN_NoRD(t *testing.T) {
	query := buildDNSQuery(0xBBBB, "test.com", dnsTypeA)
	// Clear the RD bit.
	query[2] &= ^byte(0x01)

	resp, err := BuildNXDOMAIN(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	// RD should be 0 since it was 0 in the query.
	if flags&dnsFlagRD != 0 {
		t.Error("RD bit should not be set when not in query")
	}
}

// --- DNSTypeName tests ---

func TestDNSTypeName(t *testing.T) {
	tests := []struct {
		qtype uint16
		want  string
	}{
		{dnsTypeA, "A"},
		{dnsTypeAAAA, "AAAA"},
		{dnsTypeCNAME, "CNAME"},
		{99, "TYPE99"},
	}
	for _, tt := range tests {
		got := DNSTypeName(tt.qtype)
		if got != tt.want {
			t.Errorf("DNSTypeName(%d) = %q, want %q", tt.qtype, got, tt.want)
		}
	}
}

// --- DNS policy evaluation tests ---

func TestDNSPolicyEvaluation_AllowDomain(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "dns.google"
ports = [53]
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateWithProtocol("dns.google", 53, "dns"); v != policy.Allow {
		t.Errorf("EvaluateWithProtocol(dns.google, 53, dns) = %v, want Allow", v)
	}
}

func TestDNSPolicyEvaluation_DenyDomain(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "evil.com"
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateWithProtocol("evil.com", 53, "dns"); v != policy.Deny {
		t.Errorf("EvaluateWithProtocol(evil.com, 53, dns) = %v, want Deny", v)
	}
}

func TestDNSPolicyEvaluation_GlobMatch(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "*.example.com"
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateWithProtocol("api.example.com", 53, "dns"); v != policy.Allow {
		t.Errorf("api.example.com = %v, want Allow", v)
	}

	if v := eng.EvaluateWithProtocol("evil.com", 53, "dns"); v != policy.Deny {
		t.Errorf("evil.com = %v, want Deny", v)
	}
}

func TestDNSPolicyEvaluation_DefaultDeny(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateWithProtocol("anything.com", 53, "dns"); v != policy.Deny {
		t.Errorf("anything.com = %v, want Deny", v)
	}
}

func TestDNSPolicyEvaluation_DefaultAllow(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	if v := eng.EvaluateWithProtocol("anything.com", 53, "dns"); v != policy.Allow {
		t.Errorf("anything.com = %v, want Allow", v)
	}
}

// --- DNS interceptor integration tests ---

func TestDNSInterceptor_AllowedDomain(t *testing.T) {
	// Start a mock DNS server that echoes a simple response.
	mockDNS, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mockDNS.Close()
	mockAddr := mockDNS.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := mockDNS.ReadFrom(buf)
			if err != nil {
				return
			}
			// Build a minimal response: copy query, set QR bit, add ANCOUNT=0.
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80 // Set QR bit
			mockDNS.WriteTo(resp, addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "allowed.example.com"
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)

	interceptor := NewDNSInterceptor(enginePtr, nil, mockAddr.String())

	query := buildDNSQuery(0x1111, "allowed.example.com", dnsTypeA)
	resp, err := interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	// Response should be from the mock server (QR bit set, no NXDOMAIN).
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&dnsFlagQR == 0 {
		t.Error("response should have QR bit set")
	}
	rcode := flags & 0x000F
	if rcode != 0 {
		t.Errorf("RCODE = %d, want 0 (NOERROR)", rcode)
	}
}

func TestDNSInterceptor_DeniedDomain(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)

	// Resolver address does not matter since the query should be denied.
	interceptor := NewDNSInterceptor(enginePtr, nil, "127.0.0.1:1")

	query := buildDNSQuery(0x2222, "denied.example.com", dnsTypeA)
	resp, err := interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	// Response should be NXDOMAIN.
	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != 0x2222 {
		t.Errorf("response ID = 0x%04x, want 0x2222", respID)
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	rcode := flags & 0x000F
	if rcode != dnsRcodeNXDomain {
		t.Errorf("RCODE = %d, want %d (NXDOMAIN)", rcode, dnsRcodeNXDomain)
	}
}

func TestDNSInterceptor_MixedPolicy(t *testing.T) {
	// Start mock DNS server.
	mockDNS, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mockDNS.Close()
	mockAddr := mockDNS.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := mockDNS.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80
			mockDNS.WriteTo(resp, addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "*.google.com"
protocols = ["dns"]

[[deny]]
destination = "evil.google.com"
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)
	interceptor := NewDNSInterceptor(enginePtr, nil, mockAddr.String())

	// Allowed subdomain.
	query := buildDNSQuery(0x3333, "api.google.com", dnsTypeA)
	resp, err := interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery(api.google.com): %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x000F != 0 {
		t.Errorf("api.google.com RCODE = %d, want 0", flags&0x000F)
	}

	// Denied subdomain (explicit deny overrides glob allow).
	query = buildDNSQuery(0x4444, "evil.google.com", dnsTypeA)
	resp, err = interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery(evil.google.com): %v", err)
	}
	flags = binary.BigEndian.Uint16(resp[2:4])
	rcode := flags & 0x000F
	if rcode != dnsRcodeNXDomain {
		t.Errorf("evil.google.com RCODE = %d, want %d (NXDOMAIN)", rcode, dnsRcodeNXDomain)
	}

	// Unmatched domain (default deny).
	query = buildDNSQuery(0x5555, "other.com", dnsTypeA)
	resp, err = interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery(other.com): %v", err)
	}
	flags = binary.BigEndian.Uint16(resp[2:4])
	rcode = flags & 0x000F
	if rcode != dnsRcodeNXDomain {
		t.Errorf("other.com RCODE = %d, want %d (NXDOMAIN)", rcode, dnsRcodeNXDomain)
	}
}

func TestDNSInterceptor_AAAA(t *testing.T) {
	// Start mock DNS server.
	mockDNS, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mockDNS.Close()
	mockAddr := mockDNS.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := mockDNS.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80
			mockDNS.WriteTo(resp, addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)
	interceptor := NewDNSInterceptor(enginePtr, nil, mockAddr.String())

	// AAAA query should be forwarded with default allow.
	query := buildDNSQuery(0x6666, "ipv6.test.com", dnsTypeAAAA)
	resp, err := interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery AAAA: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x000F != 0 {
		t.Errorf("AAAA RCODE = %d, want 0", flags&0x000F)
	}
}

func TestNewDNSInterceptor_DefaultResolver(t *testing.T) {
	enginePtr := new(atomic.Pointer[policy.Engine])
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	enginePtr.Store(eng)

	d := NewDNSInterceptor(enginePtr, nil, "")
	if d.resolver != "8.8.8.8:53" {
		t.Errorf("default resolver = %q, want 8.8.8.8:53", d.resolver)
	}
}

func TestNewDNSInterceptor_ResolverWithoutPort(t *testing.T) {
	enginePtr := new(atomic.Pointer[policy.Engine])
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	enginePtr.Store(eng)

	d := NewDNSInterceptor(enginePtr, nil, "1.1.1.1")
	if d.resolver != "1.1.1.1:53" {
		t.Errorf("resolver = %q, want 1.1.1.1:53", d.resolver)
	}
}

func TestNewDNSInterceptor_ResolverWithPort(t *testing.T) {
	enginePtr := new(atomic.Pointer[policy.Engine])
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	enginePtr.Store(eng)

	d := NewDNSInterceptor(enginePtr, nil, "1.1.1.1:5353")
	if d.resolver != "1.1.1.1:5353" {
		t.Errorf("resolver = %q, want 1.1.1.1:5353", d.resolver)
	}
}

// --- DNS NXDOMAIN response generation tests ---

func TestBuildNXDOMAIN_PreservesQuestionSection(t *testing.T) {
	query := buildDNSQuery(0xDDDD, "test.example.com", dnsTypeA)

	resp, err := BuildNXDOMAIN(query)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the response and verify the question section.
	// Skip the header, parse the question.
	_, questions, parseErr := parseResponseQuestions(resp)
	if parseErr != nil {
		t.Fatalf("parse response: %v", parseErr)
	}
	if len(questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(questions))
	}
	if questions[0].Name != "test.example.com" {
		t.Errorf("question name = %q, want test.example.com", questions[0].Name)
	}
}

// parseResponseQuestions is a test helper that parses questions from a DNS
// response (ignoring the QR bit check).
func parseResponseQuestions(data []byte) (id uint16, questions []DNSQuestion, err error) {
	if len(data) < dnsHeaderLen {
		return 0, nil, fmt.Errorf("too short")
	}
	id = binary.BigEndian.Uint16(data[0:2])
	qdcount := binary.BigEndian.Uint16(data[4:6])
	offset := dnsHeaderLen
	for i := 0; i < int(qdcount); i++ {
		name, newOffset, nameErr := parseDNSName(data, offset)
		if nameErr != nil {
			return 0, nil, nameErr
		}
		offset = newOffset
		if offset+4 > len(data) {
			return 0, nil, fmt.Errorf("truncated")
		}
		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		questions = append(questions, DNSQuestion{Name: name, Type: qtype, Class: qclass})
	}
	return id, questions, nil
}

func TestDNSInterceptor_RejectsMultiQuestionQueries(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)

	interceptor := NewDNSInterceptor(enginePtr, nil, "8.8.8.8:53")

	// Build a query with 2 questions by appending a second question.
	query := buildDNSQuery(0xAAAA, "allowed.example.com", dnsTypeA)
	// Append second question for evil.example.com.
	var second []byte
	second = appendDNSName(second, "evil.example.com")
	second = append(second, 0x00, 0x01) // QTYPE A
	second = append(second, 0x00, 0x01) // QCLASS IN
	query = append(query, second...)
	// Set QDCOUNT to 2.
	binary.BigEndian.PutUint16(query[4:6], 2)

	resp, err := interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	// Should return NXDOMAIN for non-standard queries.
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F
	if rcode != 3 {
		t.Errorf("RCODE = %d, want 3 (NXDOMAIN) for multi-question query", rcode)
	}
}

func TestDNSInterceptor_RejectsZeroQuestionQueries(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)

	interceptor := NewDNSInterceptor(enginePtr, nil, "8.8.8.8:53")

	query := buildDNSQuery(0xBBBB, "example.com", dnsTypeA)
	// Set QDCOUNT to 0.
	binary.BigEndian.PutUint16(query[4:6], 0)

	resp, err := interceptor.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}

	// Should return NXDOMAIN for zero-question queries.
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F
	if rcode != 3 {
		t.Errorf("RCODE = %d, want 3 (NXDOMAIN) for zero-question query", rcode)
	}
}

// --- End-to-end: DNS interceptor with real UDP relay pattern ---

func TestDNSInterceptor_HandleQuery_ForwardTimeout(t *testing.T) {
	// Verify that HandleQuery returns an error when the resolver is unreachable.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	enginePtr := new(atomic.Pointer[policy.Engine])
	enginePtr.Store(eng)

	// Use a resolver address that will refuse connections.
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.LocalAddr().String()
	ln.Close() // Close immediately so nothing is listening.

	// Give the OS a moment to release the port.
	time.Sleep(10 * time.Millisecond)

	interceptor := NewDNSInterceptor(enginePtr, nil, addr)
	query := buildDNSQuery(0x7777, "example.com", dnsTypeA)
	_, handleErr := interceptor.HandleQuery(query)
	if handleErr == nil {
		t.Error("expected error when resolver is unreachable")
	}
}
