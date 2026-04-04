package proxy

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
)

// DNSInterceptor parses DNS queries on UDP port 53, evaluates the queried
// domain against the policy engine, and either forwards allowed queries to
// an upstream resolver or returns NXDOMAIN for denied domains. All queries
// are logged to the audit log.
type DNSInterceptor struct {
	engine   *atomic.Pointer[policy.Engine]
	audit    *audit.FileLogger
	resolver string // upstream DNS resolver address (host:port)
}

// NewDNSInterceptor creates a DNS interceptor that forwards allowed queries
// to the given upstream resolver. If resolver is empty, "8.8.8.8:53" is used.
func NewDNSInterceptor(engine *atomic.Pointer[policy.Engine], audit *audit.FileLogger, resolver string) *DNSInterceptor {
	if resolver == "" {
		resolver = "8.8.8.8:53"
	}
	// Ensure the resolver has a port.
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}
	return &DNSInterceptor{
		engine:   engine,
		audit:    audit,
		resolver: resolver,
	}
}

// dnsTimeout bounds how long a single upstream DNS query can block.
const dnsQueryTimeout = 5 * time.Second

// DNS header constants.
const (
	dnsHeaderLen = 12
	// DNS RCODE values.
	dnsRcodeNXDomain = 3
	// DNS flags.
	dnsFlagQR = 0x8000 // Query/Response bit
	dnsFlagRD = 0x0100 // Recursion Desired
	dnsFlagRA = 0x0080 // Recursion Available
)

// DNS query types.
const (
	dnsTypeA     uint16 = 1
	dnsTypeAAAA  uint16 = 28
	dnsTypeCNAME uint16 = 5
)

// DNSQuestion represents a parsed DNS question entry.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// ParseDNSQuery parses a DNS query packet and extracts the questions.
// Only the header and Question section are parsed. The answer, authority,
// and additional sections are ignored.
func ParseDNSQuery(data []byte) (id uint16, questions []DNSQuestion, err error) {
	if len(data) < dnsHeaderLen {
		return 0, nil, fmt.Errorf("dns packet too short: %d bytes", len(data))
	}

	id = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])

	// Verify this is a query (QR bit = 0).
	if flags&dnsFlagQR != 0 {
		return 0, nil, fmt.Errorf("not a dns query (QR=1)")
	}

	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount == 0 {
		return id, nil, nil
	}

	offset := dnsHeaderLen
	questions = make([]DNSQuestion, 0, qdcount)
	for i := 0; i < int(qdcount); i++ {
		name, newOffset, nameErr := parseDNSName(data, offset)
		if nameErr != nil {
			return 0, nil, fmt.Errorf("parse question %d name: %w", i, nameErr)
		}
		offset = newOffset

		if offset+4 > len(data) {
			return 0, nil, fmt.Errorf("question %d: truncated QTYPE/QCLASS", i)
		}
		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		questions = append(questions, DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}

	return id, questions, nil
}

// parseDNSName parses a DNS domain name from wire format starting at offset.
// Handles both length-prefixed labels and compression pointers (RFC 1035 s4.1.4).
// Returns the decoded name and the new offset past the name.
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)
	jumped := false
	returnOffset := 0

	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("name extends past packet end at offset %d", offset)
		}

		// Check for pointer (compression).
		if data[offset]&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated compression pointer at offset %d", offset)
			}
			if !jumped {
				returnOffset = offset + 2
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			if visited[ptr] {
				return "", 0, fmt.Errorf("compression pointer loop at offset %d", offset)
			}
			visited[ptr] = true
			offset = ptr
			jumped = true
			continue
		}

		length := int(data[offset])
		if length == 0 {
			if !jumped {
				returnOffset = offset + 1
			}
			break
		}

		offset++
		if offset+length > len(data) {
			return "", 0, fmt.Errorf("label extends past packet end at offset %d", offset)
		}

		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	return strings.Join(labels, "."), returnOffset, nil
}

// BuildNXDOMAIN constructs a minimal DNS NXDOMAIN response for the given
// query packet. The response echoes the query ID and question section,
// truncated after the last question to avoid trailing bytes from the
// authority/additional sections of the original query.
func BuildNXDOMAIN(queryPacket []byte) ([]byte, error) {
	if len(queryPacket) < dnsHeaderLen {
		return nil, fmt.Errorf("query too short: %d bytes", len(queryPacket))
	}

	// Walk past the question section to find the truncation point.
	qdcount := binary.BigEndian.Uint16(queryPacket[4:6])
	offset := dnsHeaderLen
	for i := 0; i < int(qdcount); i++ {
		_, newOffset, err := parseDNSName(queryPacket, offset)
		if err != nil {
			return nil, fmt.Errorf("parse question %d name: %w", i, err)
		}
		offset = newOffset
		if offset+4 > len(queryPacket) {
			return nil, fmt.Errorf("question %d: truncated QTYPE/QCLASS", i)
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Copy only header + question section (no trailing bytes).
	resp := make([]byte, offset)
	copy(resp, queryPacket[:offset])

	// Set response flags: QR=1, RD copied from query, RA=1, RCODE=NXDOMAIN.
	origFlags := binary.BigEndian.Uint16(queryPacket[2:4])
	newFlags := dnsFlagQR | (origFlags & dnsFlagRD) | dnsFlagRA | dnsRcodeNXDomain
	binary.BigEndian.PutUint16(resp[2:4], newFlags)

	// Zero out answer, authority, and additional counts.
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)   // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0)  // ARCOUNT

	return resp, nil
}

// HandleQuery processes a single DNS query. It parses the query, evaluates
// policy for the queried domain, and returns either the upstream response
// (allowed) or an NXDOMAIN (denied). The returned byte slice is the DNS
// response to send back to the client.
func (d *DNSInterceptor) HandleQuery(query []byte) ([]byte, error) {
	_, questions, err := ParseDNSQuery(query)
	if err != nil {
		return nil, fmt.Errorf("parse dns query: %w", err)
	}

	if len(questions) != 1 {
		// Standard DNS queries have exactly one question. Reject anything
		// else to prevent policy bypass via crafted multi-question packets
		// or empty queries.
		return BuildNXDOMAIN(query)
	}

	domain := questions[0].Name
	verdict := d.evaluate(domain)

	if d.audit != nil {
		verdictStr := "allow"
		if verdict != policy.Allow {
			verdictStr = "deny"
		}
		if logErr := d.audit.Log(audit.Event{
			Destination: domain,
			Port:        53,
			Protocol:    "dns",
			Verdict:     verdictStr,
			Reason:      fmt.Sprintf("dns query type=%d", questions[0].Type),
		}); logErr != nil {
			log.Printf("audit log write error: %v", logErr)
		}
	}

	if verdict != policy.Allow {
		return BuildNXDOMAIN(query)
	}

	return d.forwardToResolver(query)
}

// evaluate checks the DNS domain against the policy engine. Uses EvaluateUDP
// with protocol override "dns" so dns-specific rules match.
func (d *DNSInterceptor) evaluate(domain string) policy.Verdict {
	eng := d.engine.Load()
	// Use EvaluateWithProtocol with "dns" so protocol-scoped rules match.
	// DNS follows the same deny-then-allow-then-default semantics as
	// regular evaluation, not the UDP default-deny semantics, because
	// DNS queries are a known protocol with meaningful domain-level policy.
	v := eng.EvaluateWithProtocol(domain, 53, "dns")
	return v
}

// forwardToResolver sends the query to the upstream DNS resolver and returns
// the response.
func (d *DNSInterceptor) forwardToResolver(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", d.resolver, dnsQueryTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial dns resolver %s: %w", d.resolver, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(dnsQueryTimeout))

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write to dns resolver: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from dns resolver: %w", err)
	}

	return buf[:n], nil
}

// DNSTypeName returns a human-readable name for common DNS query types.
func DNSTypeName(qtype uint16) string {
	switch qtype {
	case dnsTypeA:
		return "A"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypeCNAME:
		return "CNAME"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}
