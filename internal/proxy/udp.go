package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
)

// udpSessionTimeout is how long an upstream UDP mapping lives without activity.
const udpSessionTimeout = 2 * time.Minute

// UDPRelay handles SOCKS5 UDP ASSOCIATE sessions with per-datagram policy
// enforcement. Each datagram is evaluated against the policy engine before
// being relayed. UDP uses deny-unless-explicitly-allowed semantics: only
// destinations matched by an explicit allow rule are relayed. Ask verdicts
// are treated as deny because per-packet approval is impractical.
type UDPRelay struct {
	engine *atomic.Pointer[policy.Engine]
	audit  *audit.FileLogger
}

// NewUDPRelay creates a relay for SOCKS5 UDP ASSOCIATE sessions.
func NewUDPRelay(engine *atomic.Pointer[policy.Engine], audit *audit.FileLogger) *UDPRelay {
	return &UDPRelay{engine: engine, audit: audit}
}

// udpSession tracks an upstream UDP connection for a specific destination.
type udpSession struct {
	upstream net.PacketConn
	lastSeen time.Time
}

// ParseSOCKS5UDPHeader parses a SOCKS5 UDP request header per RFC 1928 s7.
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
func ParseSOCKS5UDPHeader(data []byte) (addr string, port int, payload []byte, err error) {
	if len(data) < 4 {
		return "", 0, nil, fmt.Errorf("datagram too short: %d bytes", len(data))
	}
	frag := data[2]
	if frag != 0 {
		return "", 0, nil, fmt.Errorf("fragmented datagrams not supported (frag=%d)", frag)
	}
	atyp := data[3]
	switch atyp {
	case 0x01: // IPv4
		if len(data) < 10 {
			return "", 0, nil, fmt.Errorf("datagram too short for IPv4: %d bytes", len(data))
		}
		addr = net.IP(data[4:8]).String()
		port = int(binary.BigEndian.Uint16(data[8:10]))
		payload = data[10:]
	case 0x03: // Domain name
		if len(data) < 5 {
			return "", 0, nil, fmt.Errorf("datagram too short for domain: %d bytes", len(data))
		}
		nameLen := int(data[4])
		end := 5 + nameLen + 2
		if len(data) < end {
			return "", 0, nil, fmt.Errorf("datagram too short for domain name: need %d, got %d", end, len(data))
		}
		addr = string(data[5 : 5+nameLen])
		port = int(binary.BigEndian.Uint16(data[5+nameLen : end]))
		payload = data[end:]
	case 0x04: // IPv6
		if len(data) < 22 {
			return "", 0, nil, fmt.Errorf("datagram too short for IPv6: %d bytes", len(data))
		}
		addr = net.IP(data[4:20]).String()
		port = int(binary.BigEndian.Uint16(data[20:22]))
		payload = data[22:]
	default:
		return "", 0, nil, fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}
	return addr, port, payload, nil
}

// BuildSOCKS5UDPResponse wraps a payload in a SOCKS5 UDP response header.
func BuildSOCKS5UDPResponse(srcAddr net.IP, srcPort int, payload []byte) []byte {
	if ip4 := srcAddr.To4(); ip4 != nil {
		buf := make([]byte, 0, 10+len(payload))
		buf = append(buf, 0x00, 0x00) // RSV
		buf = append(buf, 0x00)       // FRAG
		buf = append(buf, 0x01)       // ATYP IPv4
		buf = append(buf, ip4...)
		buf = append(buf, byte(srcPort>>8), byte(srcPort))
		buf = append(buf, payload...)
		return buf
	}
	buf := make([]byte, 0, 22+len(payload))
	buf = append(buf, 0x00, 0x00) // RSV
	buf = append(buf, 0x00)       // FRAG
	buf = append(buf, 0x04)       // ATYP IPv6
	buf = append(buf, srcAddr.To16()...)
	buf = append(buf, byte(srcPort>>8), byte(srcPort))
	buf = append(buf, payload...)
	return buf
}

// evaluateUDP checks policy for a UDP datagram using deny-unless-explicitly-allowed
// semantics via the engine's EvaluateUDP method.
func (r *UDPRelay) evaluateUDP(dest string, port int) policy.Verdict {
	return r.engine.Load().EvaluateUDP(dest, port)
}
