package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
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

// Serve runs the UDP relay loop on conn. It reads SOCKS5 UDP datagrams,
// evaluates each against the policy engine, and relays allowed traffic.
// Blocks until ctx is cancelled. The clientAddr is the SOCKS5 client that
// owns this ASSOCIATE session (used as the destination for relay responses).
func (r *UDPRelay) Serve(ctx context.Context, conn net.PacketConn, clientAddr net.Addr) error {
	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	defer func() {
		mu.Lock()
		for _, s := range sessions {
			s.upstream.Close()
		}
		mu.Unlock()
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, srcAddr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				r.cleanupExpired(&mu, sessions)
				continue
			}
			return fmt.Errorf("read from relay: %w", readErr)
		}

		dest, port, payload, parseErr := ParseSOCKS5UDPHeader(buf[:n])
		if parseErr != nil {
			log.Printf("[UDP] invalid datagram from %s: %v", srcAddr, parseErr)
			continue
		}

		verdict := r.evaluateUDP(dest, port)
		if verdict != policy.Allow {
			if r.audit != nil {
				if logErr := r.audit.Log(audit.Event{
					Destination: dest,
					Port:        port,
					Protocol:    "udp",
					Verdict:     "deny",
					Reason:      "udp denied",
				}); logErr != nil {
					log.Printf("audit log write error: %v", logErr)
				}
			}
			continue
		}

		dstAddr, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(dest, strconv.Itoa(port)))
		if resolveErr != nil {
			log.Printf("[UDP] resolve %s:%d: %v", dest, port, resolveErr)
			continue
		}

		sessionKey := dstAddr.String()

		mu.Lock()
		sess, exists := sessions[sessionKey]
		if !exists {
			upstream, listenErr := net.ListenPacket("udp", ":0")
			if listenErr != nil {
				mu.Unlock()
				log.Printf("[UDP] create upstream for %s: %v", sessionKey, listenErr)
				continue
			}
			sess = &udpSession{upstream: upstream, lastSeen: time.Now()}
			sessions[sessionKey] = sess
			go r.relayResponses(ctx, upstream, conn, srcAddr)
		} else {
			sess.lastSeen = time.Now()
		}
		mu.Unlock()

		if _, writeErr := sess.upstream.WriteTo(payload, dstAddr); writeErr != nil {
			log.Printf("[UDP] write to %s: %v", sessionKey, writeErr)
		}

		if r.audit != nil {
			if logErr := r.audit.Log(audit.Event{
				Destination: dest,
				Port:        port,
				Protocol:    "udp",
				Verdict:     "allow",
			}); logErr != nil {
				log.Printf("audit log write error: %v", logErr)
			}
		}
	}
}

// cleanupExpired removes upstream sessions that have been idle longer than
// udpSessionTimeout.
func (r *UDPRelay) cleanupExpired(mu *sync.Mutex, sessions map[string]*udpSession) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	for key, s := range sessions {
		if now.Sub(s.lastSeen) > udpSessionTimeout {
			s.upstream.Close()
			delete(sessions, key)
		}
	}
}

// relayResponses reads response datagrams from upstream and wraps them in
// SOCKS5 UDP headers before sending to the client.
func (r *UDPRelay) relayResponses(ctx context.Context, upstream, relay net.PacketConn, clientAddr net.Addr) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		upstream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, srcAddr, err := upstream.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		udpAddr, ok := srcAddr.(*net.UDPAddr)
		if !ok {
			continue
		}
		resp := BuildSOCKS5UDPResponse(udpAddr.IP, udpAddr.Port, buf[:n])
		if _, writeErr := relay.WriteTo(resp, clientAddr); writeErr != nil {
			log.Printf("[UDP] write response to client: %v", writeErr)
		}
	}
}
