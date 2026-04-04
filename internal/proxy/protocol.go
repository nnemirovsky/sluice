// Package proxy implements a SOCKS5 proxy server with policy enforcement,
// credential injection, and protocol-specific handlers for HTTPS, SSH,
// IMAP, and SMTP.
package proxy

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
)

// Protocol represents the detected application-layer protocol for a connection.
// It is an integer enum consistent with other enums in the codebase (Verdict,
// ChannelType). Use String() for display names and ParseProtocol() to convert
// from string representations.
type Protocol int

const (
	// ProtoGeneric indicates unrecognized traffic on a non-standard port.
	ProtoGeneric Protocol = 0
	// ProtoHTTP indicates plain HTTP traffic (ports 80, 8080).
	ProtoHTTP Protocol = 1
	// ProtoHTTPS indicates TLS-encrypted HTTP traffic (ports 443, 8443).
	ProtoHTTPS Protocol = 2
	// ProtoSSH indicates SSH traffic (port 22).
	ProtoSSH Protocol = 3
	// ProtoIMAP indicates IMAP mail retrieval traffic (ports 143, 993).
	ProtoIMAP Protocol = 4
	// ProtoSMTP indicates SMTP mail submission traffic (ports 25, 587, 465).
	ProtoSMTP Protocol = 5
	// ProtoWS indicates plaintext WebSocket traffic (HTTP Upgrade).
	ProtoWS Protocol = 6
	// ProtoWSS indicates TLS-encrypted WebSocket traffic (HTTPS Upgrade).
	ProtoWSS Protocol = 7
	// ProtoGRPC indicates gRPC traffic (HTTP/2 with application/grpc content type).
	ProtoGRPC Protocol = 8
	// ProtoDNS indicates DNS query traffic (UDP port 53).
	ProtoDNS Protocol = 9
	// ProtoQUIC indicates QUIC/HTTP3 traffic (UDP with QUIC long header).
	ProtoQUIC Protocol = 10
	// ProtoAPNS indicates Apple Push Notification Service traffic (port 5223).
	ProtoAPNS Protocol = 11
)

// String returns the display name for the protocol (e.g. "http", "https").
func (p Protocol) String() string {
	switch p {
	case ProtoHTTP:
		return "http"
	case ProtoHTTPS:
		return "https"
	case ProtoSSH:
		return "ssh"
	case ProtoIMAP:
		return "imap"
	case ProtoSMTP:
		return "smtp"
	case ProtoWS:
		return "ws"
	case ProtoWSS:
		return "wss"
	case ProtoGRPC:
		return "grpc"
	case ProtoDNS:
		return "dns"
	case ProtoQUIC:
		return "quic"
	case ProtoAPNS:
		return "apns"
	case ProtoGeneric:
		return "generic"
	default:
		return "unknown"
	}
}

// protocolNames maps string names to Protocol values for parsing.
var protocolNames = map[string]Protocol{
	"generic": ProtoGeneric,
	"http":    ProtoHTTP,
	"https":   ProtoHTTPS,
	"ssh":     ProtoSSH,
	"imap":    ProtoIMAP,
	"smtp":    ProtoSMTP,
	"ws":      ProtoWS,
	"wss":     ProtoWSS,
	"grpc":    ProtoGRPC,
	"dns":     ProtoDNS,
	"quic":    ProtoQUIC,
	"apns":    ProtoAPNS,
}

// ParseProtocol converts a string protocol name to a Protocol value.
// Returns an error for unknown protocol names.
func ParseProtocol(s string) (Protocol, error) {
	if p, ok := protocolNames[strings.ToLower(s)]; ok {
		return p, nil
	}
	return ProtoGeneric, fmt.Errorf("unknown protocol %q", s)
}

// DetectProtocol infers the application-layer protocol from the destination port.
// This is a port-based heuristic used before any bytes are read from the connection.
func DetectProtocol(port int) Protocol {
	switch port {
	case 80, 8080:
		return ProtoHTTP
	case 443, 8443:
		return ProtoHTTPS
	case 22:
		return ProtoSSH
	case 143, 993:
		return ProtoIMAP
	case 25, 587, 465:
		return ProtoSMTP
	case 5223:
		return ProtoAPNS
	default:
		return ProtoGeneric
	}
}

// DetectUDPProtocol infers the application-layer protocol for UDP traffic
// based on the destination port.
func DetectUDPProtocol(port int) Protocol {
	switch port {
	case 53:
		return ProtoDNS
	case 443, 8443:
		return ProtoQUIC
	default:
		return ProtoGeneric
	}
}

// DetectProtocolFromHeaders refines the protocol detection using HTTP request
// headers. Call this after the initial port-based detection to identify
// WebSocket upgrades and gRPC requests. The isTLS parameter indicates whether
// the connection is over TLS (determines ProtoWS vs ProtoWSS).
func DetectProtocolFromHeaders(headers http.Header, isTLS bool) Protocol {
	// WebSocket: Connection: Upgrade + Upgrade: websocket
	if strings.EqualFold(headers.Get("Upgrade"), "websocket") {
		conn := headers.Get("Connection")
		for _, v := range strings.Split(conn, ",") {
			if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
				if isTLS {
					return ProtoWSS
				}
				return ProtoWS
			}
		}
	}

	// gRPC: Content-Type starts with application/grpc
	ct := headers.Get("Content-Type")
	if strings.HasPrefix(ct, "application/grpc") {
		return ProtoGRPC
	}

	return ProtoGeneric
}

// httpMethods lists the ASCII prefixes that identify HTTP request methods.
// Each entry is at least 3 bytes so a 4-byte peek can distinguish all methods.
var httpMethods = []string{
	"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "CONN",
}

// DetectFromClientBytes examines the first bytes sent by the client after TCP
// connect to determine the application-layer protocol. Returns ProtoGeneric
// when the bytes do not match any known signature, leaving the port-based
// guess in effect.
func DetectFromClientBytes(data []byte) Protocol {
	if len(data) == 0 {
		return ProtoGeneric
	}

	// TLS ClientHello: ContentType=Handshake (0x16), then 2-byte version.
	if len(data) >= 3 && data[0] == 0x16 {
		version := uint16(data[1])<<8 | uint16(data[2])
		if version >= 0x0301 && version <= 0x0303 {
			return ProtoHTTPS
		}
	}

	// SSH version banner: starts with "SSH-".
	if len(data) >= 4 && string(data[:4]) == "SSH-" {
		return ProtoSSH
	}

	// HTTP method verb: GET, POST, PUT, HEAD, DELETE, PATCH, OPTIONS, CONNECT.
	if len(data) >= 4 {
		prefix := string(data[:4])
		for _, m := range httpMethods {
			if prefix == m {
				return ProtoHTTP
			}
		}
	}

	return ProtoGeneric
}

// IsQUICPacket checks whether a UDP payload is a QUIC Initial packet by
// verifying the long header form bit, fixed bit, and version field.
// Supports QUIC v1 (RFC 9000) and QUIC v2 (RFC 9369).
func IsQUICPacket(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// Long header: first two bits must be 1 (form bit + fixed bit).
	if data[0]&0xC0 != 0xC0 {
		return false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	// QUIC v1 = 0x00000001, QUIC v2 = 0x6b3343cf
	return version == 0x00000001 || version == 0x6b3343cf
}
