// Package proxy implements a SOCKS5 proxy server with policy enforcement,
// credential injection, and protocol-specific handlers for HTTPS, SSH,
// IMAP, and SMTP.
package proxy

import (
	"encoding/binary"
	"net/http"
	"strings"
)

// Protocol represents the detected application-layer protocol for a connection.
type Protocol string

const (
	// ProtoHTTP indicates plain HTTP traffic (ports 80, 8080).
	ProtoHTTP Protocol = "http"
	// ProtoHTTPS indicates TLS-encrypted HTTP traffic (ports 443, 8443).
	ProtoHTTPS Protocol = "https"
	// ProtoSSH indicates SSH traffic (port 22).
	ProtoSSH Protocol = "ssh"
	// ProtoIMAP indicates IMAP mail retrieval traffic (ports 143, 993).
	ProtoIMAP Protocol = "imap"
	// ProtoSMTP indicates SMTP mail submission traffic (ports 25, 587, 465).
	ProtoSMTP Protocol = "smtp"
	// ProtoWS indicates plaintext WebSocket traffic (HTTP Upgrade).
	ProtoWS Protocol = "ws"
	// ProtoWSS indicates TLS-encrypted WebSocket traffic (HTTPS Upgrade).
	ProtoWSS Protocol = "wss"
	// ProtoGRPC indicates gRPC traffic (HTTP/2 with application/grpc content type).
	ProtoGRPC Protocol = "grpc"
	// ProtoDNS indicates DNS query traffic (UDP port 53).
	ProtoDNS Protocol = "dns"
	// ProtoQUIC indicates QUIC/HTTP3 traffic (UDP with QUIC long header).
	ProtoQUIC Protocol = "quic"
	// ProtoAPNS indicates Apple Push Notification Service traffic (port 5223).
	ProtoAPNS Protocol = "apns"
	// ProtoGeneric indicates unrecognized traffic on a non-standard port.
	ProtoGeneric Protocol = "generic"
)

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
