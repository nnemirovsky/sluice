// Package proxy implements a SOCKS5 proxy server with policy enforcement,
// credential injection, and protocol-specific handlers for HTTPS, SSH,
// IMAP, and SMTP.
package proxy

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
	default:
		return ProtoGeneric
	}
}
