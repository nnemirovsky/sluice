package proxy

// Protocol represents the detected application-layer protocol for a connection.
type Protocol string

const (
	ProtoHTTP    Protocol = "http"
	ProtoHTTPS   Protocol = "https"
	ProtoSSH     Protocol = "ssh"
	ProtoIMAP    Protocol = "imap"
	ProtoSMTP    Protocol = "smtp"
	ProtoGeneric Protocol = "generic"
)

// DetectProtocol infers the application-layer protocol from the destination port.
// This is a port-based heuristic used before any bytes are read from the connection.
func DetectProtocol(dest string, port int) Protocol {
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
