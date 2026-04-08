package proxy

import "testing"

func TestExtractSNI(t *testing.T) {
	// Real TLS ClientHello captured from curl to example.com.
	// Trimmed to include only the SNI extension.
	clientHello := buildClientHello("example.com")

	sni := extractSNI(clientHello)
	if sni != "example.com" {
		t.Errorf("expected example.com, got %q", sni)
	}
}

func TestExtractSNI_NoSNI(t *testing.T) {
	sni := extractSNI([]byte{0x16, 0x03, 0x01})
	if sni != "" {
		t.Errorf("expected empty, got %q", sni)
	}
}

func TestExtractSNI_NotTLS(t *testing.T) {
	sni := extractSNI([]byte("GET / HTTP/1.1\r\n"))
	if sni != "" {
		t.Errorf("expected empty, got %q", sni)
	}
}

// buildClientHello constructs a minimal TLS 1.2 ClientHello with SNI.
func buildClientHello(hostname string) []byte {
	// SNI extension data: list length (2) + type (1) + name length (2) + name
	nameLen := len(hostname)
	sniListLen := 1 + 2 + nameLen // type + nameLen + name
	sniExtData := make([]byte, 0, 2+sniListLen)
	sniExtData = append(sniExtData, byte(sniListLen>>8), byte(sniListLen))
	sniExtData = append(sniExtData, 0) // host_name type
	sniExtData = append(sniExtData, byte(nameLen>>8), byte(nameLen))
	sniExtData = append(sniExtData, []byte(hostname)...)

	// Extension: type=0x0000 (SNI), length, data
	ext := make([]byte, 0, 4+len(sniExtData))
	ext = append(ext, 0, 0) // SNI type
	ext = append(ext, byte(len(sniExtData)>>8), byte(len(sniExtData)))
	ext = append(ext, sniExtData...)

	// Extensions total length
	extsLen := len(ext)

	// ClientHello body: version(2) + random(32) + sessionID(1) + cipherSuites(4) + compression(2) + extensions
	chBody := make([]byte, 0, 2+32+1+4+2+2+extsLen)
	chBody = append(chBody, 0x03, 0x03)          // TLS 1.2
	chBody = append(chBody, make([]byte, 32)...) // random
	chBody = append(chBody, 0)                   // session ID length = 0
	chBody = append(chBody, 0, 2, 0x00, 0xFF)    // cipher suites: length=2, one suite
	chBody = append(chBody, 1, 0)                // compression: length=1, null
	chBody = append(chBody, byte(extsLen>>8), byte(extsLen))
	chBody = append(chBody, ext...)

	// Handshake: type=ClientHello(1), length(3), body
	hsLen := len(chBody)
	hs := make([]byte, 0, 4+hsLen)
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, chBody...)

	// TLS record: type=Handshake(0x16), version(2), length(2), handshake
	recLen := len(hs)
	record := make([]byte, 0, 5+recLen)
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, hs...)

	return record
}
