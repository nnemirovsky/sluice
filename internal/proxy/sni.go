package proxy

import "io"

// extractSNI reads a TLS ClientHello from buf and returns the SNI hostname.
// Returns empty string if the data is not a TLS ClientHello or contains no SNI.
// Does not consume from any reader. The caller must buffer the bytes and replay
// them after inspection.
func extractSNI(buf []byte) string {
	// Minimum TLS record: type(1) + version(2) + length(2) + handshake header(4) = 9
	if len(buf) < 9 {
		return ""
	}
	// TLS record: ContentType=Handshake (0x16)
	if buf[0] != 0x16 {
		return ""
	}
	// Record length
	recordLen := int(buf[3])<<8 | int(buf[4])
	if len(buf) < 5+recordLen {
		return ""
	}
	hs := buf[5 : 5+recordLen]

	// Handshake: type=ClientHello (0x01)
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	ch := hs[4 : 4+hsLen]

	// ClientHello: version(2) + random(32) = 34
	if len(ch) < 34 {
		return ""
	}
	pos := 34

	// Session ID
	if pos >= len(ch) {
		return ""
	}
	sidLen := int(ch[pos])
	pos += 1 + sidLen
	if pos+2 > len(ch) {
		return ""
	}

	// Cipher suites
	csLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2 + csLen
	if pos >= len(ch) {
		return ""
	}

	// Compression methods
	cmLen := int(ch[pos])
	pos += 1 + cmLen
	if pos+2 > len(ch) {
		return ""
	}

	// Extensions
	extLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(ch) {
		return ""
	}

	for pos+4 <= extEnd {
		extType := int(ch[pos])<<8 | int(ch[pos+1])
		extDataLen := int(ch[pos+2])<<8 | int(ch[pos+3])
		pos += 4
		if pos+extDataLen > extEnd {
			return ""
		}
		// SNI extension type = 0x0000
		if extType == 0 {
			return parseSNIExtension(ch[pos : pos+extDataLen])
		}
		pos += extDataLen
	}
	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return ""
	}
	d := data[2 : 2+listLen]
	for len(d) >= 3 {
		nameType := d[0]
		nameLen := int(d[1])<<8 | int(d[2])
		d = d[3:]
		if len(d) < nameLen {
			return ""
		}
		if nameType == 0 { // host_name
			return string(d[:nameLen])
		}
		d = d[nameLen:]
	}
	return ""
}

// peekSNI reads enough bytes from r to extract the SNI from a TLS ClientHello.
// A single Read may not return the full TLS record, so this function reads
// until it has enough data (up to maxBytes). Returns the peeked buffer and
// any error. The caller should prepend the buffer to subsequent reads.
func peekSNI(r io.Reader, maxBytes int) ([]byte, string, error) {
	buf := make([]byte, 0, maxBytes)
	tmp := make([]byte, maxBytes)

	for len(buf) < maxBytes {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		// Try extracting SNI after each read. The parser returns empty
		// if the buffer is too short, so we keep reading until it succeeds
		// or we hit an error/limit.
		if sni := extractSNI(buf); sni != "" {
			return buf, sni, nil
		}
		if err != nil {
			if len(buf) > 0 {
				return buf, "", nil
			}
			return nil, "", err
		}
		// If the first bytes are not a TLS handshake, stop reading.
		if len(buf) >= 1 && buf[0] != 0x16 {
			return buf, "", nil
		}
	}
	return buf, extractSNI(buf), nil
}
