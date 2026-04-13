package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"golang.org/x/crypto/hkdf"
)

// QUIC v1 (RFC 9001) and v2 (RFC 9369) Initial salts used to derive
// Initial secrets from the Destination Connection ID.
var (
	quicV1Salt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
		0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicV2Salt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
		0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
		0xf9, 0xbd, 0x2e, 0xd9,
	}
)

// QUIC version constants.
const (
	quicVersionV1 = 0x00000001
	quicVersionV2 = 0x6b3343cf
)

// ExtractQUICSNI attempts to extract the TLS SNI hostname from a QUIC Initial
// packet. It decrypts the Initial packet payload per RFC 9001 Section 5 and
// parses CRYPTO frames to find the TLS ClientHello, then delegates to
// extractSNI for the actual SNI parsing. Returns empty string on any failure
// (malformed packet, unsupported version, decryption error, no SNI).
// Supports both QUIC v1 and v2.
func ExtractQUICSNI(packet []byte) string {
	if len(packet) < 5 {
		return ""
	}

	// Long header: form bit (1) + fixed bit (1) must both be set.
	if packet[0]&0xC0 != 0xC0 {
		return ""
	}

	version := binary.BigEndian.Uint32(packet[1:5])

	var salt []byte
	var hpLabel, keyLabel, ivLabel string

	switch version {
	case quicVersionV1:
		salt = quicV1Salt
		hpLabel = "quic hp"
		keyLabel = "quic key"
		ivLabel = "quic iv"
	case quicVersionV2:
		salt = quicV2Salt
		hpLabel = "quicv2 hp"
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
	default:
		return ""
	}

	// Parse long header fields after version.
	pos := 5

	// DCID length (1 byte) + DCID
	if pos >= len(packet) {
		return ""
	}
	dcidLen := int(packet[pos])
	pos++
	if pos+dcidLen > len(packet) {
		return ""
	}
	dcid := packet[pos : pos+dcidLen]
	pos += dcidLen

	// SCID length (1 byte) + SCID
	if pos >= len(packet) {
		return ""
	}
	scidLen := int(packet[pos])
	pos++
	pos += scidLen // skip SCID bytes
	if pos > len(packet) {
		return ""
	}

	// Initial packet type check. For QUIC v1 the type bits (bits 4-5 of
	// first byte) are 00 for Initial. For QUIC v2 Initial type is 01.
	firstByte := packet[0]
	pktType := (firstByte & 0x30) >> 4
	if version == quicVersionV1 && pktType != 0x00 {
		return ""
	}
	if version == quicVersionV2 && pktType != 0x01 {
		return ""
	}

	// Token length (variable-length integer) + token
	tokenLen, n := readQUICVarint(packet[pos:])
	if n == 0 || tokenLen > math.MaxInt {
		return ""
	}
	pos += n + int(tokenLen)
	if pos > len(packet) {
		return ""
	}

	// Payload length (variable-length integer)
	payloadLen, n := readQUICVarint(packet[pos:])
	if n == 0 || payloadLen > math.MaxInt {
		return ""
	}
	pos += n

	// pos now points to the start of the protected payload (packet number + encrypted data).
	// payloadLen covers packet number bytes + encrypted payload + AEAD tag.
	if pos+int(payloadLen) > len(packet) {
		return ""
	}

	// Derive Initial secrets.
	clientSecret, err := deriveQUICClientSecret(dcid, salt)
	if err != nil {
		return ""
	}

	hpKey, err := hkdfExpandLabel(clientSecret, hpLabel, 16)
	if err != nil {
		return ""
	}
	packetKey, err := hkdfExpandLabel(clientSecret, keyLabel, 16)
	if err != nil {
		return ""
	}
	iv, err := hkdfExpandLabel(clientSecret, ivLabel, 12)
	if err != nil {
		return ""
	}

	// Remove header protection.
	// The sample starts 4 bytes into the payload (assuming 4-byte packet number,
	// which is the maximum; we adjust after unmasking).
	protectedPayload := packet[pos : pos+int(payloadLen)]
	if len(protectedPayload) < 4+16 {
		return ""
	}
	sample := protectedPayload[4 : 4+16]

	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return ""
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	// Unmask the first byte to get the packet number length.
	// Long header: mask with 0x0f.
	unmaskedFirst := firstByte ^ (mask[0] & 0x0f)
	pnLen := int(unmaskedFirst&0x03) + 1

	// Unmask the packet number bytes.
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = protectedPayload[i] ^ mask[1+i]
	}

	// Reconstruct the packet number.
	var pn uint64
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	// Build the AAD: all header bytes up to and including the packet number,
	// with header protection removed.
	headerLen := pos + pnLen
	aad := make([]byte, headerLen)
	copy(aad, packet[:headerLen])
	// Fix the first byte in the AAD.
	aad[0] = unmaskedFirst
	// Fix the packet number bytes in the AAD.
	copy(aad[pos:], pnBytes)

	// Build the nonce: IV XOR packet number (padded to 12 bytes on the left).
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[12-1-i] ^= byte(pn >> (8 * i))
	}

	// Decrypt payload.
	aesBlock, err := aes.NewCipher(packetKey)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return ""
	}

	// Encrypted data starts after packet number bytes, includes AEAD tag.
	ciphertext := protectedPayload[pnLen:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return ""
	}

	// Parse QUIC frames looking for CRYPTO frames (type 0x06).
	// Reassemble CRYPTO data contiguous from offset 0, which covers the
	// vast majority of Initial packets.
	clientHello := extractCryptoData(plaintext)
	if clientHello == nil {
		return ""
	}

	// The CRYPTO frame contains a TLS handshake message (ClientHello) WITHOUT
	// the TLS record layer header. extractSNI expects the TLS record wrapper,
	// so we prepend a synthetic one.
	//
	// Note: quic-go may fragment the ClientHello across multiple QUIC Initial
	// packets, with each packet containing a CRYPTO frame at a different
	// offset. When the first packet's CRYPTO frame is too small to contain
	// the extensions section (where SNI lives), extraction fails silently
	// and the caller falls back to DNS reverse cache.
	return extractSNIFromHandshake(clientHello)
}

// ExtractQUICCryptoData attempts to decrypt a QUIC Initial packet and return
// the raw CRYPTO frame data and its starting offset within the TLS handshake
// stream. This allows callers to accumulate CRYPTO data across multiple QUIC
// Initial packets (which happens when quic-go fragments large ClientHellos).
// Returns nil data on any failure (malformed packet, decryption error, etc.).
func ExtractQUICCryptoData(packet []byte) (data []byte, offset uint64) {
	if len(packet) < 5 {
		return nil, 0
	}

	if packet[0]&0xC0 != 0xC0 {
		return nil, 0
	}

	version := binary.BigEndian.Uint32(packet[1:5])

	var salt []byte
	var hpLabel, keyLabel, ivLabel string

	switch version {
	case quicVersionV1:
		salt = quicV1Salt
		hpLabel = "quic hp"
		keyLabel = "quic key"
		ivLabel = "quic iv"
	case quicVersionV2:
		salt = quicV2Salt
		hpLabel = "quicv2 hp"
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
	default:
		return nil, 0
	}

	pos := 5
	if pos >= len(packet) {
		return nil, 0
	}
	dcidLen := int(packet[pos])
	pos++
	if pos+dcidLen > len(packet) {
		return nil, 0
	}
	dcid := packet[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(packet) {
		return nil, 0
	}
	scidLen := int(packet[pos])
	pos++
	pos += scidLen
	if pos > len(packet) {
		return nil, 0
	}

	firstByte := packet[0]
	pktType := (firstByte & 0x30) >> 4
	if version == quicVersionV1 && pktType != 0x00 {
		return nil, 0
	}
	if version == quicVersionV2 && pktType != 0x01 {
		return nil, 0
	}

	tokenLen, n := readQUICVarint(packet[pos:])
	if n == 0 || tokenLen > math.MaxInt {
		return nil, 0
	}
	pos += n + int(tokenLen)
	if pos > len(packet) {
		return nil, 0
	}

	payloadLen, n := readQUICVarint(packet[pos:])
	if n == 0 || payloadLen > math.MaxInt {
		return nil, 0
	}
	pos += n

	if pos+int(payloadLen) > len(packet) {
		return nil, 0
	}

	clientSecret, err := deriveQUICClientSecret(dcid, salt)
	if err != nil {
		return nil, 0
	}

	hpKey, err := hkdfExpandLabel(clientSecret, hpLabel, 16)
	if err != nil {
		return nil, 0
	}
	packetKey, err := hkdfExpandLabel(clientSecret, keyLabel, 16)
	if err != nil {
		return nil, 0
	}
	iv, err := hkdfExpandLabel(clientSecret, ivLabel, 12)
	if err != nil {
		return nil, 0
	}

	protectedPayload := packet[pos : pos+int(payloadLen)]
	if len(protectedPayload) < 4+16 {
		return nil, 0
	}
	sample := protectedPayload[4 : 4+16]

	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, 0
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	unmaskedFirst := firstByte ^ (mask[0] & 0x0f)
	pnLen := int(unmaskedFirst&0x03) + 1

	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = protectedPayload[i] ^ mask[1+i]
	}

	var pn uint64
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	headerLen := pos + pnLen
	aad := make([]byte, headerLen)
	copy(aad, packet[:headerLen])
	aad[0] = unmaskedFirst
	copy(aad[pos:], pnBytes)

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[12-1-i] ^= byte(pn >> (8 * i))
	}

	aesBlock, err := aes.NewCipher(packetKey)
	if err != nil {
		return nil, 0
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, 0
	}

	ciphertext := protectedPayload[pnLen:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, 0
	}

	// Extract the first CRYPTO frame's data and offset.
	return extractFirstCryptoFrame(plaintext)
}

// extractFirstCryptoFrame scans QUIC frames for the first CRYPTO frame
// (type 0x06) and returns its data and stream offset. Skips PADDING, PING,
// ACK, and CONNECTION_CLOSE frames. Returns nil if no CRYPTO frame is found.
func extractFirstCryptoFrame(frames []byte) ([]byte, uint64) {
	pos := 0
	for pos < len(frames) {
		frameType, n := readQUICVarint(frames[pos:])
		if n == 0 {
			break
		}
		pos += n

		switch frameType {
		case 0x00: // PADDING
		case 0x01: // PING
		case 0x02, 0x03: // ACK
			_, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return nil, 0
			}
			pos += vn
			_, vn = readQUICVarint(frames[pos:])
			if vn == 0 {
				return nil, 0
			}
			pos += vn
			rangeCount, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return nil, 0
			}
			pos += vn
			_, vn = readQUICVarint(frames[pos:])
			if vn == 0 {
				return nil, 0
			}
			pos += vn
			for i := uint64(0); i < rangeCount; i++ {
				_, vn = readQUICVarint(frames[pos:])
				if vn == 0 {
					return nil, 0
				}
				pos += vn
				_, vn = readQUICVarint(frames[pos:])
				if vn == 0 {
					return nil, 0
				}
				pos += vn
			}
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					_, vn = readQUICVarint(frames[pos:])
					if vn == 0 {
						return nil, 0
					}
					pos += vn
				}
			}
		case 0x06: // CRYPTO
			cryptoOffset, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return nil, 0
			}
			pos += vn
			dataLen, vn := readQUICVarint(frames[pos:])
			if vn == 0 || dataLen > math.MaxInt {
				return nil, 0
			}
			pos += vn
			if pos+int(dataLen) > len(frames) {
				return nil, 0
			}
			result := make([]byte, int(dataLen))
			copy(result, frames[pos:pos+int(dataLen)])
			return result, cryptoOffset
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			_, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return nil, 0
			}
			pos += vn
			if frameType == 0x1c {
				_, vn = readQUICVarint(frames[pos:])
				if vn == 0 {
					return nil, 0
				}
				pos += vn
			}
			reasonLen, vn := readQUICVarint(frames[pos:])
			if vn == 0 || reasonLen > math.MaxInt {
				return nil, 0
			}
			pos += vn
			if pos+int(reasonLen) > len(frames) {
				return nil, 0
			}
			pos += int(reasonLen)
		default:
			return nil, 0
		}
	}
	return nil, 0
}

// extractSNIFromHandshake parses a raw TLS handshake message (no record layer)
// and extracts the SNI hostname. This wraps the message in a synthetic TLS
// record header and delegates to extractSNI.
func extractSNIFromHandshake(hs []byte) string {
	if len(hs) < 4 {
		return ""
	}
	// Build a minimal TLS record: type=Handshake(0x16), version=TLS1.0(0x0301), length, data.
	record := make([]byte, 5+len(hs))
	record[0] = 0x16 // Handshake
	record[1] = 0x03 // TLS 1.0 major
	record[2] = 0x01 // TLS 1.0 minor
	record[3] = byte(len(hs) >> 8)
	record[4] = byte(len(hs))
	copy(record[5:], hs)
	return extractSNI(record)
}

// extractCryptoData scans QUIC frames for CRYPTO frames (type 0x06) and
// returns the concatenated data. Only processes frames with offset 0 or
// contiguous from offset 0 (sufficient for Initial packets which contain
// the full ClientHello). Skips PADDING, PING, ACK, and CONNECTION_CLOSE
// frames. Unknown frame types are skipped gracefully (return data collected
// so far) since their length cannot be determined.
func extractCryptoData(frames []byte) []byte {
	var result []byte
	var nextOffset uint64

	pos := 0
	for pos < len(frames) {
		// Frame types are variable-length integers per RFC 9000 Section 12.4.
		if pos >= len(frames) {
			break
		}
		frameType, n := readQUICVarint(frames[pos:])
		if n == 0 {
			break
		}
		pos += n

		switch frameType {
		case 0x00:
			// PADDING frame: single-byte type, no payload. The type byte
			// was already consumed above.

		case 0x01:
			// PING frame: single-byte type, no payload.

		case 0x02, 0x03:
			// ACK frame: skip it. Parse enough to find the length.
			// Largest Acknowledged (varint)
			_, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return result
			}
			pos += vn
			// ACK Delay (varint)
			_, vn = readQUICVarint(frames[pos:])
			if vn == 0 {
				return result
			}
			pos += vn
			// ACK Range Count (varint)
			rangeCount, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return result
			}
			pos += vn
			// First ACK Range (varint)
			_, vn = readQUICVarint(frames[pos:])
			if vn == 0 {
				return result
			}
			pos += vn
			// Additional ACK Ranges: each has Gap (varint) + ACK Range (varint)
			for i := uint64(0); i < rangeCount; i++ {
				_, vn = readQUICVarint(frames[pos:])
				if vn == 0 {
					return result
				}
				pos += vn
				_, vn = readQUICVarint(frames[pos:])
				if vn == 0 {
					return result
				}
				pos += vn
			}
			// ECN counts for type 0x03
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					_, vn = readQUICVarint(frames[pos:])
					if vn == 0 {
						return result
					}
					pos += vn
				}
			}

		case 0x06:
			// CRYPTO frame: offset(varint) + length(varint) + data
			offset, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return result
			}
			pos += vn
			dataLen, vn := readQUICVarint(frames[pos:])
			if vn == 0 || dataLen > math.MaxInt {
				return result
			}
			pos += vn
			if pos+int(dataLen) > len(frames) {
				return result
			}
			// Only include data that is contiguous from the start.
			if offset == nextOffset {
				result = append(result, frames[pos:pos+int(dataLen)]...)
				nextOffset += dataLen
			}
			pos += int(dataLen)

		case 0x1c, 0x1d:
			// CONNECTION_CLOSE frame: error_code(varint) + frame_type(varint,
			// only for 0x1c) + reason_phrase_length(varint) + reason_phrase.
			_, vn := readQUICVarint(frames[pos:])
			if vn == 0 {
				return result
			}
			pos += vn
			if frameType == 0x1c {
				// Frame Type field (only in transport CONNECTION_CLOSE).
				_, vn = readQUICVarint(frames[pos:])
				if vn == 0 {
					return result
				}
				pos += vn
			}
			reasonLen, vn := readQUICVarint(frames[pos:])
			if vn == 0 || reasonLen > math.MaxInt {
				return result
			}
			pos += vn
			if pos+int(reasonLen) > len(frames) {
				return result
			}
			pos += int(reasonLen)

		default:
			// Unknown frame type. We cannot determine its length, so return
			// whatever CRYPTO data we have collected so far.
			return result
		}
	}

	return result
}

// readQUICVarint decodes a QUIC variable-length integer (RFC 9000 Section 16).
// Returns the value and the number of bytes consumed. Returns (0, 0) if the
// buffer is too short.
func readQUICVarint(buf []byte) (uint64, int) {
	if len(buf) == 0 {
		return 0, 0
	}
	prefix := buf[0] >> 6
	length := 1 << prefix

	if len(buf) < length {
		return 0, 0
	}

	var val uint64
	switch length {
	case 1:
		val = uint64(buf[0] & 0x3f)
	case 2:
		val = uint64(buf[0]&0x3f)<<8 | uint64(buf[1])
	case 4:
		val = uint64(buf[0]&0x3f)<<24 | uint64(buf[1])<<16 |
			uint64(buf[2])<<8 | uint64(buf[3])
	case 8:
		val = uint64(buf[0]&0x3f)<<56 | uint64(buf[1])<<48 |
			uint64(buf[2])<<40 | uint64(buf[3])<<32 |
			uint64(buf[4])<<24 | uint64(buf[5])<<16 |
			uint64(buf[6])<<8 | uint64(buf[7])
	}

	return val, length
}

// deriveQUICClientSecret derives the TLS 1.3 client Initial secret from
// the DCID and salt per RFC 9001 Section 5.2. Both QUIC v1 and v2 use the
// same label for initial secret derivation, so the version is only reflected
// in the caller's choice of salt.
func deriveQUICClientSecret(dcid, salt []byte) ([]byte, error) {
	// Step 1: initial_secret = HKDF-Extract(salt, dcid)
	h := hkdf.Extract(sha256.New, dcid, salt)

	// Step 2: client_in = HKDF-Expand-Label(initial_secret, "client in", "", 32)
	return hkdfExpandLabel(h, "client in", 32)
}

// hkdfExpandLabel performs HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446
// Section 7.1), using the given secret and label to produce length bytes.
// The context (hash) is empty for QUIC key derivation.
// Label format: "tls13 " + label (RFC 8446).
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	fullLabel := "tls13 " + label

	// HkdfLabel struct:
	//   uint16 length
	//   opaque label<7..255>  = length(1) + "tls13 " + label
	//   opaque context<0..255> = length(1) + context
	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1)
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)
	hkdfLabel = append(hkdfLabel, 0) // empty context

	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, hkdfLabel)
	if _, err := r.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
