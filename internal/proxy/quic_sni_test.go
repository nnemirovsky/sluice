package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestExtractQUICSNI_V1(t *testing.T) {
	packet := buildQUICInitial(t, "cloudflare.com", quicVersionV1)
	sni := ExtractQUICSNI(packet)
	if sni != "cloudflare.com" {
		t.Errorf("expected cloudflare.com, got %q", sni)
	}
}

func TestExtractQUICSNI_V2(t *testing.T) {
	packet := buildQUICInitial(t, "example.org", quicVersionV2)
	sni := ExtractQUICSNI(packet)
	if sni != "example.org" {
		t.Errorf("expected example.org, got %q", sni)
	}
}

func TestExtractQUICSNI_Malformed(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{0xC0, 0x00, 0x00}},
		{"not long header", []byte{0x40, 0x00, 0x00, 0x00, 0x01}},
		{"unknown version", func() []byte {
			b := make([]byte, 20)
			b[0] = 0xC0
			binary.BigEndian.PutUint32(b[1:5], 0xDEADBEEF)
			return b
		}()},
		{"truncated after version", func() []byte {
			b := make([]byte, 5)
			b[0] = 0xC0
			binary.BigEndian.PutUint32(b[1:5], quicVersionV1)
			return b
		}()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sni := ExtractQUICSNI(tc.packet)
			if sni != "" {
				t.Errorf("expected empty, got %q", sni)
			}
		})
	}
}

func TestExtractQUICSNI_NotInitialPacketType(t *testing.T) {
	// Build a valid v1 packet but change the type bits to Handshake (0x02).
	packet := buildQUICInitial(t, "example.com", quicVersionV1)
	// Set type bits (bits 4-5) to 0x02 (Handshake).
	packet[0] = (packet[0] & 0xCF) | 0x20
	sni := ExtractQUICSNI(packet)
	if sni != "" {
		t.Errorf("expected empty for non-Initial packet, got %q", sni)
	}
}

func TestReadQUICVarint(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		val  uint64
		n    int
	}{
		{"1-byte 0", []byte{0x00}, 0, 1},
		{"1-byte 37", []byte{0x25}, 37, 1},
		{"2-byte 15293", []byte{0x7b, 0xbd}, 15293, 2},
		{"4-byte 494878333", []byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4},
		{"empty", []byte{}, 0, 0},
		{"truncated 2-byte", []byte{0x40}, 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, n := readQUICVarint(tc.buf)
			if val != tc.val || n != tc.n {
				t.Errorf("got (%d, %d), want (%d, %d)", val, n, tc.val, tc.n)
			}
		})
	}
}

func TestExtractCryptoData(t *testing.T) {
	// CRYPTO frame: type=0x06, offset=0 (1 byte varint), length=5, data="hello"
	frame := []byte{0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	data := extractCryptoData(frame)
	if string(data) != "hello" {
		t.Errorf("expected hello, got %q", string(data))
	}
}

func TestExtractCryptoData_WithPadding(t *testing.T) {
	// PADDING + CRYPTO frame.
	frame := []byte{0x00, 0x00, 0x06, 0x00, 0x03, 'a', 'b', 'c'}
	data := extractCryptoData(frame)
	if string(data) != "abc" {
		t.Errorf("expected abc, got %q", string(data))
	}
}

func TestExtractCryptoData_NonZeroOffset(t *testing.T) {
	// CRYPTO frame at offset 100. Should be skipped (we only handle offset 0).
	frame := []byte{0x06, 0x40, 0x64, 0x03, 'x', 'y', 'z'}
	data := extractCryptoData(frame)
	if len(data) != 0 {
		t.Errorf("expected empty for non-zero offset, got %q", string(data))
	}
}

func TestExtractSNIFromHandshake(t *testing.T) {
	// Build a ClientHello handshake message (without TLS record wrapper).
	full := buildClientHello("test.example.com")
	// Strip the TLS record header (5 bytes: type + version + length).
	hs := full[5:]
	sni := extractSNIFromHandshake(hs)
	if sni != "test.example.com" {
		t.Errorf("expected test.example.com, got %q", sni)
	}
}

// buildQUICInitial constructs a QUIC Initial packet with an encrypted
// ClientHello containing the given SNI hostname. This exercises the full
// encryption path in reverse so ExtractQUICSNI can decrypt it.
func buildQUICInitial(t *testing.T, hostname string, version uint32) []byte {
	t.Helper()

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

	// Build the ClientHello as a TLS handshake message (no record header).
	fullRecord := buildClientHello(hostname)
	clientHello := fullRecord[5:] // strip TLS record header

	// Wrap in a CRYPTO frame: type(0x06) + offset(varint 0) + length(varint) + data
	cryptoFrame := []byte{0x06, 0x00}
	cryptoFrame = append(cryptoFrame, encodeQUICVarint(uint64(len(clientHello)))...)
	cryptoFrame = append(cryptoFrame, clientHello...)

	// Determine salt and labels based on version.
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
	}

	// Derive keys.
	clientSecret, err := deriveQUICClientSecret(dcid, salt, version)
	if err != nil {
		t.Fatalf("deriveQUICClientSecret: %v", err)
	}
	hpKey, err := hkdfExpandLabel(clientSecret, hpLabel, 16)
	if err != nil {
		t.Fatalf("hkdfExpandLabel(hp): %v", err)
	}
	packetKey, err := hkdfExpandLabel(clientSecret, keyLabel, 16)
	if err != nil {
		t.Fatalf("hkdfExpandLabel(key): %v", err)
	}
	iv, err := hkdfExpandLabel(clientSecret, ivLabel, 12)
	if err != nil {
		t.Fatalf("hkdfExpandLabel(iv): %v", err)
	}

	// Packet number: use 2-byte PN = 0 for simplicity.
	pnLen := 2
	pnBytes := []byte{0x00, 0x00}
	var pn uint64

	// Build unprotected header.
	var firstByte byte
	switch version {
	case quicVersionV1:
		// Long header (0xC0) + Initial type (0x00) + reserved (0x00) + PN length (pnLen-1)
		firstByte = 0xC0 | byte(pnLen-1)
	case quicVersionV2:
		// Long header (0xC0) + Initial type for v2 (0x10) + reserved (0x00) + PN length (pnLen-1)
		firstByte = 0xC0 | 0x10 | byte(pnLen-1)
	}

	header := []byte{firstByte}
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, version)
	header = append(header, versionBytes...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0) // SCID length = 0
	header = append(header, 0) // Token length = 0 (varint)

	// We need to know the payload length to encode it in the header.
	// Payload = pnBytes + encrypted(cryptoFrame) + AEAD tag (16 bytes).
	aesBlock, err := aes.NewCipher(packetKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}

	// Pad the CRYPTO frame payload to at least 1200 bytes (QUIC minimum) minus overhead.
	// Actually, for testing purposes we do not need minimum size. Just add some padding frames.
	plaintext := cryptoFrame

	// AAD = header + pn bytes
	aad := make([]byte, len(header))
	copy(aad, header)

	// Compute payload length: pnLen + len(gcm.Seal(plaintext)) = pnLen + len(plaintext) + gcm.Overhead()
	payloadLen := pnLen + len(plaintext) + gcm.Overhead()
	payloadLenEncoded := encodeQUICVarintTwoBytes(uint64(payloadLen))
	header = append(header, payloadLenEncoded...)

	// Now add PN to AAD.
	aad = append(header, pnBytes...)

	// Nonce = IV XOR pn (padded to 12 bytes).
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[12-1-i] ^= byte(pn >> (8 * i))
	}

	// Encrypt.
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Protected payload = pnBytes + ciphertext (before header protection).
	protectedPayload := append(pnBytes, ciphertext...)

	// Apply header protection.
	// Sample starts at pnBytes offset + 4 (always use offset 4 from start of payload).
	sample := protectedPayload[4 : 4+16]
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		t.Fatalf("aes.NewCipher(hp): %v", err)
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	// Mask first byte: long header uses 0x0f.
	protectedFirst := firstByte ^ (mask[0] & 0x0f)

	// Mask PN bytes.
	protectedPN := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		protectedPN[i] = pnBytes[i] ^ mask[1+i]
	}

	// Assemble the final packet.
	packet := []byte{protectedFirst}
	packet = append(packet, header[1:]...) // skip original first byte, already replaced
	packet = append(packet, protectedPN...)
	packet = append(packet, ciphertext...)

	return packet
}

// encodeQUICVarint encodes a uint64 as a QUIC variable-length integer.
func encodeQUICVarint(val uint64) []byte {
	if val < 64 {
		return []byte{byte(val)}
	}
	if val < 16384 {
		return []byte{byte(val>>8) | 0x40, byte(val)}
	}
	if val < 1073741824 {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(val))
		b[0] |= 0x80
		return b
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, val)
	b[0] |= 0xC0
	return b
}

// encodeQUICVarintTwoBytes encodes a uint64 as a 2-byte QUIC varint.
// The value must be < 16384. This is used when we need a fixed-size encoding.
func encodeQUICVarintTwoBytes(val uint64) []byte {
	return []byte{byte(val>>8) | 0x40, byte(val)}
}
