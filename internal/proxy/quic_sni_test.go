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

func TestExtractCryptoData_MultipleCryptoFrames(t *testing.T) {
	// Two contiguous CRYPTO frames: offset=0 len=3 "abc" + offset=3 len=3 "def"
	var frame []byte
	frame = append(frame, 0x06, 0x00, 0x03, 'a', 'b', 'c') // CRYPTO offset=0 len=3
	frame = append(frame, 0x06, 0x03, 0x03, 'd', 'e', 'f') // CRYPTO offset=3 len=3
	data := extractCryptoData(frame)
	if string(data) != "abcdef" {
		t.Errorf("expected abcdef, got %q", string(data))
	}
}

func TestExtractCryptoData_PaddingBetweenCryptoFrames(t *testing.T) {
	// CRYPTO + PADDING + CRYPTO (contiguous offsets).
	var frame []byte
	frame = append(frame, 0x06, 0x00, 0x02, 'h', 'i')         // CRYPTO offset=0 len=2
	frame = append(frame, 0x00, 0x00, 0x00)                   // 3 PADDING bytes
	frame = append(frame, 0x06, 0x02, 0x03, 'b', 'y', 'e')    // CRYPTO offset=2 len=3
	frame = append(frame, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // trailing PADDING
	data := extractCryptoData(frame)
	if string(data) != "hibye" {
		t.Errorf("expected hibye, got %q", string(data))
	}
}

func TestExtractCryptoData_ConnectionClose(t *testing.T) {
	// CRYPTO frame followed by a CONNECTION_CLOSE (type 0x1c) frame.
	var frame []byte
	frame = append(frame, 0x06, 0x00, 0x03, 'a', 'b', 'c') // CRYPTO
	// CONNECTION_CLOSE (0x1c): error_code=0x00, frame_type=0x00, reason_len=0
	frame = append(frame, 0x1c, 0x00, 0x00, 0x00)
	data := extractCryptoData(frame)
	if string(data) != "abc" {
		t.Errorf("expected abc, got %q", string(data))
	}
}

func TestExtractCryptoData_ConnectionCloseApp(t *testing.T) {
	// CONNECTION_CLOSE application (0x1d) before a CRYPTO frame.
	// 0x1d: error_code=0x01, reason_len=4, reason="test"
	var frame []byte
	frame = append(frame, 0x1d, 0x01, 0x04, 't', 'e', 's', 't')
	frame = append(frame, 0x06, 0x00, 0x03, 'x', 'y', 'z') // CRYPTO
	data := extractCryptoData(frame)
	if string(data) != "xyz" {
		t.Errorf("expected xyz, got %q", string(data))
	}
}

func TestExtractCryptoData_UnknownFrameAfterCrypto(t *testing.T) {
	// CRYPTO frame followed by an unknown frame type. The unknown frame
	// should not discard the CRYPTO data already collected.
	var frame []byte
	frame = append(frame, 0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o') // CRYPTO
	frame = append(frame, 0x30)                                      // unknown type 0x30
	frame = append(frame, 0xFF, 0xFF)                                // garbage
	data := extractCryptoData(frame)
	if string(data) != "hello" {
		t.Errorf("expected hello, got %q", string(data))
	}
}

func TestExtractCryptoData_UnknownFrameBeforeCrypto(t *testing.T) {
	// Unknown frame type before any CRYPTO frame. We return nil since no
	// CRYPTO data was found before the unknown frame.
	var frame []byte
	frame = append(frame, 0x30)                            // unknown type 0x30
	frame = append(frame, 0x06, 0x00, 0x03, 'a', 'b', 'c') // CRYPTO (unreachable)
	data := extractCryptoData(frame)
	if len(data) != 0 {
		t.Errorf("expected empty for unknown frame before CRYPTO, got %q", string(data))
	}
}

func TestExtractCryptoData_ACKThenCrypto(t *testing.T) {
	// ACK frame (type 0x02) followed by a CRYPTO frame. Tests that the ACK
	// parser correctly skips the ACK so the CRYPTO frame is found.
	var frame []byte
	// ACK: largest_ack=10, delay=0, range_count=0, first_range=0
	frame = append(frame, 0x02, 0x0a, 0x00, 0x00, 0x00)
	frame = append(frame, 0x06, 0x00, 0x04, 't', 'e', 's', 't') // CRYPTO
	data := extractCryptoData(frame)
	if string(data) != "test" {
		t.Errorf("expected test, got %q", string(data))
	}
}

func TestExtractCryptoData_ACKECNThenCrypto(t *testing.T) {
	// ACK_ECN frame (type 0x03) followed by a CRYPTO frame.
	var frame []byte
	// ACK_ECN: largest_ack=5, delay=0, range_count=0, first_range=0, ect0=1, ect1=0, ecn_ce=0
	frame = append(frame, 0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00)
	frame = append(frame, 0x06, 0x00, 0x02, 'o', 'k') // CRYPTO
	data := extractCryptoData(frame)
	if string(data) != "ok" {
		t.Errorf("expected ok, got %q", string(data))
	}
}

func TestExtractQUICSNI_WithPaddingAndMultipleCrypto(t *testing.T) {
	// Build a full QUIC Initial packet where the ClientHello is split across
	// two CRYPTO frames with PADDING between them, mimicking real-world
	// quic-go behavior.
	packet := buildQUICInitialMultiCrypto(t, "multi-crypto.example.com", quicVersionV1)
	sni := ExtractQUICSNI(packet)
	if sni != "multi-crypto.example.com" {
		t.Errorf("expected multi-crypto.example.com, got %q", sni)
	}
}

// buildQUICInitialMultiCrypto constructs a QUIC Initial packet where the
// ClientHello is split across two CRYPTO frames with PADDING in between,
// reproducing the pattern seen in real quic-go traffic.
func buildQUICInitialMultiCrypto(t *testing.T, hostname string, version uint32) []byte {
	t.Helper()

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

	fullRecord := buildClientHello(hostname)
	clientHello := fullRecord[5:] // strip TLS record header

	// Split the ClientHello roughly in half across two CRYPTO frames.
	splitAt := len(clientHello) / 2
	part1 := clientHello[:splitAt]
	part2 := clientHello[splitAt:]

	// CRYPTO frame 1: offset=0, data=part1
	var crypto1 []byte
	crypto1 = append(crypto1, 0x06, 0x00)
	crypto1 = append(crypto1, encodeQUICVarint(uint64(len(part1)))...)
	crypto1 = append(crypto1, part1...)

	// 50 bytes of PADDING
	padding := make([]byte, 50)

	// CRYPTO frame 2: offset=len(part1), data=part2
	var crypto2 []byte
	crypto2 = append(crypto2, 0x06)
	crypto2 = append(crypto2, encodeQUICVarint(uint64(len(part1)))...)
	crypto2 = append(crypto2, encodeQUICVarint(uint64(len(part2)))...)
	crypto2 = append(crypto2, part2...)

	plaintext := append(crypto1, padding...)
	plaintext = append(plaintext, crypto2...)

	return buildQUICInitialFromPlaintext(t, dcid, plaintext, version)
}

// buildQUICInitialFromPlaintext encrypts the given plaintext (QUIC frames)
// into a valid QUIC Initial packet. Shared helper for custom frame layouts.
func buildQUICInitialFromPlaintext(t *testing.T, dcid, plaintext []byte, version uint32) []byte {
	t.Helper()

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

	clientSecret, err := deriveQUICClientSecret(dcid, salt)
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

	pnLen := 2
	pnBytes := []byte{0x00, 0x00}
	var pn uint64

	var firstByte byte
	switch version {
	case quicVersionV1:
		firstByte = 0xC0 | byte(pnLen-1)
	case quicVersionV2:
		firstByte = 0xC0 | 0x10 | byte(pnLen-1)
	}

	header := []byte{firstByte}
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, version)
	header = append(header, versionBytes...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0) // SCID length = 0
	header = append(header, 0) // Token length = 0

	aesBlock, err := aes.NewCipher(packetKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}

	payloadLen := pnLen + len(plaintext) + gcm.Overhead()
	header = append(header, encodeQUICVarintTwoBytes(uint64(payloadLen))...)

	aad := append(header, pnBytes...)

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[12-1-i] ^= byte(pn >> (8 * i))
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	protectedPayload := append(pnBytes, ciphertext...)

	sample := protectedPayload[4 : 4+16]
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		t.Fatalf("aes.NewCipher(hp): %v", err)
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	protectedFirst := firstByte ^ (mask[0] & 0x0f)
	protectedPN := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		protectedPN[i] = pnBytes[i] ^ mask[1+i]
	}

	packet := []byte{protectedFirst}
	packet = append(packet, header[1:]...)
	packet = append(packet, protectedPN...)
	packet = append(packet, ciphertext...)

	return packet
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
	clientSecret, err := deriveQUICClientSecret(dcid, salt)
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
