package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nemirovsky/sluice/internal/vault"
)

// helper: build a raw WebSocket frame from components for testing ReadFrame.
func buildRawFrame(fin bool, opcode byte, masked bool, maskKey [4]byte, payload []byte) []byte {
	var buf bytes.Buffer

	var b0 byte
	if fin {
		b0 |= 0x80
	}
	b0 |= opcode & 0x0F
	buf.WriteByte(b0)

	var b1 byte
	if masked {
		b1 |= 0x80
	}
	pLen := len(payload)
	switch {
	case pLen <= 125:
		b1 |= byte(pLen)
	case pLen <= 0xFFFF:
		b1 |= 126
	default:
		b1 |= 127
	}
	buf.WriteByte(b1)

	switch {
	case pLen > 0xFFFF:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(pLen))
		buf.Write(ext[:])
	case pLen > 125:
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(pLen))
		buf.Write(ext[:])
	}

	if masked {
		buf.Write(maskKey[:])
	}

	buf.Write(payload)
	return buf.Bytes()
}

// applyMask XORs payload with key.
func applyMask(data []byte, key [4]byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%4]
	}
	return out
}

func TestReadWriteFrame_UnmaskedText(t *testing.T) {
	payload := []byte("Hello, WebSocket!")
	raw := buildRawFrame(true, OpcodeText, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !f.FIN {
		t.Error("expected FIN=true")
	}
	if f.Opcode != OpcodeText {
		t.Errorf("expected opcode %d, got %d", OpcodeText, f.Opcode)
	}
	if f.Masked {
		t.Error("expected Masked=false")
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("payload mismatch: got %q, want %q", f.Payload, payload)
	}

	// UnmaskedPayload should return same content for unmasked frame.
	if !bytes.Equal(f.UnmaskedPayload(), payload) {
		t.Error("UnmaskedPayload mismatch for unmasked frame")
	}
}

func TestReadWriteFrame_MaskedText(t *testing.T) {
	cleartext := []byte("Hello, masked!")
	key := [4]byte{0x37, 0xFA, 0x21, 0x3D}
	maskedPayload := applyMask(cleartext, key)

	raw := buildRawFrame(true, OpcodeText, true, key, maskedPayload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !f.FIN {
		t.Error("expected FIN=true")
	}
	if f.Opcode != OpcodeText {
		t.Errorf("expected opcode %d, got %d", OpcodeText, f.Opcode)
	}
	if !f.Masked {
		t.Error("expected Masked=true")
	}
	if f.MaskKey != key {
		t.Errorf("mask key mismatch: got %v, want %v", f.MaskKey, key)
	}

	unmasked := f.UnmaskedPayload()
	if !bytes.Equal(unmasked, cleartext) {
		t.Errorf("UnmaskedPayload: got %q, want %q", unmasked, cleartext)
	}
}

func TestReadWriteFrame_BinaryFrame(t *testing.T) {
	payload := []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD}
	raw := buildRawFrame(true, OpcodeBinary, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Opcode != OpcodeBinary {
		t.Errorf("expected opcode %d, got %d", OpcodeBinary, f.Opcode)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestReadWriteFrame_ControlFrames(t *testing.T) {
	tests := []struct {
		name    string
		opcode  byte
		payload []byte
	}{
		{"ping", OpcodePing, []byte("ping data")},
		{"pong", OpcodePong, []byte("pong data")},
		{"close", OpcodeClose, []byte{0x03, 0xE8}}, // status 1000
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := buildRawFrame(true, tt.opcode, false, [4]byte{}, tt.payload)
			f, err := ReadFrame(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if f.Opcode != tt.opcode {
				t.Errorf("opcode: got %d, want %d", f.Opcode, tt.opcode)
			}
			if !f.FIN {
				t.Error("control frames must have FIN=true")
			}
			if !f.IsControl() {
				t.Error("IsControl() should be true")
			}
			if !bytes.Equal(f.Payload, tt.payload) {
				t.Errorf("payload mismatch")
			}
		})
	}
}

func TestReadWriteFrame_ExtendedLength16(t *testing.T) {
	// 126 bytes triggers the 16-bit extended length.
	payload := []byte(strings.Repeat("A", 200))
	raw := buildRawFrame(true, OpcodeText, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(f.Payload) != 200 {
		t.Errorf("payload length: got %d, want 200", len(f.Payload))
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Error("payload content mismatch")
	}
}

func TestReadWriteFrame_ExtendedLength64(t *testing.T) {
	// 65536 bytes triggers the 64-bit extended length.
	payload := bytes.Repeat([]byte("B"), 65536)
	raw := buildRawFrame(true, OpcodeBinary, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(f.Payload) != 65536 {
		t.Errorf("payload length: got %d, want 65536", len(f.Payload))
	}
}

func TestFrameRoundTrip_Unmasked(t *testing.T) {
	payload := []byte("round trip test")
	raw := buildRawFrame(true, OpcodeText, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	var out bytes.Buffer
	if err := WriteFrame(&out, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	if !bytes.Equal(raw, out.Bytes()) {
		t.Errorf("round-trip mismatch:\n  got  %v\n  want %v", out.Bytes(), raw)
	}
}

func TestFrameRoundTrip_Masked(t *testing.T) {
	cleartext := []byte("masked round trip")
	key := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	maskedPayload := applyMask(cleartext, key)
	raw := buildRawFrame(true, OpcodeText, true, key, maskedPayload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	var out bytes.Buffer
	if err := WriteFrame(&out, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	if !bytes.Equal(raw, out.Bytes()) {
		t.Errorf("round-trip mismatch for masked frame")
	}
}

func TestFrameRoundTrip_ExtendedLength16(t *testing.T) {
	payload := []byte(strings.Repeat("C", 300))
	raw := buildRawFrame(true, OpcodeText, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	var out bytes.Buffer
	if err := WriteFrame(&out, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	if !bytes.Equal(raw, out.Bytes()) {
		t.Error("round-trip mismatch for 16-bit length frame")
	}
}

func TestFrameRoundTrip_ExtendedLength64(t *testing.T) {
	payload := bytes.Repeat([]byte("D"), 65536)
	raw := buildRawFrame(true, OpcodeBinary, false, [4]byte{}, payload)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	var out bytes.Buffer
	if err := WriteFrame(&out, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	if !bytes.Equal(raw, out.Bytes()) {
		t.Error("round-trip mismatch for 64-bit length frame")
	}
}

func TestFrameRoundTrip_ControlFrames(t *testing.T) {
	for _, opcode := range []byte{OpcodePing, OpcodePong, OpcodeClose} {
		payload := []byte{0x03, 0xE8}
		raw := buildRawFrame(true, opcode, false, [4]byte{}, payload)

		f, err := ReadFrame(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("ReadFrame opcode %d: %v", opcode, err)
		}

		var out bytes.Buffer
		if err := WriteFrame(&out, f); err != nil {
			t.Fatalf("WriteFrame opcode %d: %v", opcode, err)
		}

		if !bytes.Equal(raw, out.Bytes()) {
			t.Errorf("round-trip mismatch for control frame opcode %d", opcode)
		}
	}
}

func TestSetPayload_Unmasked(t *testing.T) {
	f := &Frame{FIN: true, Opcode: OpcodeText, Masked: false}
	f.SetPayload([]byte("new data"))

	if !bytes.Equal(f.Payload, []byte("new data")) {
		t.Errorf("SetPayload unmasked: got %q", f.Payload)
	}
}

func TestSetPayload_Masked(t *testing.T) {
	key := [4]byte{0x12, 0x34, 0x56, 0x78}
	f := &Frame{FIN: true, Opcode: OpcodeText, Masked: true, MaskKey: key}
	data := []byte("new masked data")
	f.SetPayload(data)

	// Payload should be masked.
	unmasked := f.UnmaskedPayload()
	if !bytes.Equal(unmasked, data) {
		t.Errorf("SetPayload masked: after unmask got %q, want %q", unmasked, data)
	}

	// The raw payload should differ from the cleartext (unless key is all zeros).
	if bytes.Equal(f.Payload, data) {
		t.Error("SetPayload: raw payload should be masked, not cleartext")
	}
}

func TestSetPayload_DoesNotAlias(t *testing.T) {
	f := &Frame{FIN: true, Opcode: OpcodeText, Masked: false}
	data := []byte("original")
	f.SetPayload(data)

	// Mutating the original slice should not affect the frame.
	data[0] = 'X'
	if f.Payload[0] == 'X' {
		t.Error("SetPayload should not alias the input slice")
	}
}

func TestFragmentTracker_Unfragmented(t *testing.T) {
	ft := &FragmentTracker{}
	f := &Frame{FIN: true, Opcode: OpcodeText, Payload: []byte("hello")}

	payload, opcode, complete, err := ft.Accept(f)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !complete {
		t.Fatal("expected complete=true for unfragmented message")
	}
	if opcode != OpcodeText {
		t.Errorf("opcode: got %d, want %d", opcode, OpcodeText)
	}
	if !bytes.Equal(payload, []byte("hello")) {
		t.Errorf("payload: got %q", payload)
	}
}

func TestFragmentTracker_ThreeFragments(t *testing.T) {
	ft := &FragmentTracker{}

	// Fragment 1: start (FIN=false, opcode=text)
	f1 := &Frame{FIN: false, Opcode: OpcodeText, Payload: []byte("hel")}
	_, _, complete, err := ft.Accept(f1)
	if err != nil {
		t.Fatalf("Accept f1: %v", err)
	}
	if complete {
		t.Fatal("first fragment should not be complete")
	}

	// Fragment 2: continuation (FIN=false, opcode=continuation)
	f2 := &Frame{FIN: false, Opcode: OpcodeContinuation, Payload: []byte("lo, ")}
	_, _, complete, err = ft.Accept(f2)
	if err != nil {
		t.Fatalf("Accept f2: %v", err)
	}
	if complete {
		t.Fatal("middle fragment should not be complete")
	}

	// Fragment 3: final (FIN=true, opcode=continuation)
	f3 := &Frame{FIN: true, Opcode: OpcodeContinuation, Payload: []byte("world")}
	payload, opcode, complete, err := ft.Accept(f3)
	if err != nil {
		t.Fatalf("Accept f3: %v", err)
	}
	if !complete {
		t.Fatal("final fragment should be complete")
	}
	if opcode != OpcodeText {
		t.Errorf("opcode: got %d, want %d", opcode, OpcodeText)
	}
	if !bytes.Equal(payload, []byte("hello, world")) {
		t.Errorf("reassembled payload: got %q", payload)
	}
}

func TestFragmentTracker_MaskedFragments(t *testing.T) {
	ft := &FragmentTracker{}
	key := [4]byte{0xAB, 0xCD, 0xEF, 0x01}

	part1 := []byte("part1")
	part2 := []byte("part2")

	f1 := &Frame{FIN: false, Opcode: OpcodeText, Masked: true, MaskKey: key, Payload: applyMask(part1, key)}
	_, _, complete, err := ft.Accept(f1)
	if err != nil {
		t.Fatalf("Accept f1: %v", err)
	}
	if complete {
		t.Fatal("first fragment should not be complete")
	}

	f2 := &Frame{FIN: true, Opcode: OpcodeContinuation, Masked: true, MaskKey: key, Payload: applyMask(part2, key)}
	payload, opcode, complete, err := ft.Accept(f2)
	if err != nil {
		t.Fatalf("Accept f2: %v", err)
	}
	if !complete {
		t.Fatal("final fragment should be complete")
	}
	if opcode != OpcodeText {
		t.Errorf("opcode: got %d, want %d", opcode, OpcodeText)
	}
	if !bytes.Equal(payload, []byte("part1part2")) {
		t.Errorf("reassembled payload: got %q", payload)
	}
}

func TestFragmentTracker_ContinuationWithoutStart(t *testing.T) {
	ft := &FragmentTracker{}

	// A continuation frame without a preceding start frame should not complete.
	f := &Frame{FIN: true, Opcode: OpcodeContinuation, Payload: []byte("orphan")}
	_, _, complete, err := ft.Accept(f)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if complete {
		t.Error("continuation without start should not produce a complete message")
	}
}

func TestFragmentTracker_SequentialMessages(t *testing.T) {
	ft := &FragmentTracker{}

	// First complete fragmented message.
	f1 := &Frame{FIN: false, Opcode: OpcodeText, Payload: []byte("msg1-")}
	if _, _, _, err := ft.Accept(f1); err != nil {
		t.Fatalf("Accept f1: %v", err)
	}
	f2 := &Frame{FIN: true, Opcode: OpcodeContinuation, Payload: []byte("end")}
	payload, opcode, complete, err := ft.Accept(f2)
	if err != nil {
		t.Fatalf("Accept f2: %v", err)
	}
	if !complete || opcode != OpcodeText || !bytes.Equal(payload, []byte("msg1-end")) {
		t.Fatalf("first message: complete=%v, opcode=%d, payload=%q", complete, opcode, payload)
	}

	// Second unfragmented message.
	f3 := &Frame{FIN: true, Opcode: OpcodeBinary, Payload: []byte{0xFF}}
	payload, opcode, complete, err = ft.Accept(f3)
	if err != nil {
		t.Fatalf("Accept f3: %v", err)
	}
	if !complete || opcode != OpcodeBinary || !bytes.Equal(payload, []byte{0xFF}) {
		t.Fatalf("second message: complete=%v, opcode=%d, payload=%v", complete, opcode, payload)
	}
}

func TestReadFrame_EmptyPayload(t *testing.T) {
	raw := buildRawFrame(true, OpcodeText, false, [4]byte{}, nil)

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(f.Payload) != 0 {
		t.Errorf("expected empty payload, got length %d", len(f.Payload))
	}
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0x81}))
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	// Header says 10 bytes payload but only 3 are provided.
	raw := buildRawFrame(true, OpcodeText, false, [4]byte{}, []byte("1234567890"))
	truncated := raw[:len(raw)-5]

	_, err := ReadFrame(bytes.NewReader(truncated))
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

func TestWriteFrame_MultipleFrames(t *testing.T) {
	// Write two frames to the same buffer and read them back.
	var buf bytes.Buffer

	f1 := &Frame{FIN: true, Opcode: OpcodeText, Payload: []byte("first")}
	f2 := &Frame{FIN: true, Opcode: OpcodeBinary, Payload: []byte{0x01, 0x02}}

	if err := WriteFrame(&buf, f1); err != nil {
		t.Fatalf("WriteFrame f1: %v", err)
	}
	if err := WriteFrame(&buf, f2); err != nil {
		t.Fatalf("WriteFrame f2: %v", err)
	}

	r := bytes.NewReader(buf.Bytes())

	got1, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame f1: %v", err)
	}
	if got1.Opcode != OpcodeText || !bytes.Equal(got1.Payload, []byte("first")) {
		t.Errorf("f1 mismatch: opcode=%d, payload=%q", got1.Opcode, got1.Payload)
	}

	got2, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame f2: %v", err)
	}
	if got2.Opcode != OpcodeBinary || !bytes.Equal(got2.Payload, []byte{0x01, 0x02}) {
		t.Errorf("f2 mismatch: opcode=%d, payload=%v", got2.Opcode, got2.Payload)
	}
}

// --- WSProxy tests ---

// testProvider is a minimal vault.Provider for testing phantom token replacement.
type testProvider struct {
	creds map[string]string
}

func (p *testProvider) Get(name string) (vault.SecureBytes, error) {
	if v, ok := p.creds[name]; ok {
		return vault.NewSecureBytes(v), nil
	}
	return vault.SecureBytes{}, fmt.Errorf("credential %q not found", name)
}

func (p *testProvider) List() ([]string, error) {
	names := make([]string, 0, len(p.creds))
	for k := range p.creds {
		names = append(names, k)
	}
	return names, nil
}

func (p *testProvider) Name() string { return "test" }

// setupWSProxy creates a WSProxy with the given credentials, bindings, and rules.
func setupWSProxy(
	t *testing.T,
	creds map[string]string,
	bindings []vault.Binding,
	blockRules []WSBlockRuleConfig,
	redactRules []WSRedactRuleConfig,
) *WSProxy {
	t.Helper()
	provider := &testProvider{creds: creds}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)
	wp, err := NewWSProxy(provider, &resolverPtr, blockRules, redactRules)
	if err != nil {
		t.Fatal(err)
	}
	return wp
}

// writeFrameToConn writes a single WebSocket frame to a connection.
func writeFrameToConn(t *testing.T, conn net.Conn, f *Frame) {
	t.Helper()
	if err := WriteFrame(conn, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
}

// readFrameFromConn reads a single WebSocket frame from a connection.
func readFrameFromConn(t *testing.T, conn net.Conn) *Frame {
	t.Helper()
	f, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	return f
}

func TestWSProxy_PhantomTokenReplacement(t *testing.T) {
	wp := setupWSProxy(t,
		map[string]string{"api_key": "sk-real-secret-12345"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Credential:  "api_key",
		}},
		nil, nil,
	)

	// Create piped connections for agent<->proxy and proxy<->upstream.
	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "api.example.com", 443, "wss")
	}()

	// Agent sends a text frame containing a phantom token.
	phantom := PhantomToken("api_key")
	msg := `{"authorization": "` + phantom + `"}`
	sendFrame := &Frame{FIN: true, Opcode: OpcodeText}
	sendFrame.SetPayload([]byte(msg))
	writeFrameToConn(t, agentClient, sendFrame)

	// Read from upstream side: phantom should be replaced.
	received := readFrameFromConn(t, upstreamServer)
	if received.Opcode != OpcodeText {
		t.Errorf("expected text frame, got opcode %d", received.Opcode)
	}
	payload := string(received.UnmaskedPayload())
	if strings.Contains(payload, "SLUICE_PHANTOM") {
		t.Error("phantom token was not replaced in text frame")
	}
	expected := `{"authorization": "sk-real-secret-12345"}`
	if payload != expected {
		t.Errorf("payload mismatch: got %q, want %q", payload, expected)
	}

	// Clean up: close connections.
	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}

func TestWSProxy_UnboundPhantomStripped(t *testing.T) {
	// Credential exists but no binding for this destination.
	wp := setupWSProxy(t,
		map[string]string{"api_key": "sk-real-secret-12345"},
		nil, // no bindings
		nil, nil,
	)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "unbound.example.com", 443, "wss")
	}()

	phantom := PhantomToken("api_key")
	msg := `{"token": "` + phantom + `"}`
	sendFrame := &Frame{FIN: true, Opcode: OpcodeText}
	sendFrame.SetPayload([]byte(msg))
	writeFrameToConn(t, agentClient, sendFrame)

	received := readFrameFromConn(t, upstreamServer)
	payload := string(received.UnmaskedPayload())
	if strings.Contains(payload, "SLUICE_PHANTOM") {
		t.Error("unbound phantom token leaked in text frame")
	}
	// Unbound phantoms are stripped (replaced with empty), not replaced with real value.
	expected := `{"token": ""}`
	if payload != expected {
		t.Errorf("payload: got %q, want %q", payload, expected)
	}

	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}

func TestWSProxy_BinaryFramePassthrough(t *testing.T) {
	wp := setupWSProxy(t,
		map[string]string{"api_key": "sk-real-secret-12345"},
		[]vault.Binding{{
			Destination: "api.example.com",
			Credential:  "api_key",
		}},
		nil, nil,
	)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "api.example.com", 443, "wss")
	}()

	// Send binary frame with data that happens to contain the phantom prefix.
	// Binary frames should NOT be modified.
	binaryData := []byte{0x00, 0xFF, 0x01, 0xFE}
	copy(binaryData, []byte{0x00, 0xFF})
	sendFrame := &Frame{FIN: true, Opcode: OpcodeBinary}
	sendFrame.SetPayload(binaryData)
	writeFrameToConn(t, agentClient, sendFrame)

	received := readFrameFromConn(t, upstreamServer)
	if received.Opcode != OpcodeBinary {
		t.Errorf("expected binary frame, got opcode %d", received.Opcode)
	}
	if !bytes.Equal(received.UnmaskedPayload(), binaryData) {
		t.Errorf("binary payload modified: got %v, want %v", received.UnmaskedPayload(), binaryData)
	}

	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}

func TestWSProxy_ControlFramePassthrough(t *testing.T) {
	wp := setupWSProxy(t, nil, nil, nil, nil)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "example.com", 443, "wss")
	}()

	// Send ping from agent.
	pingFrame := &Frame{FIN: true, Opcode: OpcodePing, Payload: []byte("ping")}
	writeFrameToConn(t, agentClient, pingFrame)

	// Upstream should receive the ping unchanged.
	received := readFrameFromConn(t, upstreamServer)
	if received.Opcode != OpcodePing {
		t.Errorf("expected ping, got opcode %d", received.Opcode)
	}
	if !bytes.Equal(received.Payload, []byte("ping")) {
		t.Errorf("ping payload mismatch")
	}

	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}

func TestWSProxy_ContentDenyClosesConnection(t *testing.T) {
	wp := setupWSProxy(t,
		nil, nil,
		[]WSBlockRuleConfig{{
			Pattern: `(?i)password\s*[:=]\s*\S+`,
			Name:    "password in frame",
		}},
		nil,
	)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "example.com", 443, "wss")
	}()

	// Send text frame matching the block pattern.
	msg := `password: supersecret123`
	sendFrame := &Frame{FIN: true, Opcode: OpcodeText}
	sendFrame.SetPayload([]byte(msg))
	writeFrameToConn(t, agentClient, sendFrame)

	// Upstream should receive a close frame (1008 Policy Violation).
	received := readFrameFromConn(t, upstreamServer)
	if received.Opcode != OpcodeClose {
		t.Errorf("expected close frame, got opcode %d", received.Opcode)
	}
	if len(received.Payload) >= 2 {
		statusCode := binary.BigEndian.Uint16(received.Payload[:2])
		if statusCode != 1008 {
			t.Errorf("expected status 1008, got %d", statusCode)
		}
	}

	// Relay should return an error.
	err := <-relayErr
	if err == nil {
		t.Error("expected error from relay after block")
	}
	if !strings.Contains(err.Error(), "blocked by ws content deny rule") {
		t.Errorf("unexpected error: %v", err)
	}

	agentClient.Close()
	upstreamServer.Close()
}

func TestWSProxy_ContentRedactInResponse(t *testing.T) {
	wp := setupWSProxy(t,
		nil, nil, nil,
		[]WSRedactRuleConfig{{
			Pattern:     `sk-[a-zA-Z0-9_-]{20,}`,
			Replacement: "[REDACTED_API_KEY]",
			Name:        "api key in response",
		}},
	)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "example.com", 443, "wss")
	}()

	// Upstream sends a text frame containing a sensitive API key.
	msg := `{"api_key": "sk-abcdefghijklmnopqrstuvwxyz12345"}`
	sendFrame := &Frame{FIN: true, Opcode: OpcodeText}
	sendFrame.SetPayload([]byte(msg))
	writeFrameToConn(t, upstreamServer, sendFrame)

	// Agent should receive the redacted version.
	received := readFrameFromConn(t, agentClient)
	if received.Opcode != OpcodeText {
		t.Errorf("expected text frame, got opcode %d", received.Opcode)
	}
	payload := string(received.UnmaskedPayload())
	if strings.Contains(payload, "sk-abcdefghijklmnopqrstuvwxyz12345") {
		t.Error("API key was not redacted in response frame")
	}
	expected := `{"api_key": "[REDACTED_API_KEY]"}`
	if payload != expected {
		t.Errorf("payload: got %q, want %q", payload, expected)
	}

	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}

func TestWSProxy_ContentDenyDoesNotBlockNonMatching(t *testing.T) {
	wp := setupWSProxy(t,
		nil, nil,
		[]WSBlockRuleConfig{{
			Pattern: `(?i)password\s*[:=]\s*\S+`,
			Name:    "password in frame",
		}},
		nil,
	)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "example.com", 443, "wss")
	}()

	// Send innocuous text frame that should pass through.
	msg := `{"action": "list_users"}`
	sendFrame := &Frame{FIN: true, Opcode: OpcodeText}
	sendFrame.SetPayload([]byte(msg))
	writeFrameToConn(t, agentClient, sendFrame)

	// Upstream should receive the frame.
	received := readFrameFromConn(t, upstreamServer)
	if received.Opcode != OpcodeText {
		t.Errorf("expected text frame, got opcode %d", received.Opcode)
	}
	payload := string(received.UnmaskedPayload())
	if payload != msg {
		t.Errorf("payload: got %q, want %q", payload, msg)
	}

	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}

func TestWSProxy_RedactDoesNotModifyBinary(t *testing.T) {
	wp := setupWSProxy(t,
		nil, nil, nil,
		[]WSRedactRuleConfig{{
			Pattern:     `secret`,
			Replacement: "[REDACTED]",
			Name:        "redact secret",
		}},
	)

	agentClient, agentProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- wp.Relay(agentProxy, upstreamProxy, "example.com", 443, "wss")
	}()

	// Upstream sends binary frame. Even though the bytes spell "secret",
	// binary frames should not be redacted.
	binaryData := []byte("secret binary data")
	sendFrame := &Frame{FIN: true, Opcode: OpcodeBinary}
	sendFrame.SetPayload(binaryData)
	writeFrameToConn(t, upstreamServer, sendFrame)

	received := readFrameFromConn(t, agentClient)
	if received.Opcode != OpcodeBinary {
		t.Errorf("expected binary frame, got opcode %d", received.Opcode)
	}
	if !bytes.Equal(received.UnmaskedPayload(), binaryData) {
		t.Errorf("binary payload was modified by redact rule")
	}

	agentClient.Close()
	upstreamServer.Close()
	<-relayErr
}
