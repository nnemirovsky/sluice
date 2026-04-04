package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// WebSocket opcodes per RFC 6455 Section 5.2.
const (
	OpcodeContinuation byte = 0x0
	OpcodeText         byte = 0x1
	OpcodeBinary       byte = 0x2
	OpcodeClose        byte = 0x8
	OpcodePing         byte = 0x9
	OpcodePong         byte = 0xA
)

// maxFramePayload limits the payload size we are willing to read to prevent
// memory exhaustion from a malicious frame header. 16 MiB is generous for
// typical agent traffic.
const maxFramePayload = 16 << 20

// Frame represents a single WebSocket frame per RFC 6455 Section 5.2.
type Frame struct {
	FIN     bool
	Opcode  byte
	Masked  bool
	MaskKey [4]byte
	Payload []byte
}

// IsControl returns true for control frames (close, ping, pong).
// Control frames have opcodes >= 0x8.
func (f *Frame) IsControl() bool {
	return f.Opcode >= 0x8
}

// UnmaskedPayload returns the payload with the XOR mask removed.
// If the frame is not masked the payload is returned as-is.
func (f *Frame) UnmaskedPayload() []byte {
	if !f.Masked {
		out := make([]byte, len(f.Payload))
		copy(out, f.Payload)
		return out
	}
	out := make([]byte, len(f.Payload))
	for i, b := range f.Payload {
		out[i] = b ^ f.MaskKey[i%4]
	}
	return out
}

// SetPayload updates the payload data. If the frame was originally masked
// the new data is re-masked with the same key.
func (f *Frame) SetPayload(data []byte) {
	if f.Masked {
		masked := make([]byte, len(data))
		for i, b := range data {
			masked[i] = b ^ f.MaskKey[i%4]
		}
		f.Payload = masked
	} else {
		out := make([]byte, len(data))
		copy(out, data)
		f.Payload = out
	}
}

// ReadFrame reads a single WebSocket frame from r according to the wire
// format defined in RFC 6455 Section 5.2.
func ReadFrame(r io.Reader) (*Frame, error) {
	// First two bytes are always present: FIN/RSV/opcode and MASK/payload length.
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}

	f := &Frame{
		FIN:    hdr[0]&0x80 != 0,
		Opcode: hdr[0] & 0x0F,
		Masked: hdr[1]&0x80 != 0,
	}

	// Payload length: 7-bit, 16-bit, or 64-bit extended.
	payloadLen := uint64(hdr[1] & 0x7F)
	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, fmt.Errorf("read 16-bit payload length: %w", err)
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, fmt.Errorf("read 64-bit payload length: %w", err)
		}
		payloadLen = binary.BigEndian.Uint64(ext[:])
		// MSB must be 0 per RFC 6455 Section 5.2.
		if payloadLen>>63 != 0 {
			return nil, errors.New("invalid 64-bit payload length: MSB set")
		}
	}

	if payloadLen > maxFramePayload {
		return nil, fmt.Errorf("payload length %d exceeds maximum %d", payloadLen, maxFramePayload)
	}

	// Masking key (4 bytes, only if masked).
	if f.Masked {
		if _, err := io.ReadFull(r, f.MaskKey[:]); err != nil {
			return nil, fmt.Errorf("read mask key: %w", err)
		}
	}

	// Payload data.
	f.Payload = make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return f, nil
}

// WriteFrame serializes a WebSocket frame to w in the RFC 6455 wire format.
func WriteFrame(w io.Writer, f *Frame) error {
	// Calculate the total header size to write in a single call.
	headerSize := 2
	payloadLen := len(f.Payload)

	var lenBytes int
	switch {
	case payloadLen <= 125:
		lenBytes = 0
	case payloadLen <= 0xFFFF:
		lenBytes = 2
	default:
		lenBytes = 8
	}
	headerSize += lenBytes
	if f.Masked {
		headerSize += 4
	}

	buf := make([]byte, headerSize)
	pos := 0

	// Byte 0: FIN + opcode.
	var b0 byte
	if f.FIN {
		b0 |= 0x80
	}
	b0 |= f.Opcode & 0x0F
	buf[pos] = b0
	pos++

	// Byte 1: MASK + payload length.
	var b1 byte
	if f.Masked {
		b1 |= 0x80
	}
	switch {
	case payloadLen <= 125:
		b1 |= byte(payloadLen)
	case payloadLen <= 0xFFFF:
		b1 |= 126
	default:
		b1 |= 127
	}
	buf[pos] = b1
	pos++

	// Extended payload length.
	switch lenBytes {
	case 2:
		binary.BigEndian.PutUint16(buf[pos:], uint16(payloadLen))
		pos += 2
	case 8:
		binary.BigEndian.PutUint64(buf[pos:], uint64(payloadLen))
		pos += 8
	}

	// Mask key.
	if f.Masked {
		copy(buf[pos:], f.MaskKey[:])
	}

	// Write header + payload.
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if payloadLen > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}

	return nil
}

// FragmentTracker reassembles fragmented WebSocket messages.
// A fragmented message starts with a frame where FIN=false and opcode != 0,
// continues with zero or more continuation frames (opcode=0, FIN=false), and
// ends with a continuation frame with FIN=true.
type FragmentTracker struct {
	active      bool
	startOpcode byte
	fragments   [][]byte
}

// Accept processes an incoming frame. It returns the reassembled unmasked
// payload and the original opcode when a complete message is available.
// For unfragmented messages (FIN=true, opcode != 0) it returns the payload
// immediately. For fragments it buffers until the final frame arrives.
// Control frames are never fragmented per RFC 6455 Section 5.4. The caller
// should handle control frames separately before calling Accept.
//
// Returns (payload, opcode, complete). When complete is false the frame was
// buffered and the caller should not process the payload.
func (ft *FragmentTracker) Accept(f *Frame) ([]byte, byte, bool) {
	payload := f.UnmaskedPayload()

	// Non-fragmented message: FIN=true and opcode is not continuation.
	if f.FIN && f.Opcode != OpcodeContinuation {
		return payload, f.Opcode, true
	}

	// Start of fragmented message.
	if !f.FIN && f.Opcode != OpcodeContinuation {
		ft.active = true
		ft.startOpcode = f.Opcode
		ft.fragments = [][]byte{payload}
		return nil, 0, false
	}

	// Continuation frame without an active fragment sequence is invalid.
	if !ft.active {
		return nil, 0, false
	}

	ft.fragments = append(ft.fragments, payload)

	// Final continuation frame.
	if f.FIN {
		total := 0
		for _, frag := range ft.fragments {
			total += len(frag)
		}
		assembled := make([]byte, 0, total)
		for _, frag := range ft.fragments {
			assembled = append(assembled, frag...)
		}
		opcode := ft.startOpcode
		ft.active = false
		ft.fragments = nil
		return assembled, opcode, true
	}

	return nil, 0, false
}
