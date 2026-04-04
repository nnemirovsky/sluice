package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sort"
	"sync/atomic"

	"github.com/nemirovsky/sluice/internal/vault"
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

// wsBlockRule is a compiled content deny rule for WebSocket frames.
type wsBlockRule struct {
	re   *regexp.Regexp
	name string
}

// wsRedactRule is a compiled content redact rule for WebSocket frames.
type wsRedactRule struct {
	re          *regexp.Regexp
	replacement string
	name        string
}

// WSBlockRuleConfig defines a content deny rule for WSProxy construction.
type WSBlockRuleConfig struct {
	Pattern string
	Name    string
}

// WSRedactRuleConfig defines a content redact rule for WSProxy construction.
type WSRedactRuleConfig struct {
	Pattern     string
	Replacement string
	Name        string
}

// WSProxy relays WebSocket frames bidirectionally between agent and upstream
// connections. Text frames are inspected for phantom tokens (agent->upstream)
// and content policy rules. Binary and control frames pass through unchanged.
type WSProxy struct {
	provider    vault.Provider
	resolver    *atomic.Pointer[vault.BindingResolver]
	blockRules  []wsBlockRule
	redactRules []wsRedactRule
}

// NewWSProxy creates a WebSocket proxy with the given credential provider,
// binding resolver, and content inspection rules. Block rules with matching
// patterns cause the connection to close. Redact rules sanitize content in
// frames sent from upstream to the agent.
func NewWSProxy(
	provider vault.Provider,
	resolver *atomic.Pointer[vault.BindingResolver],
	blockConfigs []WSBlockRuleConfig,
	redactConfigs []WSRedactRuleConfig,
) (*WSProxy, error) {
	wp := &WSProxy{
		provider: provider,
		resolver: resolver,
	}
	for _, cfg := range blockConfigs {
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile ws block pattern %q: %w", cfg.Name, err)
		}
		wp.blockRules = append(wp.blockRules, wsBlockRule{re: re, name: cfg.Name})
	}
	for _, cfg := range redactConfigs {
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile ws redact pattern %q: %w", cfg.Name, err)
		}
		wp.redactRules = append(wp.redactRules, wsRedactRule{re: re, replacement: cfg.Replacement, name: cfg.Name})
	}
	return wp, nil
}

// phantomPair holds a phantom token and its corresponding real credential.
type phantomPair struct {
	phantom []byte
	secret  vault.SecureBytes
}

// Relay runs bidirectional WebSocket frame forwarding between agent and
// upstream connections. It blocks until one side closes or an error occurs.
// The host, port, and proto parameters identify the upstream destination for
// credential binding resolution.
func (wp *WSProxy) Relay(agentConn, upstreamConn net.Conn, host string, port int, proto string) error {
	// Build phantom token pairs for credentials bound to this destination.
	var pairs []phantomPair
	if res := wp.resolver.Load(); res != nil {
		for _, name := range res.CredentialsForDestination(host, port, proto) {
			secret, err := wp.provider.Get(name)
			if err != nil {
				log.Printf("[WS] credential %q lookup failed: %v", name, err)
				continue
			}
			pairs = append(pairs, phantomPair{
				phantom: []byte(PhantomToken(name)),
				secret:  secret,
			})
		}
	}
	// Sort by phantom length descending so longer tokens are replaced before
	// shorter prefixes that could corrupt them via substring match.
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].phantom) > len(pairs[j].phantom)
	})
	defer func() {
		for i := range pairs {
			pairs[i].secret.Release()
		}
	}()

	errc := make(chan error, 2)

	// Agent -> Upstream: phantom replacement + block check.
	go func() {
		errc <- wp.relayFrames(agentConn, upstreamConn, pairs, true)
	}()

	// Upstream -> Agent: redact rules.
	go func() {
		errc <- wp.relayFrames(upstreamConn, agentConn, nil, false)
	}()

	// Wait for the first direction to finish (close or error).
	err := <-errc
	agentConn.Close()
	upstreamConn.Close()
	<-errc // drain the second goroutine

	return err
}

// relayFrames reads frames from src and writes them to dst. When
// agentToUpstream is true, phantom tokens in text frames are replaced with
// real credentials and block rules are checked. When false, redact rules
// are applied to text frames (upstream->agent direction).
func (wp *WSProxy) relayFrames(src io.Reader, dst io.Writer, pairs []phantomPair, agentToUpstream bool) error {
	ft := &FragmentTracker{}
	for {
		frame, err := ReadFrame(src)
		if err != nil {
			return err
		}

		// Control frames: forward immediately.
		if frame.IsControl() {
			if writeErr := WriteFrame(dst, frame); writeErr != nil {
				return writeErr
			}
			if frame.Opcode == OpcodeClose {
				return nil
			}
			continue
		}

		// Feed data frames to the fragment tracker.
		payload, opcode, complete := ft.Accept(frame)
		if !complete {
			continue
		}

		// Binary frames: passthrough without modification.
		if opcode == OpcodeBinary {
			out := &Frame{FIN: true, Opcode: OpcodeBinary}
			out.SetPayload(payload)
			if writeErr := WriteFrame(dst, out); writeErr != nil {
				return writeErr
			}
			continue
		}

		// Text frames: apply direction-specific transformations.
		if opcode == OpcodeText {
			if agentToUpstream {
				// Check block rules before phantom replacement.
				for _, rule := range wp.blockRules {
					if rule.re.Match(payload) {
						sendCloseFrame(dst, 1008, "blocked by content policy")
						return fmt.Errorf("blocked by ws content deny rule %q", rule.name)
					}
				}

				// Replace bound phantom tokens with real credentials.
				for _, p := range pairs {
					if bytes.Contains(payload, p.phantom) {
						payload = bytes.ReplaceAll(payload, p.phantom, p.secret.Bytes())
					}
				}

				// Strip any remaining unbound phantom tokens.
				if bytes.Contains(payload, phantomPrefix) {
					payload = wp.stripUnboundPhantoms(payload)
					log.Printf("[WS] stripped unbound phantom token from text frame")
				}
			} else {
				// Upstream -> Agent: apply redact rules.
				text := string(payload)
				for _, rule := range wp.redactRules {
					text = rule.re.ReplaceAllString(text, rule.replacement)
				}
				payload = []byte(text)
			}

			out := &Frame{FIN: true, Opcode: OpcodeText}
			out.SetPayload(payload)
			if writeErr := WriteFrame(dst, out); writeErr != nil {
				return writeErr
			}
		}
	}
}

// stripUnboundPhantoms removes phantom tokens from data that are not bound
// to the current destination. Uses exact matching via provider.List() first,
// then falls back to regex for remaining tokens.
func (wp *WSProxy) stripUnboundPhantoms(data []byte) []byte {
	names, _ := wp.provider.List()
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j])
	})
	for _, name := range names {
		phantom := []byte(PhantomToken(name))
		if bytes.Contains(data, phantom) {
			data = bytes.ReplaceAll(data, phantom, nil)
		}
	}
	if bytes.Contains(data, phantomPrefix) {
		data = phantomStripRe.ReplaceAll(data, nil)
	}
	return data
}

// sendCloseFrame writes a WebSocket close frame with the given status code
// and reason text. Control frame payloads are limited to 125 bytes per RFC 6455.
func sendCloseFrame(w io.Writer, statusCode uint16, reason string) {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, statusCode)
	copy(payload[2:], reason)
	if len(payload) > 125 {
		payload = payload[:125]
	}
	frame := &Frame{
		FIN:     true,
		Opcode:  OpcodeClose,
		Payload: payload,
	}
	_ = WriteFrame(w, frame)
}
