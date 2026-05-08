package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestExtractHTTPHost_BasicGet(t *testing.T) {
	prefix := []byte("GET /derp/probe HTTP/1.1\r\nHost: derp10b.tailscale.com\r\nUser-Agent: tailscale\r\n\r\n")
	host, ok := extractHTTPHost(prefix)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "derp10b.tailscale.com" {
		t.Errorf("got %q, want derp10b.tailscale.com", host)
	}
}

func TestExtractHTTPHost_StripsPort(t *testing.T) {
	prefix := []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")
	host, ok := extractHTTPHost(prefix)
	if !ok || host != "example.com" {
		t.Errorf("got %q ok=%v, want example.com ok=true", host, ok)
	}
}

func TestExtractHTTPHost_IPv6WithPort(t *testing.T) {
	// IPv6 in Host header: [::1]:80. Should strip the :80, leave ::1 (no brackets).
	prefix := []byte("GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n")
	host, ok := extractHTTPHost(prefix)
	if !ok || host != "::1" {
		t.Errorf("got %q ok=%v, want ::1 ok=true", host, ok)
	}
}

func TestExtractHTTPHost_MissingHost(t *testing.T) {
	// HTTP/1.0 allowed missing Host. Should return ok=false rather than
	// silently allowing an empty hostname through to policy.
	prefix := []byte("GET / HTTP/1.0\r\n\r\n")
	host, ok := extractHTTPHost(prefix)
	if ok {
		t.Errorf("got %q ok=%v, want ok=false", host, ok)
	}
}

func TestExtractHTTPHost_BinaryGarbage(t *testing.T) {
	// Random bytes that happen to start with 'G' but are not HTTP.
	// The parser should reject and we fall back to IP-based policy.
	prefix := []byte{'G', 0x00, 0xff, 0x10, '\r', '\n', '\r', '\n'}
	host, ok := extractHTTPHost(prefix)
	if ok {
		t.Errorf("got %q ok=%v, want ok=false on garbage", host, ok)
	}
}

func TestPeekHTTPHost_FullRequest(t *testing.T) {
	body := "GET /probe HTTP/1.1\r\nHost: derp.tailscale.com\r\nAccept: */*\r\n\r\n"
	r := strings.NewReader(body)
	buf, host, err := peekHTTPHost(r, 4096)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if host != "derp.tailscale.com" {
		t.Errorf("got host %q", host)
	}
	if !bytes.Equal(buf, []byte(body)) {
		t.Errorf("buf should preserve all read bytes; got %d bytes", len(buf))
	}
}

func TestPeekHTTPHost_NotHTTP(t *testing.T) {
	// First byte is 0x16 (TLS handshake) — should bail out fast with
	// empty host, returning the buffered bytes for replay.
	r := bytes.NewReader([]byte{0x16, 0x03, 0x01, 0x00, 0x42})
	buf, host, err := peekHTTPHost(r, 4096)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if host != "" {
		t.Errorf("expected empty host on non-HTTP, got %q", host)
	}
	if len(buf) == 0 {
		t.Errorf("expected peeked bytes to be returned for replay")
	}
}

func TestPeekHTTPHost_Truncated(t *testing.T) {
	// Headers never terminate. peek should return empty host without
	// hanging once it hits EOF, with the buffered bytes for replay.
	body := "GET / HTTP/1.1\r\nHost: example.com\r\n"
	r := strings.NewReader(body)
	buf, host, err := peekHTTPHost(r, 4096)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected err: %v", err)
	}
	if host != "" {
		t.Errorf("expected empty host on truncated headers, got %q", host)
	}
	if len(buf) == 0 {
		t.Errorf("expected buffered bytes for replay")
	}
}

func TestPeekHTTPHost_RespectsMaxBytes(t *testing.T) {
	// Long Host header value that exceeds maxBytes triggers the cap.
	// peek must return without blocking even if no \r\n\r\n is found.
	long := strings.Repeat("X", 8192)
	body := "GET / HTTP/1.1\r\nHost: " + long
	r := strings.NewReader(body)
	buf, host, err := peekHTTPHost(r, 1024)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if host != "" {
		t.Errorf("expected empty host when headers exceed cap, got %q", host)
	}
	if len(buf) > 1024 {
		t.Errorf("buffer exceeded maxBytes: %d", len(buf))
	}
}
