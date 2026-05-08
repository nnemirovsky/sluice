package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
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

func TestExtractHTTPHost_UnbracketedIPv6(t *testing.T) {
	// Bare IPv6 without brackets is invalid per RFC but seen in the
	// wild. The previous LastIndex(":") logic chopped the final
	// hextet as if it were a port. SplitHostPort errors on this
	// shape, so the original host should pass through unmodified.
	prefix := []byte("GET / HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n")
	host, ok := extractHTTPHost(prefix)
	if !ok || host != "2001:db8::1" {
		t.Errorf("got %q ok=%v, want 2001:db8::1 ok=true (bare IPv6 must not be truncated)", host, ok)
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

func TestAttestHostFromCache_Match(t *testing.T) {
	// Cache populated by a prior agent DNS query: derp.tailscale.com
	// resolved to 192.0.2.10. Subsequent Host: derp.tailscale.com
	// arriving on a SOCKS5 CONNECT to 192.0.2.10 is attested without
	// any further DNS work.
	di := NewDNSInterceptor(nil, nil, "")
	di.StoreReverse("192.0.2.10", "derp.tailscale.com")
	s := &Server{dnsInterceptor: di}
	if !s.attestHostFromCache("derp.tailscale.com", net.ParseIP("192.0.2.10")) {
		t.Fatal("cache hit should attest")
	}
}

func TestAttestHostFromCache_DifferentHost(t *testing.T) {
	// Cache says 192.0.2.10 -> attacker.example.com. A claim of
	// Host: bank.example.com on that IP must NOT be attested off
	// the cache, even though the IP is in the cache.
	di := NewDNSInterceptor(nil, nil, "")
	di.StoreReverse("192.0.2.10", "attacker.example.com")
	s := &Server{dnsInterceptor: di}
	if s.attestHostFromCache("bank.example.com", net.ParseIP("192.0.2.10")) {
		t.Fatal("cache hit for a different host must not attest a different-Host claim")
	}
}

func TestAttestHostFromCache_NilInputs(t *testing.T) {
	s := &Server{dnsInterceptor: NewDNSInterceptor(nil, nil, "")}
	if s.attestHostFromCache("", net.ParseIP("1.2.3.4")) {
		t.Error("empty host must not attest")
	}
	if s.attestHostFromCache("example.com", nil) {
		t.Error("nil dest IP must not attest")
	}
	emptyServer := &Server{}
	if emptyServer.attestHostFromCache("example.com", net.ParseIP("1.2.3.4")) {
		t.Error("nil DNS interceptor must not attest")
	}
}

// stubLookup returns a canned result regardless of the host. Used to
// exercise hostResolvesToIP without performing any real DNS queries.
func stubLookup(ips ...string) func(context.Context, string, string) ([]net.IP, error) {
	out := make([]net.IP, len(ips))
	for i, s := range ips {
		out[i] = net.ParseIP(s)
	}
	return func(_ context.Context, _, _ string) ([]net.IP, error) {
		return out, nil
	}
}

func TestHostResolvesToIP_LookupMatch(t *testing.T) {
	// Cache empty, stubbed resolver returns the dest IP among the
	// answers. Should be attested.
	s := &Server{
		dnsInterceptor: NewDNSInterceptor(nil, nil, ""),
		lookupIP:       stubLookup("203.0.113.5", "192.0.2.10"),
	}
	if !s.hostResolvesToIP(context.Background(), "good.example.com", net.ParseIP("192.0.2.10")) {
		t.Fatal("forward-lookup match should attest")
	}
}

func TestHostResolvesToIP_LookupMismatch(t *testing.T) {
	// Stub returns a result set that does NOT include the dest IP.
	// Spoofing claim — must not attest.
	s := &Server{
		dnsInterceptor: NewDNSInterceptor(nil, nil, ""),
		lookupIP:       stubLookup("203.0.113.5"),
	}
	if s.hostResolvesToIP(context.Background(), "spoof.example.com", net.ParseIP("192.0.2.10")) {
		t.Fatal("forward-lookup mismatch must not attest")
	}
}

func TestHostResolvesToIP_LookupError(t *testing.T) {
	// Resolver returns an error (NXDOMAIN, timeout, etc). Treated
	// as deny-equivalent — sluice cannot tell a transient failure
	// from a poisoned resolver, so the strict default applies.
	errResolver := func(_ context.Context, _, _ string) ([]net.IP, error) {
		return nil, net.UnknownNetworkError("test stub error")
	}
	s := &Server{
		dnsInterceptor: NewDNSInterceptor(nil, nil, ""),
		lookupIP:       errResolver,
	}
	if s.hostResolvesToIP(context.Background(), "example.com", net.ParseIP("192.0.2.10")) {
		t.Fatal("lookup error must not attest")
	}
}
