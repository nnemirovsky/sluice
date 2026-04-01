package proxy

import (
	"context"
	"net"
	"testing"

	"golang.org/x/net/proxy"

	"github.com/nemirovsky/sluice/internal/policy"
)

// resolveLocalhost looks up "localhost" and returns the first IP address
// as a string. Tests that exercise the FQDN resolution path use this to
// listen on the same address the proxy will connect to, making them
// portable across systems where localhost resolves to 127.0.0.1, ::1,
// or both in varying order.
func resolveLocalhost(t *testing.T) string {
	t.Helper()
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), "localhost")
	if err != nil || len(addrs) == 0 {
		t.Skip("cannot resolve localhost")
	}
	return addrs[0].IP.String()
}

func TestProxyAllowsAllowedConnection(t *testing.T) {
	// Start a simple TCP echo server
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	// Create policy that allows localhost
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Start sluice proxy
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	// Connect through SOCKS5 proxy
	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestProxyAllowsFQDNConnection(t *testing.T) {
	// Resolve localhost first so we listen on the same address the
	// proxy will connect to, regardless of address family preference.
	localhostIP := resolveLocalhost(t)

	echo, err := net.Listen("tcp", net.JoinHostPort(localhostIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	// Create policy that allows "localhost" by FQDN with default deny.
	// This exercises the DNS resolution path: the FQDN "localhost" is
	// allowed by policy, then resolved to an IP. The resolved private
	// IP must also be explicitly allowed to pass the DNS rebinding
	// guard (which blocks private IPs not independently allowed).
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "localhost"

[[allow]]
destination = "127.0.0.1"

[[allow]]
destination = "::1"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", "localhost:"+portStr)
	if err != nil {
		t.Fatalf("FQDN connection through proxy should be allowed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestProxyDeniesBlockedConnection(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "127.0.0.2:9999")
	if err == nil {
		t.Fatal("expected connection to be denied")
	}
}

func TestProxyDeniesFQDNResolvingToAskIP(t *testing.T) {
	// An allowed FQDN that resolves to an IP matching an ask rule should
	// be denied by the rebinding guard. Start a real echo server so that
	// a policy bypass would result in a successful connection, not a
	// connection refused error.
	localhostIP := resolveLocalhost(t)

	echo, err := net.Listen("tcp", net.JoinHostPort(localhostIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	// Allow localhost FQDN but mark both IPv4 and IPv6 loopback as ask.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "localhost"

[[ask]]
destination = "127.0.0.1"

[[ask]]
destination = "::1"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "localhost:"+portStr)
	if err == nil {
		t.Fatal("expected FQDN resolving to ask-listed IP to be denied")
	}
}

func TestProxyDeniesFQDNResolvingToPrivateIP(t *testing.T) {
	// An allowed FQDN that resolves to a private/loopback IP should be
	// denied unless the IP is explicitly allow-listed. This prevents
	// DNS rebinding attacks where an attacker points an allow-listed
	// domain at internal infrastructure.
	localhostIP := resolveLocalhost(t)

	echo, err := net.Listen("tcp", net.JoinHostPort(localhostIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	// Allow localhost FQDN but do NOT allow the resolved IPs.
	// The rebinding guard should block the connection.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "localhost"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "localhost:"+portStr)
	if err == nil {
		t.Fatal("expected FQDN resolving to private IP without explicit allow to be denied")
	}
}

func TestProxyAllowsFQDNToPrivateIPWithDefaultAllow(t *testing.T) {
	// With default=allow, an FQDN resolving to a private IP should be
	// allowed. The private IP is implicitly allowed by the default policy,
	// so the DNS rebinding guard should not block it.
	localhostIP := resolveLocalhost(t)

	echo, err := net.Listen("tcp", net.JoinHostPort(localhostIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", "localhost:"+portStr)
	if err != nil {
		t.Fatalf("FQDN to private IP with default=allow should succeed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestProxyDeniesAskConnection(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected ask connection to be denied")
	}
}
