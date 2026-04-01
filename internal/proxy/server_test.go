package proxy

import (
	"net"
	"testing"

	"golang.org/x/net/proxy"

	"github.com/nemirovsky/sluice/internal/policy"
)

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
	// Start a TCP echo server on all interfaces so it accepts both
	// IPv4 (127.0.0.1) and IPv6 (::1) connections from the proxy.
	echo, err := net.Listen("tcp", ":0")
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
	// allowed by policy, then resolved to an IP, and the resolved IP
	// must NOT be re-rejected by the default-deny fallback.
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
	echo, err := net.Listen("tcp", ":0")
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
