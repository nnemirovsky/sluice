package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
)

// autoResolveChannel is a mock channel that automatically resolves approval
// requests with a preconfigured response. Used by proxy server tests.
type autoResolveChannel struct {
	broker   *channel.Broker
	response channel.Response
}

func (c *autoResolveChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	go c.broker.Resolve(req.ID, c.response)
	return nil
}
func (c *autoResolveChannel) CancelApproval(_ string) error             { return nil }
func (c *autoResolveChannel) Commands() <-chan channel.Command           { return nil }
func (c *autoResolveChannel) Notify(_ context.Context, _ string) error  { return nil }
func (c *autoResolveChannel) Start() error                              { return nil }
func (c *autoResolveChannel) Stop()                                     {}
func (c *autoResolveChannel) Type() channel.ChannelType                 { return channel.ChannelTelegram }

// newAutoResolveBroker creates a Broker with a single mock channel that
// auto-resolves every request with the given response.
func newAutoResolveBroker(resp channel.Response) *channel.Broker {
	ch := &autoResolveChannel{response: resp}
	broker := channel.NewBroker([]channel.Channel{ch})
	ch.broker = broker
	return broker
}

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
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	// Connect through SOCKS5 proxy
	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

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
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", "localhost:"+portStr)
	if err != nil {
		t.Fatalf("FQDN connection through proxy should be allowed: %v", err)
	}
	defer func() { _ = conn.Close() }()

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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

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
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

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
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

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
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", "localhost:"+portStr)
	if err != nil {
		t.Fatalf("FQDN to private IP with default=allow should succeed: %v", err)
	}
	defer func() { _ = conn.Close() }()

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
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected ask connection to be denied")
	}
}

func TestProxyAskWithBrokerAllowOnce(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	broker := newAutoResolveBroker(channel.ResponseAllowOnce)

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("expected ask+approve to allow connection: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestProxyAskWithBrokerDeny(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	broker := newAutoResolveBroker(channel.ResponseDeny)

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected ask+deny to block connection")
	}
}

func TestProxyAskWithBrokerAlwaysAllow(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	broker := newAutoResolveBroker(channel.ResponseAlwaysAllow)

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	// First connection: goes through broker, gets "always allow"
	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("expected always-allow to permit connection: %v", err)
	}
	_ = conn.Close()

	// Wait briefly for dynamic rule to take effect
	time.Sleep(10 * time.Millisecond)

	// Second connection: should be allowed by dynamic rule without broker
	conn2, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("expected dynamic allow rule to permit second connection: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	buf := make([]byte, 5)
	n, err := conn2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestProxyAskWithBrokerTimeout(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
timeout_sec = 1

[[ask]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	broker := channel.NewBroker(nil)

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	// No one responds to the approval request, so it should timeout
	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected timeout to deny connection")
	}
}

func TestGracefulShutdownDrainsInFlight(t *testing.T) {
	// Start a slow echo server that holds connections open briefly.
	slowEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slowEcho.Close() }()
	go func() {
		for {
			conn, err := slowEcho.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				time.Sleep(200 * time.Millisecond)
				_, _ = c.Write([]byte("done"))
			}(conn)
		}
	}()

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
	go func() { _ = srv.ListenAndServe() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	// Establish an in-flight connection through the proxy.
	conn, err := dialer.Dial("tcp", slowEcho.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}

	// Start graceful shutdown while the connection is still in-flight.
	// Use a generous timeout so the slow echo server has time to respond.
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- srv.GracefulShutdown(5 * time.Second)
	}()

	// Read the response from the slow echo server. This should complete
	// before the shutdown timeout.
	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read from in-flight connection: %v", err)
	}
	if string(buf[:n]) != "done" {
		t.Errorf("expected 'done', got %q", string(buf[:n]))
	}
	_ = conn.Close()

	// Shutdown should complete without timeout error.
	if err := <-shutdownDone; err != nil {
		t.Errorf("graceful shutdown should succeed after connections drain: %v", err)
	}
}

func TestGracefulShutdownTimesOut(t *testing.T) {
	// Start a server that holds connections forever (until closed).
	hangForever, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hangForever.Close() }()
	go func() {
		for {
			conn, err := hangForever.Accept()
			if err != nil {
				return
			}
			// Hold open until the test cleans up.
			go func(c net.Conn) {
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_ = c.Close()
			}(conn)
		}
	}()

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
	go func() { _ = srv.ListenAndServe() }()

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	// Establish an in-flight connection that will never complete.
	conn, err := dialer.Dial("tcp", hangForever.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Graceful shutdown with a very short timeout should fail.
	err = srv.GracefulShutdown(50 * time.Millisecond)
	if err == nil {
		t.Error("expected timeout error from graceful shutdown")
	}
}

func TestGracefulShutdownRejectsNewConnections(t *testing.T) {
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
	go func() { _ = srv.ListenAndServe() }()

	addr := srv.Addr()

	// Shut down the server.
	if err := srv.GracefulShutdown(time.Second); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// New connections should be rejected.
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialer.Dial("tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected connection to be rejected after shutdown")
	}
}
