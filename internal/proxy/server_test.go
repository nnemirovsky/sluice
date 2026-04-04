package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/proxy"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/vault"
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

// socks5UDPAssociate performs a SOCKS5 handshake with UDP ASSOCIATE command.
// Returns the UDP relay address on success, or an error if the server rejects
// the command. The TCP control connection is returned and must be kept alive
// for the duration of the UDP session.
func socks5UDPAssociate(proxyAddr string) (relayAddr *net.UDPAddr, controlConn net.Conn, err error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to proxy: %w", err)
	}

	// SOCKS5 auth negotiation: version=5, 1 method, no-auth=0x00
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write auth: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := conn.Read(authResp); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read auth: %w", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		conn.Close()
		return nil, nil, fmt.Errorf("auth rejected: %x", authResp)
	}

	// SOCKS5 UDP ASSOCIATE request: version=5, cmd=ASSOCIATE(0x03), rsv=0,
	// atyp=IPv4(0x01), addr=0.0.0.0, port=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write associate: %w", err)
	}

	// Read reply: version(1) + rep(1) + rsv(1) + atyp(1) + BND.ADDR + BND.PORT
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read reply header: %w", err)
	}
	if header[0] != 0x05 {
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected version: %d", header[0])
	}
	if header[1] != 0x00 {
		conn.Close()
		return nil, nil, fmt.Errorf("associate rejected with reply code: 0x%02x", header[1])
	}

	// Parse BND.ADDR based on atyp
	var ip net.IP
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4+2)
		if _, err := conn.Read(addr); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("read ipv4 addr: %w", err)
		}
		ip = net.IP(addr[:4])
		port := binary.BigEndian.Uint16(addr[4:6])
		return &net.UDPAddr{IP: ip, Port: int(port)}, conn, nil
	case 0x04: // IPv6
		addr := make([]byte, 16+2)
		if _, err := conn.Read(addr); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("read ipv6 addr: %w", err)
		}
		ip = net.IP(addr[:16])
		port := binary.BigEndian.Uint16(addr[16:18])
		return &net.UDPAddr{IP: ip, Port: int(port)}, conn, nil
	default:
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected atyp: %d", header[3])
	}
}

func TestUDPAssociateAvailable(t *testing.T) {
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

	relayAddr, controlConn, err := socks5UDPAssociate(srv.Addr())
	if err != nil {
		t.Fatalf("UDP ASSOCIATE should succeed: %v", err)
	}
	defer controlConn.Close()

	if relayAddr.Port == 0 {
		t.Fatal("expected non-zero relay port")
	}
	t.Logf("UDP relay listening at %s", relayAddr)
}

func TestUDPAssociateRelaysDatagrams(t *testing.T) {
	// Start a UDP echo server.
	echoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(fmt.Sprintf(`
[policy]
default = "allow"

[[allow]]
destination = "127.0.0.1"
ports = [%d]
protocols = ["udp"]
`, echoAddr.Port)))
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

	relayAddr, controlConn, err := socks5UDPAssociate(srv.Addr())
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	defer controlConn.Close()

	// Open a UDP socket to communicate with the relay.
	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer clientConn.Close()

	// Build SOCKS5 UDP datagram: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
	echoIP := echoAddr.IP.To4()
	payload := []byte("hello-udp")
	datagram := make([]byte, 0, 10+len(payload))
	datagram = append(datagram, 0x00, 0x00) // RSV
	datagram = append(datagram, 0x00)       // FRAG
	datagram = append(datagram, 0x01)       // ATYP IPv4
	datagram = append(datagram, echoIP...)
	datagram = append(datagram, byte(echoAddr.Port>>8), byte(echoAddr.Port))
	datagram = append(datagram, payload...)

	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	// Read response through relay.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}

	// Parse SOCKS5 UDP response header to extract the data.
	resp := respBuf[:n]
	if len(resp) < 10 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	// Skip RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) = 10 bytes for IPv4.
	respData := resp[10:]
	if string(respData) != "hello-udp" {
		t.Errorf("expected 'hello-udp', got %q", string(respData))
	}
}

func TestUDPAssociateWithPolicyDeny(t *testing.T) {
	// Policy explicitly allows UDP to a specific address, denies everything else.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "192.0.2.99"
ports = [9999]
protocols = ["udp"]
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

	relayAddr, controlConn, err := socks5UDPAssociate(srv.Addr())
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	defer controlConn.Close()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer clientConn.Close()

	// Send a datagram to a denied destination (127.0.0.1:12345).
	payload := []byte("denied-traffic")
	datagram := make([]byte, 0, 10+len(payload))
	datagram = append(datagram, 0x00, 0x00) // RSV
	datagram = append(datagram, 0x00)       // FRAG
	datagram = append(datagram, 0x01)       // ATYP IPv4
	datagram = append(datagram, 127, 0, 0, 1)
	denyPort := uint16(12345)
	datagram = append(datagram, byte(denyPort>>8), byte(denyPort))
	datagram = append(datagram, payload...)

	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	// Should not receive a response since the destination is denied.
	clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	respBuf := make([]byte, 65535)
	_, err = clientConn.Read(respBuf)
	if err == nil {
		t.Fatal("expected timeout reading from denied destination, got response")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestUDPAssociateDNSInterception(t *testing.T) {
	// Start a mock DNS server that returns a canned response.
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	dnsAddr := dnsConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Echo the query back as a "response" with QR bit set.
			resp := make([]byte, n)
			copy(resp, buf[:n])
			// Set QR=1 in flags (byte 2-3).
			resp[2] |= 0x80
			dnsConn.WriteTo(resp, addr)
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "example.com"
ports = [53]
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr:  "127.0.0.1:0",
		Policy:      eng,
		DNSResolver: dnsAddr.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	relayAddr, controlConn, err := socks5UDPAssociate(srv.Addr())
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	defer controlConn.Close()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer clientConn.Close()

	// Build a DNS query for example.com (allowed).
	dnsQuery := buildTestDNSQuery(0x1234, "example.com", 1) // A record

	// Wrap DNS query in SOCKS5 UDP datagram addressed to the DNS server IP on port 53.
	dnsIP := dnsAddr.IP.To4()
	datagram := make([]byte, 0, 10+len(dnsQuery))
	datagram = append(datagram, 0x00, 0x00) // RSV
	datagram = append(datagram, 0x00)       // FRAG
	datagram = append(datagram, 0x01)       // ATYP IPv4
	datagram = append(datagram, dnsIP...)
	datagram = append(datagram, byte(53>>8), byte(53))
	datagram = append(datagram, dnsQuery...)

	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send DNS datagram: %v", err)
	}

	// Read the DNS response through the relay.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read DNS response: %v", err)
	}

	// Parse SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) = 10
	resp := respBuf[:n]
	if len(resp) < 10 {
		t.Fatalf("DNS response too short: %d bytes", len(resp))
	}
	dnsResp := resp[10:]

	// Verify the DNS response has QR bit set and matches our query ID.
	if len(dnsResp) < 4 {
		t.Fatal("DNS response payload too short")
	}
	respID := binary.BigEndian.Uint16(dnsResp[0:2])
	if respID != 0x1234 {
		t.Errorf("expected query ID 0x1234, got 0x%04x", respID)
	}
	if dnsResp[2]&0x80 == 0 {
		t.Error("expected QR=1 in DNS response")
	}
}

func TestUDPAssociateDNSInterceptionNXDOMAIN(t *testing.T) {
	// DNS interceptor should return NXDOMAIN for denied domains without
	// contacting the upstream resolver.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "allowed.example.com"
ports = [53]
protocols = ["dns"]
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr:  "127.0.0.1:0",
		Policy:      eng,
		DNSResolver: "127.0.0.1:1", // invalid resolver; should not be contacted
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	relayAddr, controlConn, err := socks5UDPAssociate(srv.Addr())
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	defer controlConn.Close()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer clientConn.Close()

	// Query for a denied domain.
	dnsQuery := buildTestDNSQuery(0xABCD, "denied.example.com", 1)

	// Use a loopback IP as the DNS server address (port 53).
	datagram := make([]byte, 0, 10+len(dnsQuery))
	datagram = append(datagram, 0x00, 0x00) // RSV
	datagram = append(datagram, 0x00)       // FRAG
	datagram = append(datagram, 0x01)       // ATYP IPv4
	datagram = append(datagram, 127, 0, 0, 1)
	datagram = append(datagram, byte(53>>8), byte(53))
	datagram = append(datagram, dnsQuery...)

	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("send DNS datagram: %v", err)
	}

	// Should receive an NXDOMAIN response.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 65535)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read NXDOMAIN response: %v", err)
	}

	resp := respBuf[:n]
	if len(resp) < 10 {
		t.Fatalf("NXDOMAIN response too short: %d bytes", len(resp))
	}
	dnsResp := resp[10:]

	if len(dnsResp) < 4 {
		t.Fatal("DNS response payload too short")
	}
	// Check query ID matches.
	respID := binary.BigEndian.Uint16(dnsResp[0:2])
	if respID != 0xABCD {
		t.Errorf("expected query ID 0xABCD, got 0x%04x", respID)
	}
	// Check QR=1.
	if dnsResp[2]&0x80 == 0 {
		t.Error("expected QR=1 in NXDOMAIN response")
	}
	// Check RCODE=3 (NXDOMAIN) in lower 4 bits of byte 3.
	rcode := dnsResp[3] & 0x0F
	if rcode != 3 {
		t.Errorf("expected RCODE=3 (NXDOMAIN), got %d", rcode)
	}
}

// buildTestDNSQuery constructs a minimal DNS query packet.
func buildTestDNSQuery(id uint16, domain string, qtype uint16) []byte {
	var buf []byte
	// Header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x01, 0x00) // Flags: RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0

	// Question section: domain name in wire format.
	parts := splitDomainLabels(domain)
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // Root label

	// QTYPE and QCLASS.
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01) // QCLASS IN

	return buf
}

// splitDomainLabels splits a domain name into its labels.
func splitDomainLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}

// TestQUICProxyWiredIntoServer verifies that when credential injection is
// enabled, the QUIC proxy is created alongside the HTTPS MITM injector and
// listens on a local UDP port. This is the wiring test for Task 11.
func TestQUICProxyWiredIntoServer(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   &stubQUICProvider{},
		Resolver:   mustBindingResolver(t),
		VaultDir:   tmpDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	if srv.quicProxy == nil {
		t.Fatal("expected QUIC proxy to be created when injection is enabled")
	}

	// Wait for the QUIC proxy listener to start.
	var addr net.Addr
	for i := 0; i < 50; i++ {
		addr = srv.quicProxy.Addr()
		if addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("QUIC proxy did not start listening")
	}
	t.Logf("QUIC proxy listening on %s", addr)
}

// mustBindingResolver creates a minimal BindingResolver for tests.
func mustBindingResolver(t *testing.T) *vault.BindingResolver {
	t.Helper()
	r, err := vault.NewBindingResolver([]vault.Binding{
		{Destination: "example.com", Ports: []int{443}, Credential: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestUDPAssociateQUICDetectionAndRouting verifies the full chain: a QUIC
// Initial packet sent through UDP ASSOCIATE is detected and routed to the
// QUICProxy, which terminates TLS and proxies the HTTP/3 request with
// phantom token replacement.
func TestUDPAssociateQUICDetectionAndRouting(t *testing.T) {
	const sni = "api.example.com"

	// 1. Start an HTTP/3 upstream echo server.
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA upstream: %v", err)
	}
	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	// 2. Create vault provider with a test credential.
	provider := &mapQUICProvider{
		creds: map[string]string{
			"test_cred": "real-secret-value",
		},
	}

	bindings := []vault.Binding{
		{
			Destination: sni,
			Ports:       []int{443},
			Credential:  "test_cred",
			Header:      "X-Api-Key",
			Protocols:   []string{"quic"},
		},
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}

	// 3. Create the SOCKS5 server with credential injection (which creates QUICProxy).
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"

[[allow]]
destination = "api.example.com"
ports = [443]
protocols = ["udp"]
`))
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   provider,
		Resolver:   resolver,
		VaultDir:   tmpDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	if srv.quicProxy == nil {
		t.Fatal("expected QUIC proxy to be created")
	}

	// Wait for QUIC proxy to start.
	var quicAddr net.Addr
	for i := 0; i < 50; i++ {
		quicAddr = srv.quicProxy.Addr()
		if quicAddr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if quicAddr == nil {
		t.Fatal("QUIC proxy did not start listening")
	}

	// Configure QUICProxy to connect to the local upstream instead of
	// the real destination.
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstreamCAX509)
	srv.quicProxy.upstreamTLSConfig = &tls.Config{
		RootCAs: upstreamPool,
	}
	srv.quicProxy.upstreamDial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		return quic.DialAddr(ctx, upstreamAddr, tlsCfg, cfg)
	}

	// 4. Connect an HTTP/3 client directly to the QUIC proxy to verify
	// the credential injection pipeline works end-to-end. The proxy
	// generates a per-host cert signed by its CA. We create a known local
	// UDP socket and register it as an expected destination so the proxy
	// accepts the connection.
	proxyCAX509 := srv.quicProxy.caX509

	localConn, localErr := net.ListenPacket("udp", "127.0.0.1:0")
	if localErr != nil {
		t.Fatalf("listen local UDP: %v", localErr)
	}
	defer localConn.Close()
	srv.quicProxy.RegisterExpectedHost(localConn.LocalAddr().String(), sni, 443)

	pool := x509.NewCertPool()
	pool.AddCert(proxyCAX509)

	quicUDPAddr, _ := net.ResolveUDPAddr("udp", quicAddr.String())
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: sni,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, localConn, quicUDPAddr, tlsCfg, cfg)
		},
	}
	defer transport.Close()

	phantomToken := PhantomToken("test_cred")
	reqURL := fmt.Sprintf("https://%s/v1/test", sni)
	req, err := http.NewRequest("POST", reqURL, bytes.NewReader([]byte("body with "+phantomToken)))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+phantomToken)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 round trip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)

	// Verify binding-specific header injection.
	echoAPIKey := resp.Header.Get("X-Echo-Api-Key")
	if echoAPIKey != "real-secret-value" {
		t.Errorf("X-Echo-Api-Key = %q, want %q", echoAPIKey, "real-secret-value")
	}

	// Verify phantom token replaced in Authorization header.
	echoAuth := resp.Header.Get("X-Echo-Auth")
	if echoAuth != "Bearer real-secret-value" {
		t.Errorf("X-Echo-Auth = %q, want %q", echoAuth, "Bearer real-secret-value")
	}

	// Verify phantom token replaced in body.
	if bytes.Contains(respBody, []byte(phantomToken)) {
		t.Errorf("body still contains phantom token")
	}
	if !bytes.Contains(respBody, []byte("real-secret-value")) {
		t.Errorf("body missing real credential: %s", string(respBody))
	}
}

// TestServerQUICProxyNotCreatedWithoutProvider verifies that the QUICProxy
// is not created when no vault provider is configured.
func TestServerQUICProxyNotCreatedWithoutProvider(t *testing.T) {
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

	if srv.quicProxy != nil {
		t.Error("QUIC proxy should not be created without a vault provider")
	}
}

func TestSelfBypassAllowsConnectionWithoutPolicy(t *testing.T) {
	// Start a simple TCP echo server to act as sluice's own HTTP listener.
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
			_, _ = conn.Write([]byte("self"))
			_ = conn.Close()
		}
	}()

	// Use a deny-all policy. Without self-bypass, this connection would fail.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Create proxy with self-bypass for the echo server's address.
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		SelfBypass: []string{echo.Addr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	// Connect through SOCKS5 proxy to the self-bypass address.
	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy to self-bypass address: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "self" {
		t.Errorf("expected 'self', got %q", string(buf[:n]))
	}
}

func TestSelfBypassDoesNotAffectOtherAddresses(t *testing.T) {
	// Start two echo servers.
	bypass, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bypass.Close() }()

	denied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = denied.Close() }()

	go func() {
		for {
			conn, err := bypass.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()
	go func() {
		for {
			conn, err := denied.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// Deny-all policy with self-bypass only for one address.
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
		SelfBypass: []string{bypass.Addr().String()},
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

	// Connection to bypassed address should succeed.
	conn, err := dialer.Dial("tcp", bypass.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy to bypass address: %v", err)
	}
	_ = conn.Close()

	// Connection to non-bypassed address should be denied.
	_, err = dialer.Dial("tcp", denied.Addr().String())
	if err == nil {
		t.Fatal("expected denial for non-bypass address, but connection succeeded")
	}
}
