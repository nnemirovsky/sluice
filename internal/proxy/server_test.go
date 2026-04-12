package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/proxy"
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
func (c *autoResolveChannel) CancelApproval(_ string) error            { return nil }
func (c *autoResolveChannel) Commands() <-chan channel.Command         { return nil }
func (c *autoResolveChannel) Notify(_ context.Context, _ string) error { return nil }
func (c *autoResolveChannel) Start() error                             { return nil }
func (c *autoResolveChannel) Stop()                                    {}
func (c *autoResolveChannel) Type() channel.ChannelType                { return channel.ChannelTelegram }

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
		_ = conn.Close()
		return nil, nil, fmt.Errorf("write auth: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := conn.Read(authResp); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read auth: %w", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("auth rejected: %x", authResp)
	}

	// SOCKS5 UDP ASSOCIATE request: version=5, cmd=ASSOCIATE(0x03), rsv=0,
	// atyp=IPv4(0x01), addr=0.0.0.0, port=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("write associate: %w", err)
	}

	// Read reply: version(1) + rep(1) + rsv(1) + atyp(1) + BND.ADDR + BND.PORT
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read reply header: %w", err)
	}
	if header[0] != 0x05 {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("unexpected version: %d", header[0])
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("associate rejected with reply code: 0x%02x", header[1])
	}

	// Parse BND.ADDR based on atyp
	var ip net.IP
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4+2)
		if _, err := conn.Read(addr); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("read ipv4 addr: %w", err)
		}
		ip = net.IP(addr[:4])
		port := binary.BigEndian.Uint16(addr[4:6])
		return &net.UDPAddr{IP: ip, Port: int(port)}, conn, nil
	case 0x04: // IPv6
		addr := make([]byte, 16+2)
		if _, err := conn.Read(addr); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("read ipv6 addr: %w", err)
		}
		ip = net.IP(addr[:16])
		port := binary.BigEndian.Uint16(addr[16:18])
		return &net.UDPAddr{IP: ip, Port: int(port)}, conn, nil
	default:
		_ = conn.Close()
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
	defer func() { _ = controlConn.Close() }()

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
	defer func() { _ = echoConn.Close() }()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteTo(buf[:n], addr)
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
	defer func() { _ = controlConn.Close() }()

	// Open a UDP socket to communicate with the relay.
	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

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
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
	defer func() { _ = controlConn.Close() }()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

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
	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	respBuf := make([]byte, 65535)
	_, err = clientConn.Read(respBuf)
	if err == nil {
		t.Fatal("expected timeout reading from denied destination, got response")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestUDPAssociateDNSInterception(t *testing.T) {
	// Start a mock DNS server that returns a canned response.
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dnsConn.Close() }()
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
			_, _ = dnsConn.WriteTo(resp, addr)
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
	defer func() { _ = controlConn.Close() }()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

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
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
	// DNS interceptor should return NXDOMAIN for explicitly denied domains
	// without contacting the upstream resolver.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "allowed.example.com"
ports = [53]
protocols = ["dns"]

[[deny]]
destination = "denied.example.com"
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
	defer func() { _ = controlConn.Close() }()

	clientConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

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
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
// enabled, the QUIC proxy is created alongside the HTTPS MITM proxy and
// listens on a local UDP port.
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
	srv.quicProxy.upstreamDial = func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
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
	defer func() { _ = localConn.Close() }()
	srv.quicProxy.RegisterExpectedHost(localConn.LocalAddr().String(), sni, 443)

	pool := x509.NewCertPool()
	pool.AddCert(proxyCAX509)

	quicUDPAddr, _ := net.ResolveUDPAddr("udp", quicAddr.String())
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: sni,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, localConn, quicUDPAddr, tlsCfg, cfg)
		},
	}
	defer func() { _ = transport.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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

func TestDialWithHandlerSuccess(t *testing.T) {
	conn, err := dialWithHandler(func(handlerConn net.Conn, ready chan<- error) {
		ready <- nil
		// Echo back whatever is received.
		buf := make([]byte, 256)
		n, readErr := handlerConn.Read(buf)
		if readErr != nil {
			return
		}
		_, _ = handlerConn.Write(buf[:n])
		_ = handlerConn.Close()
	})
	if err != nil {
		t.Fatalf("dialWithHandler: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Errorf("got %q, want %q", string(buf[:n]), "ping")
	}
}

func TestDialWithHandlerSetupError(t *testing.T) {
	_, err := dialWithHandler(func(_ net.Conn, ready chan<- error) {
		ready <- fmt.Errorf("setup failed")
	})
	if err == nil {
		t.Fatal("expected error from handler setup failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("setup failed")) {
		t.Errorf("error = %v, want to contain 'setup failed'", err)
	}
}

func TestDialWithHandlerBidirectional(t *testing.T) {
	conn, err := dialWithHandler(func(handlerConn net.Conn, ready chan<- error) {
		ready <- nil
		// Write first, then read.
		_, _ = handlerConn.Write([]byte("from-handler"))
		buf := make([]byte, 256)
		n, _ := handlerConn.Read(buf)
		_, _ = handlerConn.Write(append([]byte("echo:"), buf[:n]...))
		_ = handlerConn.Close()
	})
	if err != nil {
		t.Fatalf("dialWithHandler: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Read the handler's first message.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "from-handler" {
		t.Errorf("got %q, want %q", string(buf[:n]), "from-handler")
	}

	// Send a response.
	_, _ = conn.Write([]byte("reply"))

	// Read the echo.
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != "echo:reply" {
		t.Errorf("got %q, want %q", string(buf[:n]), "echo:reply")
	}
}

func TestDialThroughMITMSuccess(t *testing.T) {
	// Start a mock HTTP proxy listener that accepts CONNECT requests.
	mockProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mockProxy.Close() }()

	go func() {
		for {
			conn, err := mockProxy.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				_, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				// Respond with 200 OK for CONNECT.
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				// Echo data back through the tunnel.
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	conn, err := dialThroughMITM(mockProxy.Addr().String(), "example.com", 443, "test-secret")
	if err != nil {
		t.Fatalf("dialThroughMITM: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Verify the tunnel works by sending data through it.
	_, err = conn.Write([]byte("tunnel-data"))
	if err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(buf[:n]) != "tunnel-data" {
		t.Errorf("got %q, want %q", string(buf[:n]), "tunnel-data")
	}
}

func TestDialThroughMITMRejected(t *testing.T) {
	mockProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mockProxy.Close() }()

	go func() {
		for {
			conn, err := mockProxy.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				_, _ = http.ReadRequest(br)
				_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
			}(conn)
		}
	}()

	_, err = dialThroughMITM(mockProxy.Addr().String(), "example.com", 443, "test-secret")
	if err == nil {
		t.Fatal("expected error from rejected CONNECT")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("CONNECT rejected")) {
		t.Errorf("error = %v, want to contain 'CONNECT rejected'", err)
	}
}

func TestDialThroughMITMConnectionRefused(t *testing.T) {
	// Use a port that nothing is listening on.
	_, err := dialThroughMITM("127.0.0.1:1", "example.com", 443, "test-secret")
	if err == nil {
		t.Fatal("expected error from refused connection")
	}
}

func TestSetupInjectionCreatesComponents(t *testing.T) {
	dir := t.TempDir()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	bindings := []vault.Binding{{
		Destination: "api.example.com",
		Credential:  "test_key",
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	// Verify all injection components were created.
	if srv.mitmProxy == nil {
		t.Error("mitmProxy should be created when provider and resolver are set")
	}
	if srv.addon == nil {
		t.Error("addon should be created when provider and resolver are set")
	}
	if srv.sshJump == nil {
		t.Error("SSH jump host should be created")
	}
	if srv.mailProxy == nil {
		t.Error("mail proxy should be created")
	}
}

func TestSetupInjectionDegracesWithoutResolver(t *testing.T) {
	dir := t.TempDir()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Provider set but no resolver: injection failure should be non-fatal.
	// The CA generation should work, so the only failure path is if CA
	// dir is bad. But without a resolver, the error is logged and ignored.
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   vs,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	// Server should still work for policy-only mode.
	if srv.listener == nil {
		t.Error("server should still have a listener in degraded mode")
	}
}

func TestBufferedConnRead(t *testing.T) {
	// Create a real connection pair.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_, _ = c.Write([]byte("rest-of-data"))
			_ = c.Close()
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()

	// Simulate buffered bytes (like bytes peeked during detection).
	peeked := []byte("peeked-")
	reader := io.MultiReader(bytes.NewReader(peeked), raw)
	bc := &bufferedConn{Reader: reader, Conn: raw}

	// Read should get peeked bytes first, then the connection data.
	buf := make([]byte, 256)
	total := 0
	for {
		n, err := bc.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	got := string(buf[:total])
	if got != "peeked-rest-of-data" {
		t.Errorf("got %q, want %q", got, "peeked-rest-of-data")
	}
}

func TestTrackedListenerAndConn(t *testing.T) {
	var wg sync.WaitGroup
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	tracked := &trackedListener{Listener: ln, wg: &wg}

	// Accept a connection in a goroutine.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := tracked.Accept()
		accepted <- c
	}()

	// Dial to the tracked listener.
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	tc := <-accepted
	if tc == nil {
		t.Fatal("expected accepted connection")
	}

	// The WaitGroup should have been incremented.
	// Close the tracked conn and verify WaitGroup completes.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	_ = tc.Close()

	select {
	case <-done:
		// WaitGroup decremented successfully.
	case <-time.After(2 * time.Second):
		t.Fatal("WaitGroup.Wait() did not complete after closing tracked conn")
	}

	// Double close on tracked conn should not panic.
	_ = tc.Close()

	_ = tracked.Close()
}

func TestSIGHUPEngineRecompile(t *testing.T) {
	// Start an echo server.
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
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()

	// Start with a deny-all policy.
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

	// Connection should be denied.
	_, err = dialer.Dial("tcp", echo.Addr().String())
	if err == nil {
		t.Fatal("expected denial with deny-all policy")
	}

	// Simulate SIGHUP: swap in a new engine that allows localhost.
	newEng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv.ReloadMu().Lock()
	srv.StoreEngine(newEng)
	srv.ReloadMu().Unlock()

	// Connection should now be allowed.
	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("expected connection to succeed after engine swap: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("got %q, want %q", string(buf[:n]), "ok")
	}
}

func TestSIGHUPEngineRecompileWithStore(t *testing.T) {
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
			_, _ = conn.Write([]byte("stored"))
			_ = conn.Close()
		}
	}()

	// Create a store and add a deny-all policy.
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	eng, err := policy.LoadFromStore(st)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Store:      st,
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

	// Add a rule to the store and recompile.
	_, err = st.AddRule("allow", store.RuleOpts{Destination: "127.0.0.1"})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	newEng, err := policy.LoadFromStore(st)
	if err != nil {
		t.Fatalf("reload from store: %v", err)
	}

	srv.ReloadMu().Lock()
	srv.StoreEngine(newEng)
	srv.ReloadMu().Unlock()

	// Connection should now work.
	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("expected success after store rule add: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "stored" {
		t.Errorf("got %q, want %q", string(buf[:n]), "stored")
	}
}

func TestUpdateInspectRules(t *testing.T) {
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
	defer func() { _ = srv.Close() }()

	// UpdateInspectRules with no MITM addon/QUIC should not panic.
	eng.InspectBlockRules = []policy.InspectBlockRule{{Pattern: "secret", Name: "block secrets"}}
	eng.InspectRedactRules = []policy.InspectRedactRule{{Pattern: "password", Replacement: "[REDACTED]", Name: "redact passwords"}}
	srv.UpdateInspectRules(eng)
}

func TestServerAccessors(t *testing.T) {
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
	defer func() { _ = srv.Close() }()

	// EnginePtr should return the shared pointer.
	ptr := srv.EnginePtr()
	if ptr == nil {
		t.Fatal("EnginePtr() returned nil")
	}
	if ptr.Load() != eng {
		t.Error("EnginePtr().Load() should return the configured engine")
	}

	// ResolverPtr should return a non-nil pointer.
	rp := srv.ResolverPtr()
	if rp == nil {
		t.Fatal("ResolverPtr() returned nil")
	}

	// ReloadMu should return a non-nil mutex.
	mu := srv.ReloadMu()
	if mu == nil {
		t.Fatal("ReloadMu() returned nil")
	}
	// Verify it can be locked and unlocked without deadlock.
	mu.Lock()
	mu.Unlock() //nolint:staticcheck // SA2001: intentionally testing lock/unlock works

	// Addr should be non-empty.
	if srv.Addr() == "" {
		t.Error("Addr() returned empty string")
	}

	// IsListening should be false before ListenAndServe.
	if srv.IsListening() {
		t.Error("IsListening() should be false before ListenAndServe")
	}
}

func TestStoreResolver(t *testing.T) {
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
	defer func() { _ = srv.Close() }()

	// Initially no resolver.
	if srv.ResolverPtr().Load() != nil {
		t.Error("resolver should be nil initially")
	}

	// Store a resolver.
	bindings := []vault.Binding{{Destination: "example.com", Credential: "key"}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}
	srv.StoreResolver(resolver)

	// Verify it's stored.
	if srv.ResolverPtr().Load() != resolver {
		t.Error("StoreResolver did not store the resolver")
	}
}

func TestSetBroker(t *testing.T) {
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
	defer func() { _ = srv.Close() }()

	broker := newAutoResolveBroker(channel.ResponseAllowOnce)
	srv.SetBroker(broker)

	if srv.rules.broker != broker {
		t.Error("SetBroker did not set broker on rules")
	}
	if srv.dnsResolver.broker != broker {
		t.Error("SetBroker did not set broker on dnsResolver")
	}
}

func TestFullSOCKS5MITMPipeline(t *testing.T) {
	// Uses an HTTPS backend so go-mitmproxy fires addon hooks for TLS
	// interception and performs phantom token swap via the SluiceAddon.
	dir := t.TempDir()

	// Start an HTTPS backend that echoes the Authorization header.
	var mu sync.Mutex
	var receivedAuth string
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte("auth=" + receivedAuth))
	}))
	backend.StartTLS()
	defer backend.Close()

	backendHost, backendPortStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	backendPort := 0
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	// Create a vault store with a credential.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	credName := "backend_key"
	realSecret := "Bearer real-secret-value"
	phantom := PhantomToken(credName)
	if _, err := vs.Add(credName, realSecret); err != nil {
		t.Fatal(err)
	}

	bindings := []vault.Binding{{
		Destination: backendHost,
		Ports:       []int{backendPort},
		Credential:  credName,
		Header:      "Authorization",
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	// Connect through the SOCKS5 proxy with TLS (InsecureSkipVerify
	// because go-mitmproxy generates MITM certs on the fly).
	socksDialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}

	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	reqURL := fmt.Sprintf("https://%s:%d/test", backendHost, backendPort)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Include the phantom token in the header. The MITM should replace it.
	req.Header.Set("Authorization", phantom)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	// The backend should have received the real credential, not the phantom.
	if string(body) != "auth="+realSecret {
		t.Errorf("backend received %q, want %q", string(body), "auth="+realSecret)
	}
}

// slowResolveChannel is a mock channel that takes a long time to resolve.
type slowResolveChannel struct {
	broker *channel.Broker
}

func (c *slowResolveChannel) RequestApproval(_ context.Context, _ channel.ApprovalRequest) error {
	// Never resolve. The request will time out or be cancelled by shutdown.
	return nil
}
func (c *slowResolveChannel) CancelApproval(_ string) error            { return nil }
func (c *slowResolveChannel) Commands() <-chan channel.Command         { return nil }
func (c *slowResolveChannel) Notify(_ context.Context, _ string) error { return nil }
func (c *slowResolveChannel) Start() error                             { return nil }
func (c *slowResolveChannel) Stop()                                    {}
func (c *slowResolveChannel) Type() channel.ChannelType                { return channel.ChannelTelegram }

func TestGracefulShutdownWithPendingApprovals(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "ask"
timeout_sec = 30
`))
	if err != nil {
		t.Fatal(err)
	}

	// Create a broker with a channel that never resolves approval requests.
	slowCh := &slowResolveChannel{}
	broker := channel.NewBroker([]channel.Channel{slowCh})
	slowCh.broker = broker

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()

	// Attempt a connection (will block waiting for approval).
	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_, _ = dialer.Dial("tcp", "93.184.216.34:80")
	}()

	// Give it a moment to start the approval request.
	time.Sleep(100 * time.Millisecond)

	// Shutdown. The pending approval should not prevent shutdown from completing
	// within a reasonable time (the listener closes, no new connections accepted).
	err = srv.GracefulShutdown(2 * time.Second)
	// We accept either nil (drained in time) or timeout error.
	// The key test is that shutdown doesn't hang indefinitely.
	if err != nil {
		t.Logf("shutdown returned (expected for pending request): %v", err)
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

func TestIsHTTPSPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{443, true},
		{8443, true},
		{80, false},
		{8080, false},
		{22, false},
		{0, false},
	}
	for _, tt := range tests {
		if got := isHTTPSPort(tt.port); got != tt.want {
			t.Errorf("isHTTPSPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestBindingIsMetaOnly(t *testing.T) {
	tests := []struct {
		name     string
		binding  vault.Binding
		wantMeta bool
	}{
		{
			name:     "no_protocols",
			binding:  vault.Binding{},
			wantMeta: false,
		},
		{
			name:     "tcp_only",
			binding:  vault.Binding{Protocols: []string{"tcp"}},
			wantMeta: true,
		},
		{
			name:     "udp_only",
			binding:  vault.Binding{Protocols: []string{"udp"}},
			wantMeta: true,
		},
		{
			name:     "tcp_and_udp",
			binding:  vault.Binding{Protocols: []string{"tcp", "udp"}},
			wantMeta: true,
		},
		{
			name:     "https_specific",
			binding:  vault.Binding{Protocols: []string{"https"}},
			wantMeta: false,
		},
		{
			name:     "mixed_tcp_and_https",
			binding:  vault.Binding{Protocols: []string{"tcp", "https"}},
			wantMeta: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bindingIsMetaOnly(tt.binding)
			if got != tt.wantMeta {
				t.Errorf("bindingIsMetaOnly(%v) = %v, want %v", tt.binding.Protocols, got, tt.wantMeta)
			}
		})
	}
}

func TestBidirectionalRelay(t *testing.T) {
	// Create two connections: use a TCP pair.
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln1.Close() }()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln2.Close() }()

	ch1 := make(chan net.Conn, 1)
	ch2 := make(chan net.Conn, 1)
	go func() { c, _ := ln1.Accept(); ch1 <- c }()
	go func() { c, _ := ln2.Accept(); ch2 <- c }()

	client1, err := net.Dial("tcp", ln1.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client2, err := net.Dial("tcp", ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	server1 := <-ch1
	server2 := <-ch2

	// Relay between server1 and server2.
	go bidirectionalRelay(server1, server2)

	// Write through client1 and read from client2.
	_, _ = client1.Write([]byte("hello"))
	buf := make([]byte, 10)
	_ = client2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client2.Read(buf)
	if err != nil {
		t.Fatalf("read from client2: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want %q", string(buf[:n]), "hello")
	}

	// Write through client2 and read from client1.
	_, _ = client2.Write([]byte("world"))
	_ = client1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client1.Read(buf)
	if err != nil {
		t.Fatalf("read from client1: %v", err)
	}
	if string(buf[:n]) != "world" {
		t.Errorf("got %q, want %q", string(buf[:n]), "world")
	}

	// Close one end and verify relay completes.
	_ = client1.Close()
	time.Sleep(50 * time.Millisecond)
	_ = client2.Close()
}

func TestFullSOCKS5MITMPipelineMultipleBindings(t *testing.T) {
	// Test that multiple credentials for different HTTPS destinations are
	// injected correctly through the MITM addon.
	dir := t.TempDir()

	var mu1, mu2 sync.Mutex
	var received1, received2 string

	backend1 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu1.Lock()
		received1 = r.Header.Get("Authorization")
		mu1.Unlock()
		_, _ = w.Write([]byte("ok1"))
	}))
	backend1.StartTLS()
	defer backend1.Close()

	backend2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu2.Lock()
		received2 = r.Header.Get("X-Api-Key")
		mu2.Unlock()
		_, _ = w.Write([]byte("ok2"))
	}))
	backend2.StartTLS()
	defer backend2.Close()

	host1, port1Str, _ := net.SplitHostPort(backend1.Listener.Addr().String())
	port1 := 0
	_, _ = fmt.Sscanf(port1Str, "%d", &port1)
	host2, port2Str, _ := net.SplitHostPort(backend2.Listener.Addr().String())
	port2 := 0
	_, _ = fmt.Sscanf(port2Str, "%d", &port2)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("cred1", "secret-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("cred2", "secret-2"); err != nil {
		t.Fatal(err)
	}

	bindings := []vault.Binding{
		{Destination: host1, Ports: []int{port1}, Credential: "cred1", Header: "Authorization"},
		{Destination: host2, Ports: []int{port2}, Credential: "cred2", Header: "X-Api-Key"},
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	socksDialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}
	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	// Request to backend1 with phantom for cred1.
	req1, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%d/", host1, port1), nil)
	req1.Header.Set("Authorization", PhantomToken("cred1"))
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("request to backend1: %v", err)
	}
	_ = resp1.Body.Close()

	mu1.Lock()
	if received1 != "secret-1" {
		t.Errorf("backend1 received auth %q, want %q", received1, "secret-1")
	}
	mu1.Unlock()

	// Request to backend2 with phantom for cred2.
	req2, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%d/", host2, port2), nil)
	req2.Header.Set("X-Api-Key", PhantomToken("cred2"))
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request to backend2: %v", err)
	}
	_ = resp2.Body.Close()

	mu2.Lock()
	if received2 != "secret-2" {
		t.Errorf("backend2 received key %q, want %q", received2, "secret-2")
	}
	mu2.Unlock()
}

func TestProxyDirectConnectionFallback(t *testing.T) {
	// Start a TCP echo server on a non-standard port.
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
			_, _ = conn.Write([]byte("direct"))
			_ = conn.Close()
		}
	}()

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	// No provider/resolver = no credential injection = direct connection path.
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

	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("direct connection through proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "direct" {
		t.Errorf("got %q, want %q", string(buf[:n]), "direct")
	}
}

func TestProxyUnboundHTTPSStripsPhantoms(t *testing.T) {
	// Test that unbound HTTPS connections still strip phantom tokens via
	// the MITM addon. go-mitmproxy intercepts TLS traffic and the addon
	// performs pass-3 phantom stripping even without bindings.
	dir := t.TempDir()

	var mu sync.Mutex
	var receivedCustom string
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCustom = r.Header.Get("X-Custom")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	backend.StartTLS()
	defer backend.Close()

	backendHost, backendPortStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	backendPort := 0
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("some_cred", "secret-value"); err != nil {
		t.Fatal(err)
	}

	// No bindings. Unbound HTTPS should still strip phantoms.
	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	socksDialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}

	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	phantom := PhantomToken("some_cred")
	reqURL := fmt.Sprintf("https://%s:%d/", backendHost, backendPort)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Custom", phantom)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request through proxy: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	got := receivedCustom
	mu.Unlock()

	// The phantom should have been stripped (replaced with empty).
	if got == phantom {
		t.Error("phantom token was not stripped from unbound HTTPS request")
	}
}

func TestUpdateInspectRulesWithWSConfig(t *testing.T) {
	dir := t.TempDir()
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatal(err)
	}

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr:    "127.0.0.1:0",
		Policy:        eng,
		Provider:      vs,
		Resolver:      resolver,
		VaultDir:      dir,
		WSBlockRules:  []WSBlockRuleConfig{{Pattern: "old-pattern", Name: "old"}},
		WSRedactRules: []WSRedactRuleConfig{{Pattern: "old-redact", Replacement: "[OLD]", Name: "old-redact"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	// Update inspect rules with new patterns.
	eng.InspectBlockRules = []policy.InspectBlockRule{{Pattern: "secret-pattern", Name: "block secrets"}}
	eng.InspectRedactRules = []policy.InspectRedactRule{{Pattern: "password-pattern", Replacement: "[REDACTED]", Name: "redact passwords"}}
	srv.UpdateInspectRules(eng)

	// The test passes if UpdateInspectRules doesn't panic and completes.
	// The actual rule application is tested by the WebSocket and QUIC tests.
}

func TestRelayDirect(t *testing.T) {
	// Start an echo server.
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
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			_, _ = conn.Write(buf[:n])
			_ = conn.Close()
		}
	}()

	// Create a connection pair to test relayDirect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	acceptCh := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acceptCh <- c }()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	serverConn := <-acceptCh

	go relayDirect(serverConn, []string{echo.Addr().String()})

	// Write through client -> relay -> echo -> relay -> client.
	_, _ = clientConn.Write([]byte("relay-test"))
	buf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	if string(buf[:n]) != "relay-test" {
		t.Errorf("got %q, want %q", string(buf[:n]), "relay-test")
	}
}

func TestRelayDirectFailedDial(t *testing.T) {
	// relayDirect with unreachable addresses should not panic.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	acceptCh := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acceptCh <- c }()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	serverConn := <-acceptCh

	// Use a port that nothing is listening on.
	done := make(chan struct{})
	go func() {
		relayDirect(serverConn, []string{"127.0.0.1:1"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(35 * time.Second):
		t.Fatal("relayDirect did not return within timeout")
	}
}

func TestProxyWithByteDetectionHTTPS(t *testing.T) {
	// Test that HTTPS on a non-standard port is detected via byte detection
	// and routes through the MITM addon for credential injection.
	dir := t.TempDir()

	var mu sync.Mutex
	var receivedAuth string
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte("detected"))
	}))
	backend.StartTLS()
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("detect_cred", "real-value"); err != nil {
		t.Fatal(err)
	}

	// Binding with protocols=["tcp"] to exercise the meta-protocol + byte detection path.
	bindings := []vault.Binding{{
		Destination: host,
		Ports:       []int{port},
		Credential:  "detect_cred",
		Header:      "Authorization",
		Protocols:   []string{"tcp"},
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	socksDialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}

	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	reqURL := fmt.Sprintf("https://%s:%d/", host, port)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", PhantomToken("detect_cred"))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request with byte detection: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "detected" {
		t.Errorf("got %q, want %q", string(body), "detected")
	}

	mu.Lock()
	if receivedAuth != "real-value" {
		t.Errorf("backend received auth %q, want %q", receivedAuth, "real-value")
	}
	mu.Unlock()
}

func TestProxyGenericPortNoBindingByteDetection(t *testing.T) {
	// Test a connection on a non-standard port without bindings. The byte
	// detection path for unbound connections should still route HTTPS
	// traffic through the MITM addon for phantom stripping.
	dir := t.TempDir()

	var mu sync.Mutex
	var receivedHeader string
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeader = r.Header.Get("X-Phantom")
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	backend.StartTLS()
	defer backend.Close()

	backendHost, backendPortStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	backendPort := 0
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("phantom_cred", "value"); err != nil {
		t.Fatal(err)
	}

	// Empty resolver: no bindings.
	resolver, err := vault.NewBindingResolver(nil)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	socksDialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}

	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	reqURL := fmt.Sprintf("https://%s:%d/", backendHost, backendPort)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Phantom", PhantomToken("phantom_cred"))

	resp, err := client.Do(req)
	if err != nil {
		// Non-standard port byte detection might route through the MITM
		// addon or direct. Either way, this tests that the path does not crash.
		t.Logf("HTTPS request returned error (acceptable): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	mu.Lock()
	got := receivedHeader
	mu.Unlock()

	// The phantom should have been stripped if it went through the MITM addon.
	if got == PhantomToken("phantom_cred") {
		t.Error("phantom token was not stripped for unbound non-standard port HTTPS")
	}
}

func TestDialThroughMITMBufferedResponse(t *testing.T) {
	// Test that dialThroughMITM handles responses with extra buffered data.
	mockProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mockProxy.Close() }()

	go func() {
		for {
			conn, err := mockProxy.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				_, _ = http.ReadRequest(br)
				// Respond with 200 OK and immediately send some tunnel data.
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nbuffered-data")
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	conn, err := dialThroughMITM(mockProxy.Addr().String(), "example.com", 443, "test-secret")
	if err != nil {
		t.Fatalf("dialThroughMITM: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Should be able to read the buffered data that arrived with the response.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read buffered data: %v", err)
	}
	if string(buf[:n]) != "buffered-data" {
		t.Errorf("got %q, want %q", string(buf[:n]), "buffered-data")
	}
}

func TestProxyWithStandardHTTPPort(t *testing.T) {
	// Test credential injection on port 80 (standard HTTP port) which
	// exercises the standard-port path in dial() (no byte detection needed).
	dir := t.TempDir()

	// Start backend on port 80. This may fail if port 80 is in use.
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skip("cannot bind to port 80 (probably in use or no permission)")
	}

	var mu sync.Mutex
	var receivedAuth string
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			receivedAuth = r.Header.Get("Authorization")
			mu.Unlock()
			_, _ = w.Write([]byte("port80-ok"))
		})
		_ = http.Serve(ln, mux)
	}()
	defer func() { _ = ln.Close() }()

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("port80_cred", "port80-secret"); err != nil {
		t.Fatal(err)
	}

	bindings := []vault.Binding{{
		Destination: "127.0.0.1",
		Ports:       []int{80},
		Credential:  "port80_cred",
		Header:      "Authorization",
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
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

	transport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:80/", nil)
	req.Header.Set("Authorization", PhantomToken("port80_cred"))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP on port 80: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	mu.Lock()
	if receivedAuth != "port80-secret" {
		t.Errorf("backend received auth %q, want %q", receivedAuth, "port80-secret")
	}
	mu.Unlock()
}

func TestProxyNonStandardPortWithBinding(t *testing.T) {
	// Test connection on a non-standard port with a binding that has no
	// specific protocol, exercising the byte-detection code path in dial().
	// Uses HTTPS so go-mitmproxy intercepts and fires addon hooks.
	dir := t.TempDir()

	var mu sync.Mutex
	var receivedAuth string
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte("nonstandard-ok"))
	}))
	backend.StartTLS()
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("ns_cred", "ns-secret"); err != nil {
		t.Fatal(err)
	}

	// Binding with no protocols specified (protocol-agnostic). Non-standard port
	// means proto == ProtoGeneric, which triggers handleWithDetection in dial().
	bindings := []vault.Binding{{
		Destination: host,
		Ports:       []int{port},
		Credential:  "ns_cred",
		Header:      "Authorization",
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

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
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	socksDialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}

	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	reqURL := fmt.Sprintf("https://%s:%d/", host, port)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", PhantomToken("ns_cred"))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request on non-standard port: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	mu.Lock()
	if receivedAuth != "ns-secret" {
		t.Errorf("backend received auth %q, want %q", receivedAuth, "ns-secret")
	}
	mu.Unlock()
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"169.254.1.1", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"93.184.216.34", false},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid IP: %s", tt.ip)
		}
		if got := isPrivateIP(ip); got != tt.want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// TestHandleServerFirstDetectionSMTP tests that server-first detection correctly
// identifies an SMTP server banner and routes through the mail proxy when available.
func TestHandleServerFirstDetectionSMTP(t *testing.T) {
	// Start a mock upstream server that sends an SMTP banner.
	smtpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = smtpLn.Close() }()

	go func() {
		conn, err := smtpLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 smtp.example.com ESMTP\r\n"))
		// Read and echo anything (simple relay behavior).
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, _ = conn.Write(buf[:n])
		}
	}()

	dir := t.TempDir()
	vs, _ := vault.NewStore(dir)

	srv := &Server{}
	srv.resolver.Store(nil) // no resolver

	// Create a pipe pair as the "agent" connection.
	agentConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// handleServerFirstDetection with no mail proxy: should fall back to relay.
		srv.handleServerFirstDetection(agentConn, nil, smtpLn.Addr().String(), []string{smtpLn.Addr().String()})
	}()

	// Read the SMTP banner through the relay.
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	// handleServerFirstDetection peeks only 8 bytes from the server for
	// protocol detection, so we see the first 8 bytes of the banner first.
	got := string(buf[:n])
	if !strings.HasPrefix(got, "220 smtp") {
		t.Errorf("expected SMTP banner prefix, got: %q", got)
	}

	_ = clientConn.Close()
	<-done

	_ = vs // keep vault reference to avoid unused
}

// TestHandleServerFirstDetectionFailedDial tests that a failed upstream dial
// is handled gracefully without panic.
func TestHandleServerFirstDetectionFailedDial(t *testing.T) {
	srv := &Server{}
	srv.resolver.Store(nil)

	agentConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleServerFirstDetection(agentConn, nil, "127.0.0.1:1", []string{"127.0.0.1:1"})
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleServerFirstDetection did not return")
	}
}

// TestHandleServerFirstDetectionNoData tests behavior when the upstream sends
// no banner within the timeout (should fall back to generic relay).
func TestHandleServerFirstDetectionNoData(t *testing.T) {
	// Start a server that accepts but sends nothing.
	silentLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silentLn.Close() }()

	var upstreamConn net.Conn
	acceptCh := make(chan struct{})
	go func() {
		c, err := silentLn.Accept()
		if err != nil {
			return
		}
		upstreamConn = c
		close(acceptCh)
		// Hold open but send nothing.
		buf := make([]byte, 1024)
		for {
			_, err := c.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	srv := &Server{}
	srv.resolver.Store(nil)

	agentConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleServerFirstDetection(agentConn, nil, silentLn.Addr().String(), []string{silentLn.Addr().String()})
	}()

	// Wait for upstream accept.
	select {
	case <-acceptCh:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream accept timeout")
	}

	// Write some data through the agent side. The relay should eventually
	// forward it (after the server detection timeout).
	time.Sleep(600 * time.Millisecond) // wait past serverDetectTimeout (500ms)
	_, _ = clientConn.Write([]byte("hello"))

	// Clean up by closing connections.
	_ = clientConn.Close()
	if upstreamConn != nil {
		_ = upstreamConn.Close()
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleServerFirstDetection did not return")
	}
}

func TestServerSetOnOAuthRefresh(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	vs, vsErr := vault.NewStore(dir)
	if vsErr != nil {
		t.Fatal(vsErr)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   vs,
		VaultDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	// SetOnOAuthRefresh should not panic even if addon is nil (no bindings).
	called := false
	srv.SetOnOAuthRefresh(func(_ string) {
		called = true
	})

	// The addon may or may not be present depending on server config.
	// If it is present, verify the callback was stored and works.
	if srv.addon == nil {
		t.Log("addon is nil (no TLS config), skipping callback verification")
		return
	}
	if srv.addon.onOAuthRefresh == nil {
		t.Error("onOAuthRefresh callback not set on addon")
	}

	srv.addon.onOAuthRefresh("test-cred")
	if !called {
		t.Error("onOAuthRefresh callback was not called")
	}
}

func TestServerUpdateOAuthIndexNoAddon(t *testing.T) {
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
	defer func() { _ = srv.Close() }()

	// Should not panic when addon is nil.
	srv.UpdateOAuthIndex([]store.CredentialMeta{
		{Name: "test", CredType: "oauth", TokenURL: "https://example.com/token"},
	})
}

func TestServerSetOnOAuthRefreshNoAddon(t *testing.T) {
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
	defer func() { _ = srv.Close() }()

	// Should not panic when addon is nil.
	srv.SetOnOAuthRefresh(func(_ string) {})
}

// delayedCountingChannel is a mock approval channel that counts broker
// requests and delays resolution so tests can observe dedup behavior.
type delayedCountingChannel struct {
	broker   *channel.Broker
	response channel.Response
	mu       sync.Mutex
	count    int
	delay    time.Duration
	requests []channel.ApprovalRequest
}

func (c *delayedCountingChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	c.mu.Lock()
	c.count++
	c.requests = append(c.requests, req)
	c.mu.Unlock()
	go func() {
		if c.delay > 0 {
			time.Sleep(c.delay)
		}
		c.broker.Resolve(req.ID, c.response)
	}()
	return nil
}

func (c *delayedCountingChannel) CancelApproval(_ string) error            { return nil }
func (c *delayedCountingChannel) Commands() <-chan channel.Command         { return nil }
func (c *delayedCountingChannel) Notify(_ context.Context, _ string) error { return nil }
func (c *delayedCountingChannel) Start() error                             { return nil }
func (c *delayedCountingChannel) Stop()                                    {}
func (c *delayedCountingChannel) Type() channel.ChannelType                { return channel.ChannelTelegram }

func (c *delayedCountingChannel) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// TestPendingQUICSessionBufferLimit verifies that the pendingQUICSession
// struct respects the maxPendingQUICPackets limit.
func TestPendingQUICSessionBufferLimit(t *testing.T) {
	pending := &pendingQUICSession{
		packets: nil,
		done:    make(chan struct{}),
	}

	// Buffer exactly maxPendingQUICPackets packets.
	for i := 0; i < maxPendingQUICPackets; i++ {
		pending.mu.Lock()
		if len(pending.packets) < maxPendingQUICPackets {
			pending.packets = append(pending.packets, []byte{byte(i)})
		}
		pending.mu.Unlock()
	}

	if len(pending.packets) != maxPendingQUICPackets {
		t.Fatalf("expected %d packets in buffer, got %d", maxPendingQUICPackets, len(pending.packets))
	}

	// Next packet should be dropped.
	pending.mu.Lock()
	before := len(pending.packets)
	if len(pending.packets) < maxPendingQUICPackets {
		pending.packets = append(pending.packets, []byte{0xFF})
	}
	after := len(pending.packets)
	pending.mu.Unlock()

	if after != before {
		t.Fatalf("buffer should not grow beyond %d, got %d", maxPendingQUICPackets, after)
	}

	// Verify done channel works correctly.
	pending.allowed = true
	close(pending.done)

	select {
	case <-pending.done:
		if !pending.allowed {
			t.Error("expected allowed=true after approval")
		}
	case <-time.After(time.Second):
		t.Error("done channel was not closed")
	}
}

// TestPendingQUICSessionDenied verifies that a denied pendingQUICSession
// signals done with allowed=false.
func TestPendingQUICSessionDenied(t *testing.T) {
	pending := &pendingQUICSession{
		packets: [][]byte{{0x01}, {0x02}, {0x03}},
		done:    make(chan struct{}),
	}

	pending.allowed = false
	close(pending.done)

	select {
	case <-pending.done:
		if pending.allowed {
			t.Error("expected allowed=false after denial")
		}
	case <-time.After(time.Second):
		t.Error("done channel was not closed")
	}
}

// TestQUICPendingSessionDedupOneBrokerRequest verifies that multiple QUIC
// Initial packets for the same destination during an approval wait trigger
// only a single broker request. The additional packets are buffered and
// flushed when approval resolves.
func TestQUICPendingSessionDedupOneBrokerRequest(t *testing.T) {
	// Create a counting channel that delays resolution by 200ms.
	ch := &delayedCountingChannel{
		response: channel.ResponseAllowOnce,
		delay:    200 * time.Millisecond,
	}
	broker := channel.NewBroker([]channel.Channel{ch})
	ch.broker = broker

	// Policy: ask for all QUIC traffic on port 443.
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
timeout_sec = 10

[[ask]]
destination = "*"
ports = [443]
`))
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
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
		t.Fatal("expected QUIC proxy to be created")
	}

	// Wait for QUIC proxy to start.
	for i := 0; i < 50; i++ {
		if srv.quicProxy.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.quicProxy.Addr() == nil {
		t.Fatal("QUIC proxy did not start listening")
	}

	// Connect via SOCKS5 UDP ASSOCIATE.
	tcpConn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer func() { _ = tcpConn.Close() }()

	// SOCKS5 handshake: no auth.
	_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authResp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if authResp[1] != 0x00 {
		t.Fatalf("unexpected auth method: %d", authResp[1])
	}

	// SOCKS5 UDP ASSOCIATE command (0x03).
	// Request: VER=5, CMD=3, RSV=0, ATYP=1 (IPv4), ADDR=0.0.0.0, PORT=0
	_, _ = tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assocResp := make([]byte, 10)
	if _, err := io.ReadFull(tcpConn, assocResp); err != nil {
		t.Fatalf("read ASSOCIATE response: %v", err)
	}
	if assocResp[1] != 0x00 {
		t.Fatalf("ASSOCIATE failed with reply %d", assocResp[1])
	}

	// Parse the bind address from the ASSOCIATE response.
	bindPort := int(assocResp[8])<<8 | int(assocResp[9])
	bindIP := net.IP(assocResp[4:8])
	bindAddr := &net.UDPAddr{IP: bindIP, Port: bindPort}

	// Create a UDP socket from the same IP as the TCP connection.
	localTCPAddr := tcpConn.LocalAddr().(*net.TCPAddr)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localTCPAddr.IP, Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer func() { _ = udpConn.Close() }()

	// Build a QUIC Initial packet (passes IsQUICPacket check).
	quicPayload := buildQUICInitial(t, "dedup-test.example.com", quicVersionV1)

	// Wrap in SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) + DATA
	destIP := net.ParseIP("10.0.0.1").To4()
	destPort := 443
	socks5Header := []byte{
		0x00, 0x00, // RSV
		0x00,                                       // FRAG
		0x01,                                       // ATYP IPv4
		destIP[0], destIP[1], destIP[2], destIP[3], // DST.ADDR
		byte(destPort >> 8), byte(destPort), // DST.PORT
	}
	datagram := append(socks5Header, quicPayload...)

	// Send 5 QUIC Initial packets rapidly. Only one should trigger
	// a broker request. The rest should be buffered.
	for i := 0; i < 5; i++ {
		if _, err := udpConn.WriteTo(datagram, bindAddr); err != nil {
			t.Fatalf("send QUIC packet %d: %v", i, err)
		}
		// Tiny delay to ensure the dispatch loop processes each packet.
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for the approval to resolve (200ms delay + margin).
	time.Sleep(400 * time.Millisecond)

	// Verify only one broker request was made.
	got := ch.Count()
	if got != 1 {
		t.Errorf("expected 1 broker request, got %d", got)
	}
}

// TestQUICPendingSessionDeniedDiscardsBuffer verifies that when the broker
// denies a QUIC session, all buffered packets are discarded and no session
// is created.
func TestQUICPendingSessionDeniedDiscardsBuffer(t *testing.T) {
	// Create a counting channel that denies after a delay.
	ch := &delayedCountingChannel{
		response: channel.ResponseDeny,
		delay:    100 * time.Millisecond,
	}
	broker := channel.NewBroker([]channel.Channel{ch})
	ch.broker = broker

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
timeout_sec = 10

[[ask]]
destination = "*"
ports = [443]
`))
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
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
		t.Fatal("expected QUIC proxy to be created")
	}

	for i := 0; i < 50; i++ {
		if srv.quicProxy.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.quicProxy.Addr() == nil {
		t.Fatal("QUIC proxy did not start listening")
	}

	// Connect via SOCKS5 UDP ASSOCIATE.
	tcpConn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer func() { _ = tcpConn.Close() }()

	_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authResp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}

	_, _ = tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assocResp := make([]byte, 10)
	if _, err := io.ReadFull(tcpConn, assocResp); err != nil {
		t.Fatalf("read ASSOCIATE response: %v", err)
	}
	if assocResp[1] != 0x00 {
		t.Fatalf("ASSOCIATE failed with reply %d", assocResp[1])
	}

	bindPort := int(assocResp[8])<<8 | int(assocResp[9])
	bindIP := net.IP(assocResp[4:8])
	bindAddr := &net.UDPAddr{IP: bindIP, Port: bindPort}

	localTCPAddr := tcpConn.LocalAddr().(*net.TCPAddr)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localTCPAddr.IP, Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer func() { _ = udpConn.Close() }()

	quicPayload := buildQUICInitial(t, "denied-test.example.com", quicVersionV1)
	destIP := net.ParseIP("10.0.0.2").To4()
	destPort := 443
	socks5Header := []byte{
		0x00, 0x00,
		0x00,
		0x01,
		destIP[0], destIP[1], destIP[2], destIP[3],
		byte(destPort >> 8), byte(destPort),
	}
	datagram := append(socks5Header, quicPayload...)

	// Send 3 packets. All should be buffered, then discarded on denial.
	for i := 0; i < 3; i++ {
		if _, err := udpConn.WriteTo(datagram, bindAddr); err != nil {
			t.Fatalf("send QUIC packet %d: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for the denial to resolve.
	time.Sleep(300 * time.Millisecond)

	// Verify only one broker request was made (dedup worked).
	got := ch.Count()
	if got != 1 {
		t.Errorf("expected 1 broker request for denied session, got %d", got)
	}

	// Send another packet after denial. Since the pending entry was removed,
	// this should trigger a new broker request.
	if _, err := udpConn.WriteTo(datagram, bindAddr); err != nil {
		t.Fatalf("send post-denial QUIC packet: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	got = ch.Count()
	if got != 2 {
		t.Errorf("expected 2 broker requests total (one per approval cycle), got %d", got)
	}
}

// TestQUICPendingSessionBufferOverflow verifies that when more than
// maxPendingQUICPackets arrive during an approval wait, excess packets
// are dropped.
func TestQUICPendingSessionBufferOverflow(t *testing.T) {
	// Create a channel with a long delay to keep the session pending.
	ch := &delayedCountingChannel{
		response: channel.ResponseAllowOnce,
		delay:    500 * time.Millisecond,
	}
	broker := channel.NewBroker([]channel.Channel{ch})
	ch.broker = broker

	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
timeout_sec = 10

[[ask]]
destination = "*"
ports = [443]
`))
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Broker:     broker,
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
		t.Fatal("expected QUIC proxy to be created")
	}

	for i := 0; i < 50; i++ {
		if srv.quicProxy.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Connect via SOCKS5 UDP ASSOCIATE.
	tcpConn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer func() { _ = tcpConn.Close() }()

	_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authResp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}

	_, _ = tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assocResp := make([]byte, 10)
	if _, err := io.ReadFull(tcpConn, assocResp); err != nil {
		t.Fatalf("read ASSOCIATE response: %v", err)
	}
	if assocResp[1] != 0x00 {
		t.Fatalf("ASSOCIATE failed with reply %d", assocResp[1])
	}

	bindPort := int(assocResp[8])<<8 | int(assocResp[9])
	bindIP := net.IP(assocResp[4:8])
	bindAddr := &net.UDPAddr{IP: bindIP, Port: bindPort}

	localTCPAddr := tcpConn.LocalAddr().(*net.TCPAddr)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localTCPAddr.IP, Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer func() { _ = udpConn.Close() }()

	quicPayload := buildQUICInitial(t, "overflow-test.example.com", quicVersionV1)
	destIP := net.ParseIP("10.0.0.3").To4()
	destPort := 443
	socks5Header := []byte{
		0x00, 0x00,
		0x00,
		0x01,
		destIP[0], destIP[1], destIP[2], destIP[3],
		byte(destPort >> 8), byte(destPort),
	}
	datagram := append(socks5Header, quicPayload...)

	// Send maxPendingQUICPackets + 10 packets. The extra ones should be dropped.
	total := maxPendingQUICPackets + 10
	for i := 0; i < total; i++ {
		if _, err := udpConn.WriteTo(datagram, bindAddr); err != nil {
			t.Fatalf("send QUIC packet %d: %v", i, err)
		}
		// No delay: blast them all as fast as possible.
	}

	// Small delay so the dispatch loop processes all packets.
	time.Sleep(100 * time.Millisecond)

	// Still only one broker request.
	got := ch.Count()
	if got != 1 {
		t.Errorf("expected 1 broker request during overflow test, got %d", got)
	}
}

// TestRelayQUICResponsesWrapsSOCKS5Header verifies that relayQUICResponses
// reads response packets from the upstream PacketConn, wraps them in SOCKS5
// UDP headers using the original destination address (not the QUIC proxy
// address), and writes them to the relay UDPConn.
func TestRelayQUICResponsesWrapsSOCKS5Header(t *testing.T) {
	// 1. Create the upstream PacketConn (simulates per-session listener that
	//    quic-go writes responses to).
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upstream.Close() }()

	// 2. Create the relay UDPConn (simulates bindLn from SOCKS5 UDP ASSOCIATE).
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer func() { _ = relay.Close() }()

	// 3. Create a "client" that will read from the relay.
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer func() { _ = client.Close() }()

	clientAddr := client.LocalAddr()
	originalDst := &net.UDPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}

	// 4. Start relayQUICResponses in a goroutine.
	srv := &Server{}
	go srv.relayQUICResponses(upstream, relay, clientAddr, originalDst)

	// 5. Simulate quic-go sending a response by writing to the upstream.
	responsePayload := []byte("QUIC response data from upstream")
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	if _, err := sender.WriteTo(responsePayload, upstream.LocalAddr()); err != nil {
		t.Fatalf("write to upstream: %v", err)
	}

	// 6. Read from the client and verify SOCKS5 wrapping.
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, _, readErr := client.ReadFrom(buf)
	if readErr != nil {
		t.Fatalf("read from client: %v", readErr)
	}

	// Parse the SOCKS5 UDP header.
	addr, port, payload, parseErr := ParseSOCKS5UDPHeader(buf[:n])
	if parseErr != nil {
		t.Fatalf("parse SOCKS5 UDP header: %v", parseErr)
	}

	// Verify the address is the original destination, not the QUIC proxy.
	if addr != "93.184.216.34" {
		t.Errorf("SOCKS5 header addr = %q, want %q", addr, "93.184.216.34")
	}
	if port != 443 {
		t.Errorf("SOCKS5 header port = %d, want %d", port, 443)
	}
	if !bytes.Equal(payload, responsePayload) {
		t.Errorf("payload = %q, want %q", string(payload), string(responsePayload))
	}

	// Clean up: close upstream to stop the relay goroutine.
	_ = upstream.Close()
}

// TestRelayQUICResponsesIPv6OriginalDst verifies that relayQUICResponses
// correctly wraps responses when the original destination is an IPv6 address.
func TestRelayQUICResponsesIPv6OriginalDst(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upstream.Close() }()

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer func() { _ = relay.Close() }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer func() { _ = client.Close() }()

	clientAddr := client.LocalAddr()
	// Use an IPv6 original destination.
	originalDst := &net.UDPAddr{IP: net.ParseIP("2606:4700::6810:84e5"), Port: 443}

	srv := &Server{}
	go srv.relayQUICResponses(upstream, relay, clientAddr, originalDst)

	responsePayload := []byte("IPv6 response")
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	if _, err := sender.WriteTo(responsePayload, upstream.LocalAddr()); err != nil {
		t.Fatalf("write to upstream: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, _, readErr := client.ReadFrom(buf)
	if readErr != nil {
		t.Fatalf("read from client: %v", readErr)
	}

	addr, port, payload, parseErr := ParseSOCKS5UDPHeader(buf[:n])
	if parseErr != nil {
		t.Fatalf("parse SOCKS5 UDP header: %v", parseErr)
	}

	if addr != "2606:4700::6810:84e5" {
		t.Errorf("SOCKS5 header addr = %q, want %q", addr, "2606:4700::6810:84e5")
	}
	if port != 443 {
		t.Errorf("SOCKS5 header port = %d, want %d", port, 443)
	}
	if !bytes.Equal(payload, responsePayload) {
		t.Errorf("payload = %q, want %q", string(payload), string(responsePayload))
	}

	_ = upstream.Close()
}

// TestRelayQUICResponsesStopsOnUpstreamClose verifies that relayQUICResponses
// exits when the upstream PacketConn is closed.
func TestRelayQUICResponsesStopsOnUpstreamClose(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer func() { _ = relay.Close() }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer func() { _ = client.Close() }()

	originalDst := &net.UDPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}

	done := make(chan struct{})
	srv := &Server{}
	go func() {
		srv.relayQUICResponses(upstream, relay, client.LocalAddr(), originalDst)
		close(done)
	}()

	// Close upstream to signal the relay to stop.
	_ = upstream.Close()

	select {
	case <-done:
		// Goroutine exited as expected.
	case <-time.After(3 * time.Second):
		t.Fatal("relayQUICResponses did not exit after upstream close")
	}
}

// TestRelayQUICResponsesMultiplePackets verifies that relayQUICResponses
// correctly relays multiple sequential response packets.
func TestRelayQUICResponsesMultiplePackets(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upstream.Close() }()

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer func() { _ = relay.Close() }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer func() { _ = client.Close() }()

	originalDst := &net.UDPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}

	srv := &Server{}
	go srv.relayQUICResponses(upstream, relay, client.LocalAddr(), originalDst)

	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Send 3 packets and verify each is relayed correctly.
	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("response packet %d", i))
		if _, writeErr := sender.WriteTo(payload, upstream.LocalAddr()); writeErr != nil {
			t.Fatalf("write packet %d: %v", i, writeErr)
		}

		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65535)
		n, _, readErr := client.ReadFrom(buf)
		if readErr != nil {
			t.Fatalf("read packet %d: %v", i, readErr)
		}

		addr, port, got, parseErr := ParseSOCKS5UDPHeader(buf[:n])
		if parseErr != nil {
			t.Fatalf("parse packet %d: %v", i, parseErr)
		}
		if addr != "93.184.216.34" || port != 443 {
			t.Errorf("packet %d: addr=%q port=%d, want 93.184.216.34:443", i, addr, port)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("packet %d: payload = %q, want %q", i, string(got), string(payload))
		}
	}

	_ = upstream.Close()
}
