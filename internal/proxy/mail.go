package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/nemirovsky/sluice/internal/vault"
)

// MailProxy handles IMAP and SMTP connections by intercepting authentication
// commands and replacing phantom credentials with real ones from the vault.
//
// For IMAP: intercepts LOGIN and AUTHENTICATE PLAIN commands.
// For SMTP: intercepts AUTH PLAIN and AUTH LOGIN commands.
//
// The proxy relays all non-authentication traffic unchanged. Phantom tokens
// (SLUICE_PHANTOM:name) in authentication commands are replaced with real
// credentials. For base64-encoded auth data (AUTH PLAIN, AUTH LOGIN), the
// proxy decodes, replaces, and re-encodes.
//
// For implicit TLS ports (993 IMAPS, 465 SMTPS), the proxy terminates TLS
// from the agent using a per-host certificate signed by the proxy's CA, then
// establishes a separate TLS connection to the upstream server. This allows
// the proxy to read and modify plaintext IMAP/SMTP commands between the two
// TLS layers.
type MailProxy struct {
	provider vault.Provider
	caCert   *tls.Certificate // nil = no TLS MITM (implicit TLS ports passed through)
}

// NewMailProxy creates a mail protocol proxy for credential injection.
// If caCert is non-nil, implicit TLS ports (993, 465) are handled via
// TLS termination on the agent side.
func NewMailProxy(provider vault.Provider, caCert *tls.Certificate) *MailProxy {
	return &MailProxy{provider: provider, caCert: caCert}
}

// mailSession holds per-connection state for auth command tracking.
type mailSession struct {
	proxy              *MailProxy
	proto              Protocol
	mu                 sync.Mutex
	pendingPrompts     int  // server prompts expected after client auth command
	continuationsArmed int  // continuations confirmed by server (334/+), consumed by client
	inDataMode         bool // true after SMTP DATA command, before terminating "."
	starttlsPending    bool // client sent STARTTLS, waiting for server response
	starttlsConfirmed  bool // server confirmed STARTTLS (220 for SMTP, OK for IMAP)
}

// HandleConnection proxies a mail protocol connection, intercepting
// authentication commands and replacing phantom tokens with real
// credentials from the vault.
//
// The agentConn is the raw TCP stream from the agent (after SOCKS5
// handshake). dialAddrs is a list of policy-approved IP:port addresses
// to try in order for the upstream TCP connection. hostAddr is the
// FQDN:port used for TLS ServerName verification. For implicit TLS
// ports (993, 465), the agent-side connection is wrapped in a TLS
// server using the proxy's CA cert. For plaintext ports where the
// client negotiates STARTTLS, the proxy performs a TLS MITM upgrade
// mid-stream (if a CA cert is available) so credential injection
// continues over the encrypted session.
//
// The ready channel signals when setup is complete. nil means the handler
// is ready to relay traffic. A non-nil error means setup failed and the
// SOCKS5 layer should report a connection failure to the client.
func (m *MailProxy) HandleConnection(agentConn net.Conn, dialAddrs []string, hostAddr string, binding vault.Binding, proto Protocol, ready chan<- error) error {
	defer agentConn.Close()

	// signalErr sends an error on ready (if non-nil) to report setup
	// failure to the SOCKS5 layer before returning.
	signalErr := func(err error) error {
		if ready != nil {
			ready <- err
			ready = nil
		}
		return err
	}

	upstreamConn, err := m.dialUpstream(dialAddrs, hostAddr)
	if err != nil {
		return signalErr(err)
	}
	defer upstreamConn.Close()

	// For implicit TLS ports (993 IMAPS, 465 SMTPS), the agent's mail
	// client starts TLS immediately. The proxy must terminate that TLS
	// to read plaintext IMAP/SMTP for credential injection. A per-host
	// certificate signed by the proxy's CA is presented to the agent.
	_, portStr, _ := net.SplitHostPort(dialAddrs[0])
	port, _ := strconv.Atoi(portStr)
	host, _, _ := net.SplitHostPort(hostAddr)

	// agentRW and upstreamRW are the plaintext views used for line-by-line
	// protocol parsing. For implicit TLS ports the agent side is a
	// decrypted TLS stream. For plaintext ports they start as the raw
	// TCP connections and may be upgraded to TLS after STARTTLS.
	var agentRW io.ReadWriter = agentConn
	var upstreamRW io.ReadWriter = upstreamConn

	// For implicit TLS ports (993, 465), prepare the host cert before
	// signaling ready. The actual TLS handshake must happen AFTER the
	// SOCKS5 CONNECT success is sent, because the agent cannot send a
	// TLS ClientHello until the SOCKS tunnel is established.
	var implicitTLSCert *tls.Certificate
	if isImplicitTLSPort(port) && m.caCert != nil {
		hostCert, certErr := GenerateHostCert(*m.caCert, host)
		if certErr != nil {
			return signalErr(fmt.Errorf("generate host cert for %s: %w", host, certErr))
		}
		implicitTLSCert = &hostCert
	}

	// Setup complete. Signal the SOCKS5 layer to send CONNECT success.
	if ready != nil {
		ready <- nil
		ready = nil
	}

	// Perform agent-side TLS handshake after SOCKS CONNECT success so
	// the agent can send its ClientHello through the established tunnel.
	if implicitTLSCert != nil {
		tlsConn := tls.Server(agentConn, &tls.Config{
			Certificates: []tls.Certificate{*implicitTLSCert},
		})
		if tlsErr := tlsConn.Handshake(); tlsErr != nil {
			return fmt.Errorf("agent TLS handshake for %s: %w", host, tlsErr)
		}
		agentRW = tlsConn
		log.Printf("[MAIL] TLS terminated for agent connection to %s:%d", host, port)
	}

	phantom := PhantomToken(binding.Credential)
	log.Printf("[MAIL] proxying %s connection to %s via credential %q", proto, hostAddr, binding.Credential)

	sess := &mailSession{proxy: m, proto: proto}

	// Channel-based relay: two goroutines read lines from each side and
	// send them to a shared select loop. This allows the loop to pause
	// agent reads during STARTTLS negotiation and perform a TLS MITM
	// upgrade before binary TLS records hit the line readers.
	agentReader := bufio.NewReader(agentRW)
	serverReader := bufio.NewReader(upstreamRW)

	type readResult struct {
		line string
		err  error
	}

	agentCh := make(chan readResult, 1)
	serverCh := make(chan readResult, 1)

	readAsync := func(r *bufio.Reader, ch chan<- readResult) {
		line, readErr := r.ReadString('\n')
		ch <- readResult{line, readErr}
	}

	go readAsync(agentReader, agentCh)
	go readAsync(serverReader, serverCh)

	agentPaused := false

	for {
		select {
		case r := <-agentCh:
			if len(r.line) > 0 {
				modified := sess.processLine(r.line, phantom, binding)
				if _, writeErr := io.WriteString(upstreamRW, modified); writeErr != nil {
					return nil
				}
			}
			if r.err != nil {
				return nil
			}
			sess.mu.Lock()
			pending := sess.starttlsPending
			sess.mu.Unlock()
			if pending {
				// Client sent STARTTLS. Pause agent reads until the
				// server confirms (the client won't send anything
				// else until it receives the server's response).
				agentPaused = true
			} else {
				go readAsync(agentReader, agentCh)
			}

		case r := <-serverCh:
			if len(r.line) > 0 {
				sess.processServerLine(r.line)
				if _, writeErr := io.WriteString(agentRW, r.line); writeErr != nil {
					return nil
				}
			}
			if r.err != nil {
				return nil
			}

			sess.mu.Lock()
			confirmed := sess.starttlsConfirmed
			pending := sess.starttlsPending
			sess.mu.Unlock()

			if confirmed {
				sess.mu.Lock()
				sess.starttlsConfirmed = false
				sess.mu.Unlock()

				if m.caCert == nil {
					// No CA cert: raw relay without credential injection.
					// The TLS handshake proceeds end-to-end between agent
					// and upstream. The proxy passes bytes transparently.
					log.Printf("[MAIL] STARTTLS on %s without CA cert; raw relay (no credential injection)", hostAddr)
					done := make(chan struct{})
					go func() {
						io.Copy(agentRW, serverReader)
						agentConn.Close()
						close(done)
					}()
					io.Copy(upstreamRW, agentReader)
					upstreamConn.Close()
					<-done
					return nil
				}

				// Upgrade upstream: wrap raw TCP in TLS client.
				tlsUpstream := tls.Client(upstreamConn, &tls.Config{
					ServerName: host,
				})
				if tlsErr := tlsUpstream.Handshake(); tlsErr != nil {
					return fmt.Errorf("upstream STARTTLS handshake for %s: %w", host, tlsErr)
				}
				upstreamRW = tlsUpstream

				// Upgrade agent: wrap raw TCP in TLS server.
				hostCert, certErr := GenerateHostCert(*m.caCert, host)
				if certErr != nil {
					return fmt.Errorf("generate host cert for STARTTLS %s: %w", host, certErr)
				}
				agentTLS := tls.Server(agentConn, &tls.Config{
					Certificates: []tls.Certificate{hostCert},
				})
				if tlsErr := agentTLS.Handshake(); tlsErr != nil {
					return fmt.Errorf("agent STARTTLS handshake for %s: %w", host, tlsErr)
				}
				agentRW = agentTLS

				log.Printf("[MAIL] STARTTLS MITM upgrade complete for %s", host)

				// Reset readers for the new TLS connections and resume
				// the relay. The mail client will re-send EHLO/CAPABILITY
				// over TLS before issuing AUTH commands.
				agentReader = bufio.NewReader(agentRW)
				serverReader = bufio.NewReader(upstreamRW)
				agentPaused = false
				go readAsync(agentReader, agentCh)
				go readAsync(serverReader, serverCh)
			} else {
				go readAsync(serverReader, serverCh)
				// If STARTTLS was rejected by the server, resume agent reads.
				if agentPaused && !pending {
					agentPaused = false
					go readAsync(agentReader, agentCh)
				}
			}
		}
	}
}

// processServerLine inspects a server response line and arms base64
// continuation processing when the server sends a continuation prompt
// (334 for SMTP, + for IMAP). This ensures phantom token replacement
// only occurs when the server has actually requested auth continuation,
// preventing a malicious client from triggering credential injection
// without server cooperation.
func (sess *mailSession) processServerLine(line string) {
	trimmed := strings.TrimRight(line, "\r\n")

	sess.mu.Lock()
	defer sess.mu.Unlock()

	// STARTTLS response handling. When the client sent STARTTLS, the
	// server's response determines whether TLS upgrade proceeds.
	if sess.starttlsPending {
		// SMTP: 220 = STARTTLS accepted (RFC 3207).
		if sess.proto == ProtoSMTP && strings.HasPrefix(trimmed, "220") {
			sess.starttlsPending = false
			sess.starttlsConfirmed = true
			return
		}
		// SMTP: any other status code = STARTTLS rejected.
		if sess.proto == ProtoSMTP && len(trimmed) >= 3 &&
			trimmed[0] >= '1' && trimmed[0] <= '5' &&
			trimmed[1] >= '0' && trimmed[1] <= '9' &&
			trimmed[2] >= '0' && trimmed[2] <= '9' {
			sess.starttlsPending = false
			return
		}
		// IMAP: tagged OK = STARTTLS accepted (RFC 2595).
		// Tagged response without OK = STARTTLS rejected.
		if sess.proto == ProtoIMAP && len(trimmed) > 0 &&
			trimmed[0] != '*' && trimmed[0] != '+' {
			if strings.Contains(strings.ToUpper(trimmed), " OK") {
				sess.starttlsPending = false
				sess.starttlsConfirmed = true
				return
			}
			sess.starttlsPending = false
			return
		}
	}

	if sess.pendingPrompts <= 0 {
		return
	}

	// SMTP: 334 response is the AUTH continuation prompt (RFC 4954).
	if sess.proto == ProtoSMTP && (trimmed == "334" || strings.HasPrefix(trimmed, "334 ")) {
		sess.pendingPrompts--
		sess.continuationsArmed++
		return
	}

	// IMAP: + is the continuation response (RFC 3501 Section 7.5).
	if sess.proto == ProtoIMAP && (trimmed == "+" || strings.HasPrefix(trimmed, "+ ")) {
		sess.pendingPrompts--
		sess.continuationsArmed++
		return
	}

	// Server sent a non-continuation response while prompts were pending.
	// The auth command was rejected or unsupported. Clear pending state
	// to avoid stale arming from a later unrelated 334/+ response.
	// SMTP: any 3-digit response code that isn't 334.
	if sess.proto == ProtoSMTP && len(trimmed) >= 3 &&
		trimmed[0] >= '1' && trimmed[0] <= '5' &&
		trimmed[1] >= '0' && trimmed[1] <= '9' &&
		trimmed[2] >= '0' && trimmed[2] <= '9' {
		sess.pendingPrompts = 0
		return
	}
	// IMAP: any tagged response (not * untagged, not + continuation)
	// indicates the command completed without continuation.
	if sess.proto == ProtoIMAP && len(trimmed) > 0 && trimmed[0] != '*' && trimmed[0] != '+' {
		sess.pendingPrompts = 0
	}
}

// isImplicitTLSPort returns true for mail ports that use implicit TLS
// (connection starts with a TLS handshake, no STARTTLS negotiation).
func isImplicitTLSPort(port int) bool {
	return port == 993 || port == 465
}

// dialUpstream connects to the upstream mail server, trying each address in
// dialAddrs in order. For implicit-TLS ports (993 for IMAPS, 465 for SMTPS),
// the connection is wrapped in TLS with the FQDN from hostAddr as the
// ServerName for certificate verification. For plaintext ports (143, 25, 587),
// a raw TCP connection is used. All addresses share the same port (they are
// resolved IPs for the same destination).
func (m *MailProxy) dialUpstream(dialAddrs []string, hostAddr string) (net.Conn, error) {
	if len(dialAddrs) == 0 {
		return nil, fmt.Errorf("no dial addresses provided")
	}

	_, portStr, err := net.SplitHostPort(dialAddrs[0])
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	// Extract FQDN from hostAddr for TLS ServerName verification.
	host, _, _ := net.SplitHostPort(hostAddr)

	var lastErr error
	for _, addr := range dialAddrs {
		if isImplicitTLSPort(port) {
			dialer := &net.Dialer{Timeout: connectTimeout}
			conn, dialErr := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName: host,
			})
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		} else {
			conn, dialErr := net.DialTimeout("tcp", addr, connectTimeout)
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
	}
	return nil, fmt.Errorf("dial upstream %v: %w", dialAddrs, lastErr)
}

// processLine inspects a line from the agent and replaces phantom tokens
// in authentication commands. It handles three cases:
//
//  1. Direct phantom token in the line (IMAP LOGIN command).
//  2. Inline base64 after AUTH PLAIN / AUTHENTICATE PLAIN.
//  3. Standalone base64 continuation line only when the previous command
//     indicated continuation data is expected (AUTH PLAIN without inline
//     data, AUTHENTICATE PLAIN without inline data, AUTH LOGIN).
func (sess *mailSession) processLine(line, phantom string, binding vault.Binding) string {
	trimmed := strings.TrimRight(line, "\r\n")
	upper := strings.ToUpper(trimmed)

	// SMTP DATA mode: after the DATA command, the client sends the message
	// body until a line containing only ".". During this phase, we must NOT
	// replace phantom tokens because the message body is untrusted content.
	// An attacker could embed a phantom token in an email to exfiltrate the
	// real credential to the upstream server.
	if sess.inDataMode {
		if trimmed == "." {
			sess.inDataMode = false
		}
		return line
	}

	// Detect SMTP DATA command. The server will respond with 354, and all
	// subsequent client lines are message body until the terminating ".".
	if sess.proto == ProtoSMTP && upper == "DATA" {
		sess.inDataMode = true
		return line
	}

	// Detect STARTTLS command from client. On plaintext mail ports,
	// STARTTLS upgrades the connection to TLS mid-stream. The relay
	// pauses agent reads, waits for the server's confirmation, and
	// then performs a TLS MITM upgrade to continue credential injection.
	if (sess.proto == ProtoSMTP && upper == "STARTTLS") ||
		(sess.proto == ProtoIMAP && isIMAPSTARTTLS(upper)) {
		sess.mu.Lock()
		sess.starttlsPending = true
		sess.mu.Unlock()
		return line
	}

	// Direct phantom token replacement is restricted to IMAP LOGIN
	// commands only. Replacing in arbitrary commands (MAIL FROM, RCPT TO,
	// APPEND, etc.) would let an attacker embed a phantom token in a
	// non-auth command and exfiltrate the real credential upstream.
	if sess.proto == ProtoIMAP && isIMAPLogin(upper) && strings.Contains(trimmed, phantom) {
		sess.mu.Lock()
		sess.pendingPrompts = 0
		sess.continuationsArmed = 0
		sess.mu.Unlock()
		return sess.proxy.replacePhantom(trimmed, phantom, binding) + "\r\n"
	}

	// AUTH PLAIN / AUTHENTICATE PLAIN with inline base64 data.
	if b64, prefix, ok := extractAuthPlainBase64(upper, trimmed); ok {
		sess.mu.Lock()
		sess.pendingPrompts = 0
		sess.continuationsArmed = 0
		sess.mu.Unlock()
		if replaced, didReplace := sess.proxy.tryReplaceBase64(b64, phantom, binding); didReplace {
			return prefix + replaced + "\r\n"
		}
		return line
	}

	// Check for auth commands that expect base64 continuation on following lines.
	// Don't arm continuations immediately; wait for the server to send a
	// continuation prompt (334 for SMTP, + for IMAP) before allowing
	// phantom replacement. This prevents a malicious client from triggering
	// credential injection without server confirmation.
	if n := authContinuationCount(upper); n > 0 {
		sess.mu.Lock()
		sess.pendingPrompts = n
		sess.mu.Unlock()
		return line
	}

	// Standalone base64 continuation line, only when the server has confirmed
	// with a continuation prompt (334/+). Without server confirmation,
	// the line is forwarded unchanged.
	sess.mu.Lock()
	armed := sess.continuationsArmed
	if armed > 0 {
		sess.continuationsArmed--
	}
	sess.mu.Unlock()
	if armed > 0 {
		if replaced, didReplace := sess.proxy.tryReplaceBase64(trimmed, phantom, binding); didReplace {
			return replaced + "\r\n"
		}
	}

	return line
}

// isIMAPLogin returns true if the uppercased line matches an IMAP LOGIN
// command. IMAP LOGIN format: "tag LOGIN username password".
func isIMAPLogin(upper string) bool {
	fields := strings.Fields(upper)
	return len(fields) >= 2 && fields[1] == "LOGIN"
}

// isIMAPSTARTTLS returns true if the uppercased line matches an IMAP
// STARTTLS command. IMAP STARTTLS format: "tag STARTTLS".
func isIMAPSTARTTLS(upper string) bool {
	fields := strings.Fields(upper)
	return len(fields) >= 2 && fields[1] == "STARTTLS"
}

// authContinuationCount returns the number of base64 continuation lines
// expected after the given auth command, or 0 if this is not such a command.
// AUTH LOGIN expects 2 continuations (username, then password).
// AUTH PLAIN and AUTHENTICATE PLAIN expect 1 continuation.
func authContinuationCount(upper string) int {
	// SMTP: "AUTH PLAIN\r\n" (no inline data, continuation follows)
	if upper == "AUTH PLAIN" {
		return 1
	}
	// SMTP: "AUTH LOGIN" (no inline data) expects two continuation lines
	// (username + password). "AUTH LOGIN <initial-response>" already has
	// the username inline, so only 1 continuation (password) follows.
	if upper == "AUTH LOGIN" {
		return 2
	}
	if strings.HasPrefix(upper, "AUTH LOGIN ") {
		return 1
	}
	// IMAP: "tag AUTHENTICATE PLAIN\r\n" (no inline data)
	if strings.HasSuffix(upper, " AUTHENTICATE PLAIN") {
		return 1
	}
	return 0
}

// extractAuthPlainBase64 finds inline base64 data in AUTH PLAIN or
// AUTHENTICATE PLAIN commands. Returns the base64 portion, the line
// prefix to preserve, and whether a match was found.
func extractAuthPlainBase64(upper, original string) (b64, prefix string, found bool) {
	// SMTP: "AUTH PLAIN <base64>"
	const smtpAuthPlain = "AUTH PLAIN "
	if strings.HasPrefix(upper, smtpAuthPlain) {
		b64 = original[len(smtpAuthPlain):]
		if b64 != "" {
			return b64, original[:len(smtpAuthPlain)], true
		}
	}
	// IMAP: "tag AUTHENTICATE PLAIN <base64>"
	const imapAuthPlain = " AUTHENTICATE PLAIN "
	if idx := strings.Index(upper, imapAuthPlain); idx >= 0 {
		dataStart := idx + len(imapAuthPlain)
		if dataStart < len(original) {
			return original[dataStart:], original[:dataStart], true
		}
	}
	return "", "", false
}

// replacePhantom does a direct string replacement of the phantom token
// with the real credential value from the vault.
func (m *MailProxy) replacePhantom(line, phantom string, binding vault.Binding) string {
	secret, err := m.provider.Get(binding.Credential)
	if err != nil {
		log.Printf("[MAIL] credential %q lookup failed: %v", binding.Credential, err)
		return line
	}
	defer secret.Release()

	replaced := strings.ReplaceAll(line, phantom, secret.String())
	log.Printf("[MAIL] injected credential %q", binding.Credential)
	return replaced
}

// tryReplaceBase64 attempts to base64-decode the value, replace phantom
// tokens in the decoded form, and re-encode. Returns the replaced string
// and true if a replacement was made.
func (m *MailProxy) tryReplaceBase64(value, phantom string, binding vault.Binding) (string, bool) {
	if len(value) == 0 {
		return value, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return value, false
	}
	if !bytes.Contains(decoded, []byte(phantom)) {
		return value, false
	}

	secret, err := m.provider.Get(binding.Credential)
	if err != nil {
		log.Printf("[MAIL] credential %q lookup failed: %v", binding.Credential, err)
		return value, false
	}
	defer secret.Release()

	replaced := bytes.ReplaceAll(decoded, []byte(phantom), []byte(secret.String()))
	encoded := base64.StdEncoding.EncodeToString(replaced)
	log.Printf("[MAIL] injected credential %q (base64)", binding.Credential)
	return encoded, true
}
