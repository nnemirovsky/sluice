package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

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
type MailProxy struct {
	provider vault.Provider
}

// NewMailProxy creates a mail protocol proxy for credential injection.
func NewMailProxy(provider vault.Provider) *MailProxy {
	return &MailProxy{provider: provider}
}

// mailSession holds per-connection state for auth command tracking.
type mailSession struct {
	proxy          *MailProxy
	expectBase64   bool // true when next line should be base64 auth continuation
}

// HandleConnection proxies a mail protocol connection, intercepting
// authentication commands and replacing phantom tokens with real
// credentials from the vault.
//
// The agentConn is the raw TCP stream from the agent (after SOCKS5
// handshake). The upstreamAddr is the target host:port. TLS wrapping
// for implicit TLS ports (993, 465) is handled at a lower layer.
func (m *MailProxy) HandleConnection(agentConn net.Conn, upstreamAddr string, binding vault.Binding, proto Protocol) error {
	upstreamConn, err := net.DialTimeout("tcp", upstreamAddr, connectTimeout)
	if err != nil {
		return fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}

	phantom := PhantomToken(binding.Credential)
	done := make(chan struct{})

	log.Printf("[MAIL] proxying %s connection to %s via credential %q", proto, upstreamAddr, binding.Credential)

	// Upstream -> agent: relay unchanged.
	go func() {
		io.Copy(agentConn, upstreamConn)
		close(done)
	}()

	sess := &mailSession{proxy: m}

	// Agent -> upstream: read lines and replace phantom tokens in auth commands.
	reader := bufio.NewReader(agentConn)
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			modified := sess.processLine(line, phantom, binding)
			if _, writeErr := io.WriteString(upstreamConn, modified); writeErr != nil {
				break
			}
		}
		if readErr != nil {
			break
		}
	}

	upstreamConn.Close()
	<-done
	return nil
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

	// Direct phantom token in the line (e.g., IMAP LOGIN command).
	if strings.Contains(trimmed, phantom) {
		sess.expectBase64 = false
		return sess.proxy.replacePhantom(trimmed, phantom, binding) + "\r\n"
	}

	upper := strings.ToUpper(trimmed)

	// AUTH PLAIN / AUTHENTICATE PLAIN with inline base64 data.
	if b64, prefix, ok := extractAuthPlainBase64(upper, trimmed); ok {
		sess.expectBase64 = false
		if replaced, didReplace := sess.proxy.tryReplaceBase64(b64, phantom, binding); didReplace {
			return prefix + replaced + "\r\n"
		}
		return line
	}

	// Check for auth commands that expect base64 continuation on the next line.
	if isAuthContinuationTrigger(upper) {
		sess.expectBase64 = true
		return line
	}

	// Standalone base64 continuation line, only when expected after an auth command.
	if sess.expectBase64 {
		sess.expectBase64 = false
		if replaced, didReplace := sess.proxy.tryReplaceBase64(trimmed, phantom, binding); didReplace {
			return replaced + "\r\n"
		}
	}

	return line
}

// isAuthContinuationTrigger returns true if the line is an auth command
// that expects base64 data on the following line(s).
func isAuthContinuationTrigger(upper string) bool {
	// SMTP: "AUTH PLAIN\r\n" (no inline data, continuation follows)
	if upper == "AUTH PLAIN" {
		return true
	}
	// SMTP: "AUTH LOGIN" or "AUTH LOGIN\r\n"
	if upper == "AUTH LOGIN" || strings.HasPrefix(upper, "AUTH LOGIN ") {
		return true
	}
	// IMAP: "tag AUTHENTICATE PLAIN\r\n" (no inline data)
	if strings.HasSuffix(upper, " AUTHENTICATE PLAIN") {
		return true
	}
	return false
}

// extractAuthPlainBase64 finds inline base64 data in AUTH PLAIN or
// AUTHENTICATE PLAIN commands. Returns the base64 portion, the line
// prefix to preserve, and whether a match was found.
func extractAuthPlainBase64(upper, original string) (b64, prefix string, found bool) {
	// SMTP: "AUTH PLAIN <base64>"
	const smtpAuthPlain = "AUTH PLAIN "
	if strings.HasPrefix(upper, smtpAuthPlain) {
		return original[len(smtpAuthPlain):], original[:len(smtpAuthPlain)], true
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
