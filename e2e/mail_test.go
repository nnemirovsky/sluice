//go:build e2e

package e2e

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// startMockIMAPServer starts a minimal IMAP server on a free port. It
// responds to CAPABILITY, LOGIN, and LOGOUT commands. The server records
// received LOGIN credentials for verification.
func startMockIMAPServer(t *testing.T) (addr string, credentials chan string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	creds := make(chan string, 10)

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go handleIMAPConn(conn, creds)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), creds
}

// handleIMAPConn handles a single IMAP client connection.
func handleIMAPConn(conn net.Conn, creds chan string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Send server greeting.
	fmt.Fprintf(conn, "* OK IMAP4rev1 Mock Server ready\r\n")

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}

		tag := parts[0]
		cmd := strings.ToUpper(parts[1])

		switch cmd {
		case "CAPABILITY":
			fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN\r\n")
			fmt.Fprintf(conn, "%s OK CAPABILITY completed\r\n", tag)
		case "LOGIN":
			// LOGIN <username> <password>
			if len(parts) >= 3 {
				creds <- parts[2] // Send "user pass" or just the args
			}
			fmt.Fprintf(conn, "%s OK LOGIN completed\r\n", tag)
		case "LOGOUT":
			fmt.Fprintf(conn, "* BYE Mock Server signing off\r\n")
			fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return
		case "NOOP":
			fmt.Fprintf(conn, "%s OK NOOP completed\r\n", tag)
		default:
			fmt.Fprintf(conn, "%s BAD Unknown command\r\n", tag)
		}
	}
}

// startMockSMTPServer starts a minimal SMTP server on a free port. It
// responds to EHLO, AUTH, and QUIT commands.
func startMockSMTPServer(t *testing.T) (addr string, credentials chan string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	creds := make(chan string, 10)

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go handleSMTPConn(conn, creds)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), creds
}

// handleSMTPConn handles a single SMTP client connection.
func handleSMTPConn(conn net.Conn, creds chan string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Send server greeting.
	fmt.Fprintf(conn, "220 mock.smtp.server ESMTP ready\r\n")

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			fmt.Fprintf(conn, "250-mock.smtp.server Hello\r\n")
			fmt.Fprintf(conn, "250-AUTH PLAIN LOGIN\r\n")
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			// AUTH PLAIN may have the base64 data inline.
			if len(line) > 11 {
				creds <- line[11:] // base64 data
			}
			fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
		case strings.HasPrefix(cmd, "AUTH LOGIN"):
			fmt.Fprintf(conn, "334 VXNlcm5hbWU6\r\n") // "Username:" in base64
			userLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			creds <- strings.TrimRight(userLine, "\r\n")
			fmt.Fprintf(conn, "334 UGFzc3dvcmQ6\r\n") // "Password:" in base64
			passLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			creds <- strings.TrimRight(passLine, "\r\n")
			fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			fmt.Fprintf(conn, "221 2.0.0 Bye\r\n")
			return
		case strings.HasPrefix(cmd, "NOOP"):
			fmt.Fprintf(conn, "250 OK\r\n")
		default:
			fmt.Fprintf(conn, "500 Unrecognized command\r\n")
		}
	}
}

// TestMail_IMAPAllowRulePermitsConnection verifies that an IMAP connection
// through the SOCKS5 proxy succeeds when an allow rule is configured.
func TestMail_IMAPAllowRulePermitsConnection(t *testing.T) {
	imapAddr, _ := startMockIMAPServer(t)
	host, port := splitHostPort(t, imapAddr)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow mock imap"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Connect through SOCKS5 to the IMAP server.
	dialer := connectSOCKS5(t, proc.ProxyAddr)
	conn, err := dialer.Dial("tcp", imapAddr)
	if err != nil {
		t.Fatalf("SOCKS5 dial to IMAP: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read server greeting.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read IMAP greeting: %v", err)
	}
	if !strings.Contains(greeting, "OK") {
		t.Fatalf("expected OK greeting, got: %s", greeting)
	}

	// Send CAPABILITY command.
	fmt.Fprintf(conn, "a001 CAPABILITY\r\n")
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read CAPABILITY response: %v", readErr)
		}
		if strings.HasPrefix(line, "a001 ") {
			if !strings.Contains(line, "OK") {
				t.Fatalf("CAPABILITY failed: %s", line)
			}
			break
		}
	}

	// Send LOGOUT.
	fmt.Fprintf(conn, "a002 LOGOUT\r\n")
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			break
		}
		if strings.HasPrefix(line, "a002 ") {
			break
		}
	}

	// Verify audit log recorded the connection.
	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, host) {
		t.Error("audit log should contain entry for IMAP connection")
	}
}

// TestMail_IMAPDenyRuleBlocksConnection verifies that a deny rule prevents
// IMAP connections through the SOCKS5 proxy.
func TestMail_IMAPDenyRuleBlocksConnection(t *testing.T) {
	imapAddr, _ := startMockIMAPServer(t)
	host, port := splitHostPort(t, imapAddr)

	config := fmt.Sprintf(`
[policy]
default = "allow"

[[deny]]
destination = "%s"
ports = [%s]
name = "block mock imap"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	dialer := connectSOCKS5(t, proc.ProxyAddr)
	conn, err := dialer.Dial("tcp", imapAddr)
	if err != nil {
		// Connection denied at SOCKS5 level. This is the expected outcome.
		time.Sleep(500 * time.Millisecond)
		if !auditLogContains(t, proc.AuditPath, `"verdict":"deny"`) {
			t.Error("audit log should contain deny verdict for blocked IMAP")
		}
		return
	}
	defer conn.Close()

	// If SOCKS5 CONNECT succeeded (some implementations allow CONNECT but
	// refuse at a higher level), verify the connection does not work.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected IMAP connection to be denied, but received data")
	}
}

// TestMail_SMTPAllowRulePermitsConnection verifies that an SMTP connection
// through the SOCKS5 proxy succeeds when an allow rule is configured.
func TestMail_SMTPAllowRulePermitsConnection(t *testing.T) {
	smtpAddr, _ := startMockSMTPServer(t)
	host, port := splitHostPort(t, smtpAddr)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow mock smtp"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	dialer := connectSOCKS5(t, proc.ProxyAddr)
	conn, err := dialer.Dial("tcp", smtpAddr)
	if err != nil {
		t.Fatalf("SOCKS5 dial to SMTP: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read server greeting.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read SMTP greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("expected 220 greeting, got: %s", greeting)
	}

	// Send EHLO.
	fmt.Fprintf(conn, "EHLO test.local\r\n")
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read EHLO response: %v", readErr)
		}
		// Multi-line EHLO: lines start with "250-", final line starts with "250 ".
		if strings.HasPrefix(line, "250 ") {
			break
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("unexpected EHLO response: %s", line)
		}
	}

	// Send QUIT.
	fmt.Fprintf(conn, "QUIT\r\n")
	quitResp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(quitResp, "221") {
		t.Errorf("expected 221 on QUIT, got: %s", quitResp)
	}

	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, proc.AuditPath, host) {
		t.Error("audit log should contain entry for SMTP connection")
	}
}

// TestMail_SMTPDenyRuleBlocksConnection verifies that a deny rule prevents
// SMTP connections through the SOCKS5 proxy.
func TestMail_SMTPDenyRuleBlocksConnection(t *testing.T) {
	smtpAddr, _ := startMockSMTPServer(t)
	host, port := splitHostPort(t, smtpAddr)

	config := fmt.Sprintf(`
[policy]
default = "allow"

[[deny]]
destination = "%s"
ports = [%s]
name = "block mock smtp"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	dialer := connectSOCKS5(t, proc.ProxyAddr)
	conn, err := dialer.Dial("tcp", smtpAddr)
	if err != nil {
		// Connection denied at SOCKS5 level.
		time.Sleep(500 * time.Millisecond)
		if !auditLogContains(t, proc.AuditPath, `"verdict":"deny"`) {
			t.Error("audit log should contain deny verdict for blocked SMTP")
		}
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected SMTP connection to be denied, but received data")
	}
}
