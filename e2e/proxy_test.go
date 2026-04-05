//go:build e2e

package e2e

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestProxy_AllowRulePermitsConnection verifies that an explicit allow rule
// lets traffic through the SOCKS5 proxy to the echo server.
func TestProxy_AllowRulePermitsConnection(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow echo server"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	status, body := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/hello")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if !strings.Contains(body, "URL: /hello") {
		t.Fatalf("echo server did not reflect request URL, got: %s", body)
	}
}

// TestProxy_DenyRuleBlocksConnection verifies that an explicit deny rule
// prevents traffic through the SOCKS5 proxy.
func TestProxy_DenyRuleBlocksConnection(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "allow"

[[deny]]
destination = "%s"
ports = [%s]
name = "block echo server"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/blocked")
	if err == nil {
		t.Fatal("expected connection to be denied, but it succeeded")
	}
	if !auditLogContains(t, proc.AuditPath, `"verdict":"deny"`) {
		t.Fatal("audit log should contain deny verdict")
	}
}

// TestProxy_AskWithoutBrokerAutoDenies verifies that ask rules are treated
// as deny when no approval broker (Telegram) is configured.
func TestProxy_AskWithoutBrokerAutoDenies(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%s]
name = "ask for echo server"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/ask")
	if err == nil {
		t.Fatal("expected ask-without-broker to deny, but connection succeeded")
	}
	if !auditLogContains(t, proc.AuditPath, `"verdict":"deny"`) {
		t.Fatal("audit log should contain deny verdict for ask-without-broker")
	}
}

// TestProxy_DefaultVerdictApplies verifies that when no rule matches, the
// default verdict is used.
func TestProxy_DefaultVerdictApplies(t *testing.T) {
	echo := startEchoServer(t)

	t.Run("default_deny", func(t *testing.T) {
		config := `
[policy]
default = "deny"
`
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/test")
		if err == nil {
			t.Fatal("expected default deny to block connection")
		}
	})

	t.Run("default_allow", func(t *testing.T) {
		config := `
[policy]
default = "allow"
`
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		status, body := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/test")
		if status != 200 {
			t.Fatalf("expected 200, got %d", status)
		}
		if !strings.Contains(body, "URL: /test") {
			t.Fatalf("expected echo response, got: %s", body)
		}
	})
}

// TestProxy_GlobPatterns verifies that glob patterns in policy rules match
// correctly. Single * matches one label (octet for IPs), ** matches across dots.
func TestProxy_GlobPatterns(t *testing.T) {
	echo := startEchoServer(t)
	_, port := mustSplitAddr(t, echo.URL)

	t.Run("star_matches_single_label", func(t *testing.T) {
		config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.*"
ports = [%s]
name = "single star"
`, port)
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/glob")
		if status != 200 {
			t.Fatalf("expected 200 with 127.0.0.* pattern, got %d", status)
		}
	})

	t.Run("star_does_not_match_across_dots", func(t *testing.T) {
		config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.*"
ports = [%s]
name = "single star should not cross dots"
`, port)
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/glob")
		if err == nil {
			t.Fatal("expected 127.* to NOT match 127.0.0.1")
		}
	})

	t.Run("doublestar_matches_across_dots", func(t *testing.T) {
		config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.**"
ports = [%s]
name = "double star crosses dots"
`, port)
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/glob")
		if status != 200 {
			t.Fatalf("expected 200 with 127.** pattern, got %d", status)
		}
	})
}

// TestProxy_PortSpecificRules verifies that port restrictions on rules work:
// allow one port but deny another for the same destination.
func TestProxy_PortSpecificRules(t *testing.T) {
	echoA := startEchoServer(t)
	echoB := startEchoServer(t)
	_, portA := mustSplitAddr(t, echoA.URL)
	_, portB := mustSplitAddr(t, echoB.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
ports = [%s]
name = "allow port A"

[[deny]]
destination = "127.0.0.1"
ports = [%s]
name = "deny port B"
`, portA, portB)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echoA.URL+"/portA")
	if status != 200 {
		t.Fatalf("expected port A to be allowed, got status %d", status)
	}

	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echoB.URL+"/portB")
	if err == nil {
		t.Fatal("expected port B to be denied, but it succeeded")
	}
}

// TestProxy_ProtocolSpecificRules verifies that rules with protocols
// restrictions only match when the port maps to the specified protocol.
// On non-standard ports, portToProtocol returns "" so protocol-scoped rules
// do not match.
func TestProxy_ProtocolSpecificRules(t *testing.T) {
	echo := startEchoServer(t)
	_, port := mustSplitAddr(t, echo.URL)

	t.Run("protocol_scoped_rule_rejects_non_standard_port", func(t *testing.T) {
		// protocols=["https"] will not match the echo server's random port
		// because portToProtocol returns "" for non-standard ports.
		config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
ports = [%s]
protocols = ["https"]
name = "https only"
`, port)
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/proto")
		if err == nil {
			t.Fatal("expected protocol-scoped rule to not match non-standard port")
		}
	})

	t.Run("unscoped_rule_allows_any_port", func(t *testing.T) {
		config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
ports = [%s]
name = "any protocol"
`, port)
		proc := startSluice(t, SluiceOpts{ConfigTOML: config})
		status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/proto")
		if status != 200 {
			t.Fatalf("expected unscoped rule to allow, got status %d", status)
		}
	})
}

// TestProxy_PolicyImportViaCLI verifies that importing a TOML policy file
// via the CLI and sending SIGHUP makes the proxy enforce the new rules.
func TestProxy_PolicyImportViaCLI(t *testing.T) {
	echo := startEchoServer(t)
	_, port := mustSplitAddr(t, echo.URL)

	config := `
[policy]
default = "deny"
`
	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Connection should be denied before import.
	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/before")
	if err == nil {
		t.Fatal("expected deny before import")
	}

	// Import an allow rule via CLI.
	importTOML := fmt.Sprintf(`
[[allow]]
destination = "127.0.0.1"
ports = [%s]
name = "imported allow"
`, port)
	importConfig(t, proc, importTOML)
	sendSIGHUP(t, proc)

	// Connection should now be allowed.
	status, body := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/after")
	if status != 200 {
		t.Fatalf("expected 200 after import + SIGHUP, got %d", status)
	}
	if !strings.Contains(body, "URL: /after") {
		t.Fatalf("expected echo response, got: %s", body)
	}
}

// TestProxy_DynamicRuleAddViaCLI verifies that adding a rule via the CLI
// and sending SIGHUP makes the proxy allow previously denied traffic.
func TestProxy_DynamicRuleAddViaCLI(t *testing.T) {
	echo := startEchoServer(t)
	_, port := mustSplitAddr(t, echo.URL)

	config := `
[policy]
default = "deny"
`
	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/before")
	if err == nil {
		t.Fatal("expected deny before dynamic add")
	}

	// Flags must come before the positional destination arg because Go's
	// flag package stops parsing at the first non-flag argument.
	runSluicePolicyAdd(t, proc, "allow", "--ports", port, "127.0.0.1")
	sendSIGHUP(t, proc)

	status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/after")
	if status != 200 {
		t.Fatalf("expected 200 after dynamic add + SIGHUP, got %d", status)
	}
}

// TestProxy_DynamicRuleRemoveViaCLI verifies that removing a rule via the CLI
// and sending SIGHUP makes the proxy deny previously allowed traffic.
func TestProxy_DynamicRuleRemoveViaCLI(t *testing.T) {
	echo := startEchoServer(t)
	_, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
ports = [%s]
name = "temp allow"
`, port)
	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Connection should be allowed initially.
	status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/before")
	if status != 200 {
		t.Fatalf("expected 200 before remove, got %d", status)
	}

	// Find the rule ID from policy list output.
	listOutput := runSluiceCLI(t, proc, "policy", "list")
	re := regexp.MustCompile(`\[(\d+)\] allow`)
	matches := re.FindStringSubmatch(listOutput)
	if len(matches) < 2 {
		t.Fatalf("could not parse rule ID from list output: %s", listOutput)
	}
	ruleID := matches[1]

	// policy remove takes the rule ID as a positional arg. --db must come first.
	runSluicePolicyRemove(t, proc, ruleID)
	sendSIGHUP(t, proc)

	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/after")
	if err == nil {
		t.Fatal("expected deny after rule removal + SIGHUP")
	}
}

// mustSplitAddr extracts host and port from an httptest.Server URL.
// Returns (host, port) as strings.
func mustSplitAddr(t *testing.T, serverURL string) (string, string) {
	t.Helper()
	addr := strings.TrimPrefix(serverURL, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return host, port
}

// runSluicePolicyAdd runs `sluice policy add <verdict> [flags...] <destination>`
// with --db placed before the positional destination argument.
func runSluicePolicyAdd(t *testing.T, proc *SluiceProcess, args ...string) string {
	t.Helper()
	binary := buildSluice(t)
	// Insert --db after "add <verdict>" which is args[0], then the rest of args.
	// args format: verdict, [flags...], destination
	// We need: verdict, --db, dbPath, [flags...], destination
	fullArgs := []string{"policy", "add", args[0], "--db", proc.DBPath}
	fullArgs = append(fullArgs, args[1:]...)
	cmd := exec.Command(binary, fullArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sluice policy add: %v\n%s", err, out)
	}
	return string(out)
}

// runSluicePolicyRemove runs `sluice policy remove --db <path> <id>`.
func runSluicePolicyRemove(t *testing.T, proc *SluiceProcess, ruleID string) string {
	t.Helper()
	binary := buildSluice(t)
	cmd := exec.Command(binary, "policy", "remove", "--db", proc.DBPath, ruleID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sluice policy remove: %v\n%s", err, out)
	}
	return string(out)
}
