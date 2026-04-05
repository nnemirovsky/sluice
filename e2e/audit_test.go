//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// auditEvent represents a parsed audit log JSON line.
type auditEvent struct {
	Timestamp   string `json:"timestamp"`
	PrevHash    string `json:"prev_hash"`
	Destination string `json:"destination"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Action      string `json:"action,omitempty"`
	Credential  string `json:"credential_used,omitempty"`
}

// parseAuditLog reads the audit log file and returns parsed events.
func parseAuditLog(t *testing.T, path string) []auditEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read audit log: %v", err)
	}

	var events []auditEvent
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var evt auditEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("parse audit line: %v\nline: %s", err, line)
		}
		events = append(events, evt)
	}
	return events
}

// TestAudit_ProxyConnectionsCreateEntries verifies that both allowed and
// denied proxy connections produce audit log entries with correct verdicts.
func TestAudit_ProxyConnectionsCreateEntries(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow echo"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Make an allowed connection.
	status, _ := httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+"/audit-allowed")
	if status != 200 {
		t.Fatalf("expected 200 for allowed connection, got %d", status)
	}

	// Make a denied connection (to a different port that has no allow rule).
	echo2 := startEchoServer(t)
	_, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo2.URL+"/audit-denied")
	if err == nil {
		t.Fatal("expected denied connection to fail")
	}

	// Give the audit logger time to flush.
	time.Sleep(500 * time.Millisecond)

	events := parseAuditLog(t, proc.AuditPath)
	if len(events) == 0 {
		t.Fatal("audit log is empty after proxy connections")
	}

	var foundAllow, foundDeny bool
	for _, evt := range events {
		if evt.Verdict == "allow" && evt.Destination == host {
			foundAllow = true
		}
		if evt.Verdict == "deny" && evt.Destination == host {
			foundDeny = true
		}
	}

	if !foundAllow {
		t.Error("audit log missing 'allow' entry for echo server connection")
	}
	if !foundDeny {
		t.Error("audit log missing 'deny' entry for denied connection")
	}
}

// TestAudit_MCPToolCallsCreateEntries verifies that MCP tool calls produce
// audit log entries for both allowed and denied tool calls.
func TestAudit_MCPToolCallsCreateEntries(t *testing.T) {
	toml := `
[[allow]]
tool = "mock__echo"
name = "allow echo"

[[deny]]
tool = "mock__secret"
name = "block secret"
`
	proc := startMCPSluice(t, toml)
	sessionID := initMCPSession(t, proc.HealthURL)

	// Make an allowed tool call.
	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__echo",
			"arguments": map[string]interface{}{"message": "audit-test"},
		},
	})
	if resp.Error != nil {
		t.Fatalf("echo tool call error: %s", resp.Error.Message)
	}

	// Make a denied tool call.
	sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__secret",
			"arguments": map[string]interface{}{},
		},
	})

	// Give audit logger time to flush.
	time.Sleep(500 * time.Millisecond)

	events := parseAuditLog(t, proc.AuditPath)
	if len(events) == 0 {
		t.Fatal("audit log is empty after MCP tool calls")
	}

	var foundToolAllow, foundToolDeny bool
	for _, evt := range events {
		if evt.Tool == "mock__echo" && evt.Verdict == "allow" {
			foundToolAllow = true
		}
		if evt.Tool == "mock__secret" && evt.Verdict == "deny" {
			foundToolDeny = true
		}
	}

	if !foundToolAllow {
		t.Error("audit log missing 'allow' entry for mock__echo tool call")
	}
	if !foundToolDeny {
		t.Error("audit log missing 'deny' entry for mock__secret tool call")
	}
}

// TestAudit_HashChainValid verifies that after multiple proxy and MCP
// operations, `sluice audit verify` reports a valid chain with no broken links.
func TestAudit_HashChainValid(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow echo"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Generate several audit entries with allowed and denied connections.
	for i := 0; i < 5; i++ {
		httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+fmt.Sprintf("/chain-%d", i))
	}

	// Generate some denied entries.
	echo2 := startEchoServer(t)
	for i := 0; i < 3; i++ {
		tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, echo2.URL+fmt.Sprintf("/denied-%d", i))
	}

	time.Sleep(500 * time.Millisecond)

	// Run `sluice audit verify` and check it exits 0.
	binary := buildSluice(t)
	cmd := exec.Command(binary, "audit", "verify", proc.AuditPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit verify failed (expected exit 0): %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "Broken links: 0") {
		t.Errorf("expected 0 broken links, got:\n%s", output)
	}

	// Verify there are entries (not an empty chain).
	if strings.Contains(output, "Total lines:  0") {
		t.Error("audit log has 0 lines despite multiple connections")
	}
}

// TestAudit_TamperingDetected verifies that modifying a line in the audit log
// causes `sluice audit verify` to detect the tampering (non-zero exit).
func TestAudit_TamperingDetected(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow echo"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Generate several audit entries.
	for i := 0; i < 5; i++ {
		httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+fmt.Sprintf("/tamper-%d", i))
	}

	time.Sleep(500 * time.Millisecond)

	// Verify chain is initially valid.
	binary := buildSluice(t)
	cmd := exec.Command(binary, "audit", "verify", proc.AuditPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit verify should pass before tampering: %v\n%s", err, out)
	}

	// Stop sluice to release the file handle before tampering.
	stopSluice(t, proc)

	// Tamper with a line in the middle of the audit log.
	data, err := os.ReadFile(proc.AuditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 audit lines, got %d", len(lines))
	}

	// Modify the second line's destination field to simulate tampering.
	var evt map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &evt); err != nil {
		t.Fatalf("parse audit line for tampering: %v", err)
	}
	evt["destination"] = "tampered.example.com"
	tampered, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal tampered event: %v", err)
	}
	lines[1] = string(tampered)

	tamperedData := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(proc.AuditPath, []byte(tamperedData), 0o600); err != nil {
		t.Fatalf("write tampered audit log: %v", err)
	}

	// Run verify again. It should detect the tampering and exit non-zero.
	cmd = exec.Command(binary, "audit", "verify", proc.AuditPath)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit verify should fail after tampering, but exited 0:\n%s", out)
	}

	output := string(out)
	if strings.Contains(output, "Broken links: 0") {
		t.Errorf("expected broken links > 0 after tampering, got:\n%s", output)
	}
}

// TestAudit_ContinuityAcrossRestart verifies that the audit log hash chain
// remains valid when sluice is stopped and restarted, with more entries
// appended after the restart.
func TestAudit_ContinuityAcrossRestart(t *testing.T) {
	echo := startEchoServer(t)
	host, port := mustSplitAddr(t, echo.URL)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[allow]]
destination = "%s"
ports = [%s]
name = "allow echo"
`, host, port)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Generate some audit entries before restart.
	for i := 0; i < 3; i++ {
		httpGetViaSOCKS5(t, proc.ProxyAddr, echo.URL+fmt.Sprintf("/pre-restart-%d", i))
	}

	time.Sleep(500 * time.Millisecond)

	// Count entries before restart.
	preEvents := parseAuditLog(t, proc.AuditPath)
	if len(preEvents) == 0 {
		t.Fatal("no audit entries before restart")
	}
	preCount := len(preEvents)

	// Stop sluice.
	stopSluice(t, proc)

	// Restart sluice with the same DB and audit log.
	proc2 := startSluiceWithDB(t, proc.DBPath, proc.AuditPath, nil)

	// Generate more entries after restart.
	for i := 0; i < 3; i++ {
		httpGetViaSOCKS5(t, proc2.ProxyAddr, echo.URL+fmt.Sprintf("/post-restart-%d", i))
	}

	time.Sleep(500 * time.Millisecond)

	// Verify total entries grew.
	postEvents := parseAuditLog(t, proc2.AuditPath)
	if len(postEvents) <= preCount {
		t.Fatalf("expected more entries after restart: pre=%d, post=%d", preCount, len(postEvents))
	}

	// Verify the full chain is valid using sluice audit verify.
	binary := buildSluice(t)
	cmd := exec.Command(binary, "audit", "verify", proc2.AuditPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit verify failed after restart: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "Broken links: 0") {
		t.Errorf("expected 0 broken links across restart, got:\n%s", output)
	}

	// Verify total line count includes both pre- and post-restart entries.
	expectedTotal := fmt.Sprintf("Total lines:  %d", len(postEvents))
	if !strings.Contains(output, expectedTotal) {
		t.Errorf("expected total lines to be %d, got:\n%s", len(postEvents), output)
	}
}
