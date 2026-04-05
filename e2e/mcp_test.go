//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// buildMockUpstreamOnce compiles the mock MCP upstream binary once per test run.
var buildMockUpstreamOnce sync.Once
var mockUpstreamBinary string
var mockUpstreamBuildErr error

// buildMockUpstream compiles the mock MCP upstream binary and returns its path.
func buildMockUpstream(t *testing.T) string {
	t.Helper()
	buildMockUpstreamOnce.Do(func() {
		mockUpstreamBinary = filepath.Join(os.TempDir(), "mock-mcp-upstream-e2e")
		cmd := exec.Command("go", "build", "-o", mockUpstreamBinary, "./e2e/testdata/mock_mcp_upstream.go")
		cmd.Dir = findProjectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			mockUpstreamBuildErr = fmt.Errorf("build mock upstream: %v\n%s", err, out)
		}
	})
	if mockUpstreamBuildErr != nil {
		t.Fatal(mockUpstreamBuildErr)
	}
	return mockUpstreamBinary
}

// mcpRequest is a JSON-RPC 2.0 request for MCP.
type mcpRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// mcpResponse is a JSON-RPC 2.0 response from MCP.
type mcpResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *mcpResponseError `json:"error,omitempty"`
}

type mcpResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpToolResult holds the result of a tools/call response.
type mcpToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Meta    map[string]interface{} `json:"_meta,omitempty"`
	IsError bool                   `json:"isError,omitempty"`
}

// mcpListToolsResult holds the result of a tools/list response.
type mcpListToolsResult struct {
	Tools []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tools"`
}

// sendMCPRequest sends a JSON-RPC request to the MCP HTTP endpoint.
// On the first call (initialize), it captures the session ID and uses it
// for subsequent requests.
func sendMCPRequest(t *testing.T, healthURL string, sessionID *string, req mcpRequest) mcpResponse {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal MCP request: %v", err)
	}

	mcpURL := strings.Replace(healthURL, "/healthz", "/mcp", 1)
	httpReq, err := http.NewRequest("POST", mcpURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create MCP request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if sessionID != nil && *sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", *sessionID)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("send MCP request: %v", err)
	}
	defer resp.Body.Close()

	// Capture session ID from initialize response.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && sessionID != nil {
		*sessionID = sid
	}

	// Notifications return 202 with no body.
	if resp.StatusCode == http.StatusAccepted {
		return mcpResponse{JSONRPC: "2.0"}
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("MCP request returned %d: %s", resp.StatusCode, respBody)
	}

	var mcpResp mcpResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		t.Fatalf("decode MCP response: %v", err)
	}
	return mcpResp
}

// initMCPSession performs the initialize/notifications/initialized handshake
// and returns the session ID.
func initMCPSession(t *testing.T, healthURL string) string {
	t.Helper()
	var sessionID string

	// Initialize.
	resp := sendMCPRequest(t, healthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "e2e-test", "version": "1.0.0"},
		},
	})
	if resp.Error != nil {
		t.Fatalf("initialize failed: %s", resp.Error.Message)
	}
	if sessionID == "" {
		t.Fatal("no session ID returned from initialize")
	}

	// Send notifications/initialized.
	sendMCPRequest(t, healthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	})

	return sessionID
}

// startMCPSluice starts sluice with an MCP upstream registered. It builds the
// mock upstream binary, registers it in the DB, and starts sluice which auto-
// starts the MCP gateway on /mcp.
func startMCPSluice(t *testing.T, extraTOML string, mockArgs ...string) *SluiceProcess {
	t.Helper()
	mockBin := buildMockUpstream(t)

	// Build args string for the upstream.
	argsFlag := ""
	if len(mockArgs) > 0 {
		argsFlag = strings.Join(mockArgs, ",")
	}

	config := fmt.Sprintf(`
[policy]
default = "allow"

%s
`, extraTOML)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Register the mock upstream in the DB.
	binary := buildSluice(t)
	addArgs := []string{"mcp", "add", "--db", proc.DBPath, "--command", mockBin, "mock"}
	if argsFlag != "" {
		addArgs = []string{"mcp", "add", "--db", proc.DBPath, "--command", mockBin, "--args", argsFlag, "mock"}
	}
	cmd := exec.Command(binary, addArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mcp add: %v\n%s", err, out)
	}

	// Stop and restart sluice so it picks up the upstream from the DB.
	// The MCP gateway only starts if upstreams are registered when the
	// process starts. We need to restart after registering the upstream.
	stopSluice(t, proc)

	// Start a fresh sluice with the same DB that now has the upstream.
	proc2 := startSluiceWithDB(t, proc.DBPath, proc.AuditPath, config, nil)
	return proc2
}

// startMCPSluiceMulti starts sluice with multiple MCP upstreams.
func startMCPSluiceMulti(t *testing.T, upstreams map[string][]string, extraTOML string) *SluiceProcess {
	t.Helper()
	mockBin := buildMockUpstream(t)

	config := fmt.Sprintf(`
[policy]
default = "allow"

%s
`, extraTOML)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})
	binary := buildSluice(t)

	// Register each upstream.
	for name, args := range upstreams {
		addArgs := []string{"mcp", "add", "--db", proc.DBPath, "--command", mockBin, name}
		if len(args) > 0 {
			argsFlag := strings.Join(args, ",")
			addArgs = []string{"mcp", "add", "--db", proc.DBPath, "--command", mockBin, "--args", argsFlag, name}
		}
		cmd := exec.Command(binary, addArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("mcp add %s: %v\n%s", name, err, out)
		}
	}

	// Restart to pick up upstreams.
	stopSluice(t, proc)
	proc2 := startSluiceWithDB(t, proc.DBPath, proc.AuditPath, config, nil)
	return proc2
}

// startSluiceWithDB starts sluice using an existing DB file. This allows
// registering upstreams in the DB before starting sluice, so the MCP gateway
// discovers them on startup.
func startSluiceWithDB(t *testing.T, dbPath, auditPath, configTOML string, env []string) *SluiceProcess {
	t.Helper()
	binary := buildSluice(t)

	proxyPort := freePort(t)
	healthPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	healthAddr := fmt.Sprintf("127.0.0.1:%d", healthPort)

	args := []string{
		"--listen", proxyAddr,
		"--db", dbPath,
		"--audit", auditPath,
		"--health-addr", healthAddr,
		"--runtime", "none",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sluice: %v", err)
	}

	proc := &SluiceProcess{
		Cmd:       cmd,
		ProxyAddr: proxyAddr,
		HealthURL: fmt.Sprintf("http://%s/healthz", healthAddr),
		DBPath:    dbPath,
		AuditPath: auditPath,
		ConfigDir: filepath.Dir(dbPath),
		cancel:    cancel,
	}

	t.Cleanup(func() {
		stopSluice(t, proc)
	})

	waitForHealthy(t, proc.HealthURL, 10*time.Second)

	// Wait a bit for the MCP gateway to finish upstream initialization.
	// The health endpoint becomes available before upstream handshakes complete.
	time.Sleep(500 * time.Millisecond)

	return proc
}

// TestMCP_ToolDiscovery verifies that registering an MCP upstream via CLI,
// starting the gateway, and calling tools/list returns the upstream's tools
// with the correct namespace prefix.
func TestMCP_ToolDiscovery(t *testing.T) {
	proc := startMCPSluice(t, "")
	sessionID := initMCPSession(t, proc.HealthURL)

	// List tools.
	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	})
	if resp.Error != nil {
		t.Fatalf("tools/list error: %s", resp.Error.Message)
	}

	var result mcpListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tools/list result: %v", err)
	}

	if len(result.Tools) != 3 {
		t.Fatalf("expected 3 tools, got %d: %+v", len(result.Tools), result.Tools)
	}

	// Verify tools are namespaced with the upstream name "mock".
	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}
	for _, expected := range []string{"mock__echo", "mock__secret", "mock__slow"} {
		if !toolNames[expected] {
			t.Errorf("expected tool %q not found in %v", expected, toolNames)
		}
	}
}

// TestMCP_AllowedToolCallSucceeds verifies that a tool call matching an allow
// policy succeeds and returns the correct response from the upstream.
func TestMCP_AllowedToolCallSucceeds(t *testing.T) {
	toml := `
[[allow]]
tool = "mock__echo"
name = "allow echo"
`
	proc := startMCPSluice(t, toml)
	sessionID := initMCPSession(t, proc.HealthURL)

	// Call the echo tool.
	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__echo",
			"arguments": map[string]interface{}{"message": "hello world"},
		},
	})
	if resp.Error != nil {
		t.Fatalf("tools/call error: %s", resp.Error.Message)
	}

	var result mcpToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tool result: %v", err)
	}

	if result.IsError {
		t.Fatalf("tool call returned error: %+v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatal("empty content in tool result")
	}

	// The echo tool returns the arguments as text.
	if !strings.Contains(result.Content[0].Text, "hello world") {
		t.Errorf("expected echo to contain 'hello world', got: %s", result.Content[0].Text)
	}

	// Verify governance metadata is present.
	if result.Meta == nil {
		t.Fatal("expected governance metadata in response")
	}
	gov, ok := result.Meta["governance"]
	if !ok {
		t.Fatal("expected 'governance' key in meta")
	}
	govMap, ok := gov.(map[string]interface{})
	if !ok {
		t.Fatalf("governance meta is not a map: %T", gov)
	}
	if govMap["verdict"] != "allow" {
		t.Errorf("expected verdict 'allow', got %v", govMap["verdict"])
	}
}

// TestMCP_DeniedToolCallReturnsError verifies that a tool call matching a deny
// policy is blocked and returns an error.
func TestMCP_DeniedToolCallReturnsError(t *testing.T) {
	toml := `
[[deny]]
tool = "mock__echo"
name = "block echo"
`
	proc := startMCPSluice(t, toml)
	sessionID := initMCPSession(t, proc.HealthURL)

	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__echo",
			"arguments": map[string]interface{}{"message": "should be blocked"},
		},
	})
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %s", resp.Error.Message)
	}

	var result mcpToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tool result: %v", err)
	}

	if !result.IsError {
		t.Fatal("expected tool call to be denied (isError=true)")
	}

	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "denied") {
		t.Errorf("expected denial message, got: %+v", result.Content)
	}
}

// TestMCP_AskWithoutBrokerReturnsError verifies that a tool call matching an
// ask policy returns an error when no approval broker is configured.
func TestMCP_AskWithoutBrokerReturnsError(t *testing.T) {
	toml := `
[[ask]]
tool = "mock__echo"
name = "ask for echo"
`
	proc := startMCPSluice(t, toml)
	sessionID := initMCPSession(t, proc.HealthURL)

	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__echo",
			"arguments": map[string]interface{}{"message": "needs approval"},
		},
	})
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %s", resp.Error.Message)
	}

	var result mcpToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tool result: %v", err)
	}

	if !result.IsError {
		t.Fatal("expected ask-without-broker to return error")
	}

	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "approval") {
		t.Errorf("expected approval-related error message, got: %+v", result.Content)
	}
}

// TestMCP_ArgumentInspectionBlocks verifies that argument inspection blocks a
// tool call when the arguments contain a pattern-matched string.
func TestMCP_ArgumentInspectionBlocks(t *testing.T) {
	toml := `
[[allow]]
tool = "mock__echo"
name = "allow echo"

[[deny]]
pattern = "sk-[a-zA-Z0-9]{10,}"
name = "block api keys in args"
`
	proc := startMCPSluice(t, toml)
	sessionID := initMCPSession(t, proc.HealthURL)

	// Call echo with an API key pattern in the arguments.
	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__echo",
			"arguments": map[string]interface{}{"message": "use this key: sk-abcdefghij1234"},
		},
	})
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %s", resp.Error.Message)
	}

	var result mcpToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tool result: %v", err)
	}

	if !result.IsError {
		t.Fatal("expected argument inspection to block the tool call")
	}

	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "blocked") {
		t.Errorf("expected 'blocked' in error message, got: %+v", result.Content)
	}
}

// TestMCP_ResponseRedaction verifies that pattern-matched content in tool
// responses is redacted before reaching the client.
func TestMCP_ResponseRedaction(t *testing.T) {
	toml := `
[[allow]]
tool = "mock__*"
name = "allow all mock tools"

[[redact]]
pattern = "sk-[a-zA-Z0-9]+"
replacement = "[REDACTED_KEY]"
name = "redact api keys"
`
	proc := startMCPSluice(t, toml)
	sessionID := initMCPSession(t, proc.HealthURL)

	// Call the secret tool which returns text containing "sk-secret1234567890".
	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__secret",
			"arguments": map[string]interface{}{},
		},
	})
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %s", resp.Error.Message)
	}

	var result mcpToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tool result: %v", err)
	}

	if result.IsError {
		t.Fatalf("tool call returned error: %+v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatal("empty content in response")
	}

	responseText := result.Content[0].Text

	// The original secret pattern should be redacted.
	if strings.Contains(responseText, "sk-secret1234567890") {
		t.Errorf("secret pattern was NOT redacted from response: %s", responseText)
	}

	// The replacement string should be present.
	if !strings.Contains(responseText, "[REDACTED_KEY]") {
		t.Errorf("expected redaction replacement in response, got: %s", responseText)
	}

	// Non-secret content should remain.
	if !strings.Contains(responseText, "password is hunter2") {
		t.Errorf("non-secret content was incorrectly removed: %s", responseText)
	}
}

// TestMCP_MultipleUpstreamsNamespaced verifies that tools from multiple
// upstreams are correctly namespaced and independently callable.
func TestMCP_MultipleUpstreamsNamespaced(t *testing.T) {
	upstreams := map[string][]string{
		"alpha": {"--name", "alpha-server"},
		"beta":  {"--name", "beta-server"},
	}
	proc := startMCPSluiceMulti(t, upstreams, "")
	sessionID := initMCPSession(t, proc.HealthURL)

	// List tools and verify both namespaces are present.
	resp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	})
	if resp.Error != nil {
		t.Fatalf("tools/list error: %s", resp.Error.Message)
	}

	var result mcpListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tools/list: %v", err)
	}

	// Each upstream exposes 3 tools, so we should have 6 total.
	if len(result.Tools) != 6 {
		t.Fatalf("expected 6 tools (3 from each upstream), got %d", len(result.Tools))
	}

	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	// Check both namespaces.
	for _, prefix := range []string{"alpha", "beta"} {
		for _, tool := range []string{"echo", "secret", "slow"} {
			name := prefix + "__" + tool
			if !toolNames[name] {
				t.Errorf("expected tool %q not found", name)
			}
		}
	}

	// Call a tool from each upstream to verify independent routing.
	for _, prefix := range []string{"alpha", "beta"} {
		toolName := prefix + "__echo"
		msg := "hello from " + prefix
		callResp := sendMCPRequest(t, proc.HealthURL, &sessionID, mcpRequest{
			JSONRPC: "2.0",
			ID:      10,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name":      toolName,
				"arguments": map[string]interface{}{"message": msg},
			},
		})
		if callResp.Error != nil {
			t.Fatalf("call %s error: %s", toolName, callResp.Error.Message)
		}

		var tr mcpToolResult
		if err := json.Unmarshal(callResp.Result, &tr); err != nil {
			t.Fatalf("parse %s result: %v", toolName, err)
		}
		if tr.IsError {
			t.Fatalf("%s returned error: %+v", toolName, tr.Content)
		}
		if len(tr.Content) == 0 || !strings.Contains(tr.Content[0].Text, msg) {
			t.Errorf("%s did not echo correctly, got: %+v", toolName, tr.Content)
		}
	}
}

// TestMCP_UpstreamTimeout verifies that when an upstream takes longer than
// the configured timeout, the gateway returns an error.
func TestMCP_UpstreamTimeout(t *testing.T) {
	// Use a very short timeout (2s) and a slow upstream (5s delay).
	mockBin := buildMockUpstream(t)

	config := `
[policy]
default = "allow"
timeout_sec = 2

[[allow]]
tool = "mock__*"
name = "allow all mock tools"
`
	proc := startSluice(t, SluiceOpts{ConfigTOML: config})
	binary := buildSluice(t)

	// Register mock with --slow-ms 5000 (5 second delay for the slow tool).
	cmd := exec.Command(binary, "mcp", "add", "--db", proc.DBPath,
		"--command", mockBin, "--args", "--slow-ms,5000", "--timeout", "2", "mock")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mcp add: %v\n%s", err, out)
	}

	// Restart to pick up the upstream.
	stopSluice(t, proc)
	proc2 := startSluiceWithDB(t, proc.DBPath, proc.AuditPath, config, nil)

	sessionID := initMCPSession(t, proc2.HealthURL)

	// Call the slow tool which should timeout.
	resp := sendMCPRequest(t, proc2.HealthURL, &sessionID, mcpRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "mock__slow",
			"arguments": map[string]interface{}{},
		},
	})
	if resp.Error != nil {
		// JSON-RPC level error is acceptable only if it indicates a timeout.
		if !strings.Contains(resp.Error.Message, "timeout") && !strings.Contains(resp.Error.Message, "deadline") {
			t.Fatalf("expected timeout-related JSON-RPC error, got: %s", resp.Error.Message)
		}
		return
	}

	var result mcpToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse tool result: %v", err)
	}

	// The gateway should report an upstream error due to timeout.
	if !result.IsError {
		t.Fatal("expected timeout error from slow tool call")
	}

	if len(result.Content) == 0 {
		t.Fatal("expected error content in timeout response")
	}

	errorText := result.Content[0].Text
	if !strings.Contains(errorText, "timeout") && !strings.Contains(errorText, "Upstream error") {
		t.Errorf("expected timeout-related error, got: %s", errorText)
	}
}
