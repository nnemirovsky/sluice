package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/policy"
)

func newTestGateway() *Gateway {
	tools := []Tool{
		{Name: "test__hello", Description: "Says hello"},
		{Name: "test__greet", Description: "Greets someone"},
	}
	tp, _ := NewToolPolicy(nil, policy.Allow)
	return &Gateway{
		upstreams:  make(map[string]MCPUpstream),
		toolMap:    map[string]string{"test__hello": "test", "test__greet": "test"},
		allTools:   tools,
		policy:     tp,
		timeoutSec: 5,
	}
}

func TestHandleRequestInitialize(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}`),
	}

	resp := gw.handleRequest(req)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.ProtocolVersion != "2025-03-26" {
		t.Errorf("protocol version = %q, want %q", result.ProtocolVersion, "2025-03-26")
	}
	if result.ServerInfo.Name != "sluice" {
		t.Errorf("server name = %q, want %q", result.ServerInfo.Name, "sluice")
	}
}

func TestHandleRequestNotification(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	resp := gw.handleRequest(req)
	if resp != nil {
		t.Fatalf("expected nil for notification, got %+v", resp)
	}
}

func TestHandleRequestToolsList(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/list",
	}

	resp := gw.handleRequest(req)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	var result ListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 2 {
		t.Errorf("tools count = %d, want 2", len(result.Tools))
	}
	if result.Tools[0].Name != "test__hello" {
		t.Errorf("first tool = %q, want %q", result.Tools[0].Name, "test__hello")
	}
}

func TestHandleRequestToolsCallInvalidParams(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`3`),
		Method:  "tools/call",
		Params:  json.RawMessage(`not json`),
	}

	resp := gw.handleRequest(req)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
	}
}

func TestHandleRequestUnknownMethod(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`4`),
		Method:  "nonexistent/method",
	}

	resp := gw.handleRequest(req)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("error code = %d, want -32601", resp.Error.Code)
	}
}

func TestHandleRequestUnknownNotification(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/cancelled",
	}

	resp := gw.handleRequest(req)
	if resp != nil {
		t.Fatalf("expected nil for notification without ID, got %+v", resp)
	}
}

func TestHandleRequestPing(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`6`),
		Method:  "ping",
	}

	resp := gw.handleRequest(req)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestMarshalResultError(t *testing.T) {
	// marshalResult should handle marshal errors gracefully.
	// Use a value that can't be marshaled to JSON.
	ch := make(chan int) // channels are not JSON-serializable
	resp := marshalResult(json.RawMessage(`1`), ch)
	if resp.Error == nil {
		t.Fatal("expected error for unmarshalable value")
	}
	if resp.Error.Code != -32603 {
		t.Errorf("error code = %d, want -32603", resp.Error.Code)
	}
}

// TestRunStdioBasic tests RunStdio with piped stdin/stdout.
func TestRunStdioBasic(t *testing.T) {
	gw := newTestGateway()

	// Create pipes to replace stdin/stdout.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	// Run the gateway in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- gw.RunStdio()
	}()

	// Send an initialize request.
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}` + "\n"
	stdinW.Write([]byte(initReq))

	// Send a tools/list request.
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	stdinW.Write([]byte(listReq))

	// Send a ping.
	pingReq := `{"jsonrpc":"2.0","id":3,"method":"ping"}` + "\n"
	stdinW.Write([]byte(pingReq))

	// Close stdin to signal EOF.
	stdinW.Close()

	// Wait for RunStdio to finish.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunStdio error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunStdio did not return after stdin close")
	}

	// Read responses from stdout.
	stdoutW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, stdoutR)

	// Should have 3 responses (one per request).
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 response lines, got %d: %s", len(lines), buf.String())
	}

	// Verify first response is initialize result.
	var initResp JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("parse init response: %v", err)
	}
	if initResp.Error != nil {
		t.Errorf("init response error: %s", initResp.Error.Message)
	}
}

// TestRunStdioParseError tests RunStdio with malformed JSON input.
func TestRunStdioParseError(t *testing.T) {
	gw := newTestGateway()

	stdinR, stdinW, _ := os.Pipe()
	stdoutR, stdoutW, _ := os.Pipe()

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- gw.RunStdio()
	}()

	// Send invalid JSON.
	stdinW.Write([]byte("not json at all\n"))
	stdinW.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunStdio error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunStdio did not return")
	}

	stdoutW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, stdoutR)

	// Should have a parse error response.
	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error response for malformed JSON")
	}
	if resp.Error.Code != -32700 {
		t.Errorf("error code = %d, want -32700", resp.Error.Code)
	}
}

// TestReadSSEResponse tests SSE response parsing.
func TestReadSSEResponse(t *testing.T) {
	h := &HTTPUpstream{name: "test"}

	// Build SSE stream with matching response.
	sse := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
	resp, err := h.readSSEResponse(strings.NewReader(sse), json.RawMessage(`1`))
	if err != nil {
		t.Fatalf("readSSEResponse: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %s", resp.Error.Message)
	}
}

// TestReadSSEResponseSkipsNotifications tests that notifications are skipped.
func TestReadSSEResponseSkipsNotifications(t *testing.T) {
	h := &HTTPUpstream{name: "test"}

	// Notification (no id) followed by the real response.
	sse := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"done\":true}}\n\n"

	resp, err := h.readSSEResponse(strings.NewReader(sse), json.RawMessage(`5`))
	if err != nil {
		t.Fatalf("readSSEResponse: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestReadSSEResponseSkipsMismatchedID tests that mismatched IDs are skipped.
func TestReadSSEResponseSkipsMismatchedID(t *testing.T) {
	h := &HTTPUpstream{name: "test"}

	sse := "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"match\":true}}\n\n"

	resp, err := h.readSSEResponse(strings.NewReader(sse), json.RawMessage(`42`))
	if err != nil {
		t.Fatalf("readSSEResponse: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestReadSSEResponseNoMatch tests error when stream ends without a match.
func TestReadSSEResponseNoMatch(t *testing.T) {
	h := &HTTPUpstream{name: "test"}

	sse := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	_, err := h.readSSEResponse(strings.NewReader(sse), json.RawMessage(`999`))
	if err == nil {
		t.Fatal("expected error for no matching response")
	}
}

// TestReadSSEResponseTrailingData tests data without trailing blank line.
func TestReadSSEResponseTrailingData(t *testing.T) {
	h := &HTTPUpstream{name: "test"}

	// Data without trailing blank line (no final empty line).
	sse := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"trailing\":true}}"
	resp, err := h.readSSEResponse(strings.NewReader(sse), json.RawMessage(`1`))
	if err != nil {
		t.Fatalf("readSSEResponse: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response from trailing data")
	}
}

// TestProcessSSEDataServerRequest tests that server-initiated requests are skipped.
func TestProcessSSEDataServerRequest(t *testing.T) {
	h := &HTTPUpstream{name: "test"}

	data := `{"jsonrpc":"2.0","id":1,"method":"server/ping"}`
	resp, done, err := h.processSSEData(data, "1")
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Error("server request should be skipped, not matched")
	}
	if resp != nil {
		t.Error("expected nil response for server request")
	}
}

func TestHandleRequestToolsCallUnknownTool(t *testing.T) {
	gw := newTestGateway()
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`5`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"unknown__tool"}`),
	}

	resp := gw.handleRequest(req)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	// Should get a result with IsError, not a JSON-RPC error
	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for unknown tool")
	}
}
