package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/policy"
)

func newTestMCPHandler(t *testing.T) *MCPHTTPHandler {
	t.Helper()
	script := writeMockServer(t)
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
	})
	return NewMCPHTTPHandler(gw)
}

func postMCP(handler http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// initSession performs an initialize handshake and returns the session ID.
func initSession(t *testing.T, handler http.Handler) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	rec := postMCP(handler, body, nil)
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize did not return session ID")
	}
	return sid
}

func TestMCPHTTPInitializeReturnsSessionID(t *testing.T) {
	handler := newTestMCPHandler(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	rec := postMCP(handler, body, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("expected Mcp-Session-Id header in initialize response")
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ProtocolVersion != "2025-03-26" {
		t.Errorf("expected protocol version 2025-03-26, got %s", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "sluice" {
		t.Errorf("expected server name sluice, got %s", result.ServerInfo.Name)
	}
}

func TestMCPHTTPToolsList(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Initialize to get session ID.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	sid := initRec.Header().Get("Mcp-Session-Id")

	// List tools with session ID.
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	rec := postMCP(handler, body, map[string]string{"Mcp-Session-Id": sid})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	var result ListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(result.Tools))
	}
	if result.Tools[0].Name != "test__greet" {
		t.Errorf("expected test__greet, got %s", result.Tools[0].Name)
	}
}

func TestMCPHTTPToolsCall(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Initialize.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	sid := initRec.Header().Get("Mcp-Session-Id")

	// Call tool.
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test__greet","arguments":{"name":"world"}}}`
	rec := postMCP(handler, body, map[string]string{"Mcp-Session-Id": sid})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Content) == 0 || result.Content[0].Text == "" {
		t.Fatal("expected non-empty tool result")
	}
}

func TestMCPHTTPToolsCallSSE(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Initialize.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	sid := initRec.Header().Get("Mcp-Session-Id")

	// Call tool with Accept: text/event-stream.
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test__greet","arguments":{"name":"sse"}}}`
	rec := postMCP(handler, body, map[string]string{
		"Mcp-Session-Id": sid,
		"Accept":         "text/event-stream",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %s", ct)
	}

	// Parse the SSE data line.
	scanner := bufio.NewScanner(rec.Body)
	var dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if dataLine == "" {
		t.Fatal("no data line in SSE response")
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(dataLine), &resp); err != nil {
		t.Fatalf("decode SSE data: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error in SSE: %s", resp.Error.Message)
	}
}

func TestMCPHTTPDeleteSession(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Initialize to create session.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	sid := initRec.Header().Get("Mcp-Session-Id")

	if handler.SessionCount() != 1 {
		t.Fatalf("expected 1 session, got %d", handler.SessionCount())
	}

	// DELETE session.
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", sid)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	if handler.SessionCount() != 0 {
		t.Fatalf("expected 0 sessions after delete, got %d", handler.SessionCount())
	}
}

func TestMCPHTTPDeleteInvalidSession(t *testing.T) {
	handler := newTestMCPHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "nonexistent")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestMCPHTTPDeleteNoSessionHeader(t *testing.T) {
	handler := newTestMCPHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestMCPHTTPInvalidSessionReturns404(t *testing.T) {
	handler := newTestMCPHandler(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	rec := postMCP(handler, body, map[string]string{"Mcp-Session-Id": "bogus"})

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid session, got %d", rec.Code)
	}
}

func TestMCPHTTPMissingSessionReturns400(t *testing.T) {
	handler := newTestMCPHandler(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	rec := postMCP(handler, body, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing session, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMCPHTTPNotificationReturns202(t *testing.T) {
	handler := newTestMCPHandler(t)

	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	rec := postMCP(handler, body, nil)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMCPHTTPMethodNotAllowed(t *testing.T) {
	handler := newTestMCPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}

	allow := rec.Header().Get("Allow")
	if !strings.Contains(allow, "POST") || !strings.Contains(allow, "DELETE") {
		t.Errorf("expected Allow header with POST and DELETE, got %q", allow)
	}
}

func TestMCPHTTPBadJSON(t *testing.T) {
	handler := newTestMCPHandler(t)

	rec := postMCP(handler, `{invalid`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with JSON-RPC error, got %d", rec.Code)
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Fatalf("expected parse error (-32700), got %+v", resp.Error)
	}
}

func TestMCPHTTPBadContentType(t *testing.T) {
	handler := newTestMCPHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("data"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", rec.Code)
	}
}

func TestMCPHTTPFullHandshakeAndToolCall(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Step 1: Initialize.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	if initRec.Code != http.StatusOK {
		t.Fatalf("initialize: expected 200, got %d", initRec.Code)
	}
	sid := initRec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no session ID from initialize")
	}

	// Step 2: Send initialized notification.
	notifyBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	notifyRec := postMCP(handler, notifyBody, map[string]string{"Mcp-Session-Id": sid})
	if notifyRec.Code != http.StatusAccepted {
		t.Fatalf("notification: expected 202, got %d", notifyRec.Code)
	}

	// Step 3: List tools.
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	listRec := postMCP(handler, listBody, map[string]string{"Mcp-Session-Id": sid})
	if listRec.Code != http.StatusOK {
		t.Fatalf("tools/list: expected 200, got %d", listRec.Code)
	}

	var listResp JSONRPCResponse
	if err := json.NewDecoder(listRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	var tools ListToolsResult
	if err := json.Unmarshal(listResp.Result, &tools); err != nil {
		t.Fatalf("decode tools: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("expected tools, got none")
	}

	// Step 4: Call a tool.
	callBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"test__greet","arguments":{"name":"world"}}}`
	callRec := postMCP(handler, callBody, map[string]string{"Mcp-Session-Id": sid})
	if callRec.Code != http.StatusOK {
		t.Fatalf("tools/call: expected 200, got %d: %s", callRec.Code, callRec.Body.String())
	}

	var callResp JSONRPCResponse
	if err := json.NewDecoder(callRec.Body).Decode(&callResp); err != nil {
		t.Fatalf("decode tools/call: %v", err)
	}
	if callResp.Error != nil {
		t.Fatalf("tools/call error: %s", callResp.Error.Message)
	}

	var result ToolResult
	if err := json.Unmarshal(callResp.Result, &result); err != nil {
		t.Fatalf("decode tool result: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %s", result.Content[0].Text)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected tool content")
	}

	// Step 5: Delete session.
	delReq := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	delReq.Header.Set("Mcp-Session-Id", sid)
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", delRec.Code)
	}
}

func TestMCPHTTPPolicyEnforcement(t *testing.T) {
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "deny"},
	}, policy.Allow)
	if err != nil {
		t.Fatal(err)
	}

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
		ToolPolicy: tp,
	})
	handler := NewMCPHTTPHandler(gw)

	// Initialize.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	sid := initRec.Header().Get("Mcp-Session-Id")

	// Call denied tool.
	callBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test__greet","arguments":{}}}`
	callRec := postMCP(handler, callBody, map[string]string{"Mcp-Session-Id": sid})

	var resp JSONRPCResponse
	if err := json.NewDecoder(callRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected denied tool call to return error result")
	}
	if !strings.Contains(result.Content[0].Text, "denied") {
		t.Errorf("expected denial message, got %q", result.Content[0].Text)
	}
}

func TestMCPHTTPPing(t *testing.T) {
	handler := newTestMCPHandler(t)
	sid := initSession(t, handler)

	body := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	rec := postMCP(handler, body, map[string]string{"Mcp-Session-Id": sid})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestMCPHTTPNoContentTypeAllowed(t *testing.T) {
	// Some clients may omit Content-Type. Accept it gracefully.
	handler := newTestMCPHandler(t)
	sid := initSession(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
	req.Header.Set("Mcp-Session-Id", sid)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMCPHTTPSessionEchoedOnSubsequentRequests(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Initialize.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}`
	initRec := postMCP(handler, initBody, nil)
	sid := initRec.Header().Get("Mcp-Session-Id")

	// Ping with session.
	pingBody := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	pingRec := postMCP(handler, pingBody, map[string]string{"Mcp-Session-Id": sid})

	echoed := pingRec.Header().Get("Mcp-Session-Id")
	if echoed != sid {
		t.Errorf("expected echoed session ID %q, got %q", sid, echoed)
	}
}

// TestMCPHTTPStreamedResponse verifies that the SSE response body follows
// the Server-Sent Events format: "data: <json>\n\n".
func TestMCPHTTPStreamedResponse(t *testing.T) {
	handler := newTestMCPHandler(t)
	sid := initSession(t, handler)

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test__greet","arguments":{"name":"stream"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", sid)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Read the full body and verify SSE format.
	raw, _ := io.ReadAll(rec.Body)
	body2 := string(raw)
	if !strings.HasPrefix(body2, "data: ") {
		t.Fatalf("expected SSE data prefix, got %q", body2)
	}
	// SSE events end with double newline.
	if !strings.HasSuffix(body2, "\n\n") {
		t.Fatalf("expected SSE event to end with double newline, got %q", body2)
	}
}

func TestPruneOldestSession(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Manually create sessions with known timestamps.
	sess1 := &mcpSession{id: "old", createdAt: time.Now().Add(-10 * time.Minute)}
	sess1.lastAccessedAt.Store(time.Now().Add(-10 * time.Minute).UnixNano())
	handler.sessions.Store("old", sess1)

	sess2 := &mcpSession{id: "new", createdAt: time.Now()}
	sess2.lastAccessedAt.Store(time.Now().UnixNano())
	handler.sessions.Store("new", sess2)

	if handler.SessionCount() != 2 {
		t.Fatalf("expected 2 sessions, got %d", handler.SessionCount())
	}

	handler.pruneOldestSession()

	if handler.SessionCount() != 1 {
		t.Fatalf("expected 1 session after prune, got %d", handler.SessionCount())
	}

	// The older session should have been pruned.
	if _, ok := handler.sessions.Load("old"); ok {
		t.Error("oldest session should have been pruned")
	}
	if _, ok := handler.sessions.Load("new"); !ok {
		t.Error("newer session should still exist")
	}
}

func TestNewSessionPrunesWhenFull(t *testing.T) {
	handler := newTestMCPHandler(t)

	// Fill up to maxSessions by manually adding sessions.
	for i := 0; i < maxSessions; i++ {
		sess := &mcpSession{id: fmt.Sprintf("sess_%d", i), createdAt: time.Now()}
		sess.lastAccessedAt.Store(time.Now().UnixNano())
		handler.sessions.Store(sess.id, sess)
	}

	if handler.SessionCount() != maxSessions {
		t.Fatalf("expected %d sessions, got %d", maxSessions, handler.SessionCount())
	}

	// Creating a new session should trigger prune.
	newSess := handler.newSession()
	if newSess == nil {
		t.Fatal("expected non-nil session")
	}
	// Count should still be maxSessions (one pruned + one added = net zero change).
	if handler.SessionCount() != maxSessions {
		t.Errorf("expected %d sessions after prune+add, got %d", maxSessions, handler.SessionCount())
	}
}

func TestPruneOldestSessionEmpty(t *testing.T) {
	handler := newTestMCPHandler(t)
	// Pruning an empty session map should not panic.
	handler.pruneOldestSession()
	if handler.SessionCount() != 0 {
		t.Errorf("expected 0 sessions, got %d", handler.SessionCount())
	}
}
