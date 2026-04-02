package mcp

import (
	"encoding/json"
	"testing"

	"github.com/nemirovsky/sluice/internal/policy"
)

func newTestGateway() *Gateway {
	tools := []Tool{
		{Name: "test__hello", Description: "Says hello"},
		{Name: "test__greet", Description: "Greets someone"},
	}
	tp := NewToolPolicy(nil, policy.Allow)
	return &Gateway{
		upstreams:  make(map[string]*Upstream),
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
