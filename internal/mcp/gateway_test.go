package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
)

// autoResolveChannel is a mock channel that automatically resolves approval
// requests with a preconfigured response. Used by gateway tests.
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

// mockMCPServerFS is a mock MCP server that provides filesystem-like tools
// and returns a distinguishable response for routing verification.
const mockMCPServerFS = `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  id=$(echo "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$method" in
    initialize)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"fs\",\"version\":\"0.1.0\"}}}"
      ;;
    notifications/initialized)
      ;;
    tools/list)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"read\",\"description\":\"Read a file\"},{\"name\":\"write\",\"description\":\"Write a file\"}]}}"
      ;;
    tools/call)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"response from fs\"}]}}"
      ;;
    *)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}"
      ;;
  esac
done
`

// mockMCPServerSensitive returns responses containing an API key pattern
// so redaction rules can be tested.
const mockMCPServerSensitive = `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  id=$(echo "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$method" in
    initialize)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"sensitive\",\"version\":\"0.1.0\"}}}"
      ;;
    notifications/initialized)
      ;;
    tools/list)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"lookup\",\"description\":\"Lookup data\"}]}}"
      ;;
    tools/call)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Found key sk-abcdefghijklmnopqrstuvwxyz1234 in config\"}]}}"
      ;;
    *)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}"
      ;;
  esac
done
`

func writeMockServerScript(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mock_mcp.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newGatewayForTest(t *testing.T, cfg GatewayConfig) *Gateway {
	t.Helper()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	t.Cleanup(gw.Stop)
	return gw
}

// --- NewGateway initialization tests ---

func TestNewGateway(t *testing.T) {
	script := writeMockServer(t)
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
	})

	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "test__greet" {
		t.Errorf("expected test__greet, got %q", tools[0].Name)
	}
	if tools[1].Name != "test__add" {
		t.Errorf("expected test__add, got %q", tools[1].Name)
	}
}

func TestNewGatewayNoUpstreams(t *testing.T) {
	gw := newGatewayForTest(t, GatewayConfig{})
	tools := gw.Tools()
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestNewGatewayDefaultPolicy(t *testing.T) {
	// When no policy is provided, the gateway creates a default allow-all policy.
	script := writeMockServer(t)
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
	})

	// With default policy, all tool calls should be allowed.
	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{"name":"world"}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if result.IsError {
		t.Errorf("expected success, got error: %s", result.Content[0].Text)
	}
}

func TestNewGatewayDefaultTimeout(t *testing.T) {
	gw := newGatewayForTest(t, GatewayConfig{})
	if gw.timeoutSec != 120 {
		t.Errorf("expected default timeout 120s, got %d", gw.timeoutSec)
	}
}

func TestNewGatewayCustomTimeout(t *testing.T) {
	gw := newGatewayForTest(t, GatewayConfig{TimeoutSec: 30})
	if gw.timeoutSec != 30 {
		t.Errorf("expected custom timeout 30s, got %d", gw.timeoutSec)
	}
}

func TestNewGatewayDuplicateUpstreamName(t *testing.T) {
	script := writeMockServer(t)
	_, err := NewGateway(GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "dup", Command: "bash", Args: []string{script}},
			{Name: "dup", Command: "bash", Args: []string{script}},
		},
	})
	if err == nil {
		t.Fatal("expected error for duplicate upstream name")
	}
}

func TestNewGatewayInvalidUpstreamName(t *testing.T) {
	script := writeMockServer(t)
	cases := []struct {
		name    string
		wantErr string
	}{
		{"", "must not be empty"},
		{"has__double", "must not contain"},
		{"!invalid", "must match"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("name=%q", tc.name), func(t *testing.T) {
			_, err := NewGateway(GatewayConfig{
				Upstreams: []UpstreamConfig{{
					Name:    tc.name,
					Command: "bash",
					Args:    []string{script},
				}},
			})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewGatewayStartFailure(t *testing.T) {
	_, err := NewGateway(GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "bad",
			Command: "/nonexistent/binary",
		}},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

// --- StartUpstream with mock process (handshake + tool discovery) ---

func TestNewGatewayHandshakeAndDiscovery(t *testing.T) {
	// NewGateway internally calls StartUpstream, Initialize (handshake),
	// and DiscoverTools. Verify that the full flow works and tools are
	// namespaced correctly.
	script := writeMockServer(t)
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "svc",
			Command: "bash",
			Args:    []string{script},
		}},
	})

	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools after handshake+discovery, got %d", len(tools))
	}
	// Verify namespace prefix
	for _, tool := range tools {
		if tool.Name != "svc__greet" && tool.Name != "svc__add" {
			t.Errorf("unexpected tool name %q (expected svc__ prefix)", tool.Name)
		}
	}
	// Verify descriptions survived the handshake
	if tools[0].Description != "Say hello" {
		t.Errorf("expected description 'Say hello', got %q", tools[0].Description)
	}
}

// --- tools/list aggregation across multiple upstreams ---

func TestGatewayMultipleUpstreamsToolAggregation(t *testing.T) {
	script1 := writeMockServer(t)
	script2 := writeMockServerScript(t, mockMCPServerFS)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "github", Command: "bash", Args: []string{script1}},
			{Name: "fs", Command: "bash", Args: []string{script2}},
		},
	})

	tools := gw.Tools()
	if len(tools) != 4 {
		t.Fatalf("expected 4 tools (2 from each upstream), got %d", len(tools))
	}

	// Collect tool names into a set for order-independent checking.
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	expected := []string{"github__greet", "github__add", "fs__read", "fs__write"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing expected tool %q in aggregated list", name)
		}
	}
}

// --- tools/call routing to correct upstream ---

func TestGatewayToolCallRouting(t *testing.T) {
	script1 := writeMockServer(t)                        // returns "hello from mock"
	script2 := writeMockServerScript(t, mockMCPServerFS) // returns "response from fs"

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "github", Command: "bash", Args: []string{script1}},
			{Name: "fs", Command: "bash", Args: []string{script2}},
		},
	})

	// Call a tool from the first upstream.
	result1, err := gw.HandleToolCall(CallToolParams{
		Name:      "github__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall github__greet: %v", err)
	}
	if result1.IsError {
		t.Fatalf("expected success, got error: %s", result1.Content[0].Text)
	}
	if result1.Content[0].Text != "hello from mock" {
		t.Errorf("expected 'hello from mock', got %q", result1.Content[0].Text)
	}

	// Call a tool from the second upstream.
	result2, err := gw.HandleToolCall(CallToolParams{
		Name:      "fs__read",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall fs__read: %v", err)
	}
	if result2.IsError {
		t.Fatalf("expected success, got error: %s", result2.Content[0].Text)
	}
	if result2.Content[0].Text != "response from fs" {
		t.Errorf("expected 'response from fs', got %q", result2.Content[0].Text)
	}
}

func TestGatewayToolCallUnknownTool(t *testing.T) {
	script := writeMockServer(t)
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "nonexistent__tool",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for unknown tool")
	}
	if result.Content[0].Text != "Unknown tool: nonexistent__tool" {
		t.Errorf("unexpected error message: %q", result.Content[0].Text)
	}
}

// --- Tool policy enforcement ---

func TestGatewayToolCallPolicyDeny(t *testing.T) {
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

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for denied tool")
	}
	if result.Content[0].Text != "Tool call denied by policy" {
		t.Errorf("unexpected error message: %q", result.Content[0].Text)
	}
}

func TestGatewayToolCallPolicyAllow(t *testing.T) {
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "allow"},
	}, policy.Deny)
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

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if result.IsError {
		t.Errorf("expected success, got error: %s", result.Content[0].Text)
	}

	// Verify the non-allowed tool is denied by fallback.
	result2, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__add",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result2.IsError {
		t.Error("expected error result for tool not in allow list")
	}
}

func TestGatewayToolCallPolicyAskApproved(t *testing.T) {
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "ask"},
	}, policy.Allow)
	if err != nil {
		t.Fatal(err)
	}
	broker := newAutoResolveBroker(channel.ResponseAllowOnce)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
		ToolPolicy: tp,
		Broker:     broker,
		TimeoutSec: 5,
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if result.IsError {
		t.Errorf("expected success after approval, got error: %s", result.Content[0].Text)
	}
	if result.Content[0].Text != "hello from mock" {
		t.Errorf("expected 'hello from mock', got %q", result.Content[0].Text)
	}
}

func TestGatewayToolCallPolicyAskDenied(t *testing.T) {
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "ask"},
	}, policy.Allow)
	if err != nil {
		t.Fatal(err)
	}
	broker := newAutoResolveBroker(channel.ResponseDeny)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
		ToolPolicy: tp,
		Broker:     broker,
		TimeoutSec: 5,
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for denied approval")
	}
	if result.Content[0].Text != "Denied by user" {
		t.Errorf("unexpected error message: %q", result.Content[0].Text)
	}
}

func TestGatewayToolCallPolicyAskNoBroker(t *testing.T) {
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "ask"},
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
		// No Broker configured.
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when no broker configured for ask verdict")
	}
	if result.Content[0].Text != "Tool call requires approval (no broker configured)" {
		t.Errorf("unexpected error message: %q", result.Content[0].Text)
	}
}

func TestGatewayToolCallPolicyAskAlwaysAllow(t *testing.T) {
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "ask"},
	}, policy.Ask)
	if err != nil {
		t.Fatal(err)
	}
	broker := newAutoResolveBroker(channel.ResponseAlwaysAllow)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
		ToolPolicy: tp,
		Broker:     broker,
		TimeoutSec: 5,
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Content[0].Text)
	}

	// Second call should be auto-allowed without broker involvement
	// because AddDynamicAllow was called.
	result2, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall (second): %v", err)
	}
	if result2.IsError {
		t.Errorf("expected auto-allow on second call, got error: %s", result2.Content[0].Text)
	}
}

// --- Content inspection ---

func TestGatewayInspectBlocksArguments(t *testing.T) {
	script := writeMockServer(t)
	inspector, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`, Name: "api_key_leak"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
		Inspector: inspector,
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{"key":"sk-abcdefghijklmnopqrstuvwxyz1234"}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when arguments contain blocked pattern")
	}
	if result.Content[0].Text != `Tool call blocked: blocked by rule "api_key_leak"` {
		t.Errorf("unexpected error message: %q", result.Content[0].Text)
	}
}

func TestGatewayInspectRedactsResponse(t *testing.T) {
	// Use a mock server that returns a response containing an API key.
	script := writeMockServerScript(t, mockMCPServerSensitive)
	inspector, err := NewContentInspector(
		nil,
		[]policy.InspectRedactRule{
			{Pattern: `sk-[a-zA-Z0-9]{20,}`, Replacement: "[REDACTED]", Name: "api_key"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "sensitive",
			Command: "bash",
			Args:    []string{script},
		}},
		Inspector: inspector,
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "sensitive__lookup",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Content[0].Text)
	}
	want := "Found key [REDACTED] in config"
	if result.Content[0].Text != want {
		t.Errorf("expected redacted response %q, got %q", want, result.Content[0].Text)
	}
}

func TestGatewayInspectBlockBeforeApproval(t *testing.T) {
	// When arguments are blocked, the call should be denied even before
	// reaching the approval flow.
	script := writeMockServer(t)
	tp, err := NewToolPolicy([]policy.ToolRule{
		{Tool: "test__greet", Verdict: "ask"},
	}, policy.Allow)
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := NewContentInspector(
		[]policy.InspectBlockRule{
			{Pattern: `(?i)(password)\s*=\s*\S+`, Name: "password_leak"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	broker := channel.NewBroker(nil)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
		ToolPolicy: tp,
		Inspector:  inspector,
		Broker:     broker,
		TimeoutSec: 5,
	})

	// No channel to handle broker requests. If the broker is hit,
	// the test will hang until timeout. The inspector should block first.
	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{"cmd":"password= secret123"}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when arguments blocked by inspector")
	}
}

// --- Governance metadata ---

func TestGatewayGovernanceMetadata(t *testing.T) {
	script := writeMockServer(t)
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "test",
			Command: "bash",
			Args:    []string{script},
		}},
	})

	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if result.Meta == nil {
		t.Fatal("expected governance metadata in result")
	}
	gov, ok := result.Meta["governance"].(map[string]interface{})
	if !ok {
		t.Fatal("governance metadata missing or wrong type")
	}
	if gov["verdict"] != "allow" {
		t.Errorf("expected verdict 'allow', got %q", gov["verdict"])
	}
	if gov["tool"] != "test__greet" {
		t.Errorf("expected tool 'test__greet', got %q", gov["tool"])
	}
	if gov["version"] != "0.1.0" {
		t.Errorf("expected version '0.1.0', got %q", gov["version"])
	}
}

// --- Audit logging ---

func TestGatewayAuditLogging(t *testing.T) {
	// Verify that audit events are logged during tool calls.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	auditLogger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	defer func() { _ = auditLogger.Close() }()

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
		Audit:      auditLogger,
	})

	// Make a denied call to generate an audit event.
	denyResult, denyErr := gw.HandleToolCall(CallToolParams{
		Name:      "test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if denyErr != nil {
		t.Fatalf("denied tool call returned error: %v", denyErr)
	}
	if !denyResult.IsError {
		t.Error("expected denied tool call to set IsError")
	}

	// Make an allowed call too.
	allowResult, allowErr := gw.HandleToolCall(CallToolParams{
		Name:      "test__add",
		Arguments: json.RawMessage(`{}`),
	})
	if allowErr != nil {
		t.Fatalf("allowed tool call returned error: %v", allowErr)
	}
	if allowResult.IsError {
		t.Error("expected allowed tool call to succeed")
	}

	// Read the audit log and verify events were written with correct verdicts.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected audit log entries, got empty file")
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 audit log entries, got %d", len(lines))
	}

	// Verify the audit entries contain tool names and verdicts.
	var foundDeny, foundAllow bool
	for _, line := range lines {
		if strings.Contains(line, "test__greet") && strings.Contains(line, "deny") {
			foundDeny = true
		}
		if strings.Contains(line, "test__add") && strings.Contains(line, "allow") {
			foundAllow = true
		}
	}
	if !foundDeny {
		t.Error("audit log missing deny entry for test__greet")
	}
	if !foundAllow {
		t.Error("audit log missing allow entry for test__add")
	}
}

// --- Mixed upstream transports ---

func TestGatewayMixedTransports(t *testing.T) {
	// Stdio upstream via bash mock script.
	script := writeMockServer(t)

	// HTTP upstream via httptest.
	httpSrv := mockHTTPMCPServer(t)
	defer httpSrv.Close()

	// WebSocket upstream via httptest.
	wsSrv := mockWSMCPServer(t)
	defer wsSrv.Close()

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "local", Command: "bash", Args: []string{script}, Transport: TransportStdio},
			{Name: "remote", Command: httpSrv.URL, Transport: TransportHTTP},
			{Name: "realtime", Command: wsSrv.URL, Transport: TransportWS},
		},
	})

	// Verify all tools are discovered from all three transports.
	tools := gw.Tools()
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}

	// Stdio mock: greet, add. HTTP mock: search, fetch. WS mock: subscribe, query.
	expected := []string{
		"local__greet", "local__add",
		"remote__search", "remote__fetch",
		"realtime__subscribe", "realtime__query",
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing expected tool %q", name)
		}
	}
	if len(tools) != len(expected) {
		t.Errorf("expected %d tools, got %d", len(expected), len(tools))
	}

	// Call a tool from each transport and verify routing.
	result1, err := gw.HandleToolCall(CallToolParams{
		Name:      "local__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall local__greet: %v", err)
	}
	if result1.IsError || result1.Content[0].Text != "hello from mock" {
		t.Errorf("stdio upstream: expected 'hello from mock', got %q (isError=%v)", result1.Content[0].Text, result1.IsError)
	}

	result2, err := gw.HandleToolCall(CallToolParams{
		Name:      "remote__search",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall remote__search: %v", err)
	}
	if result2.IsError || result2.Content[0].Text != "result from HTTP upstream" {
		t.Errorf("HTTP upstream: expected 'result from HTTP upstream', got %q (isError=%v)", result2.Content[0].Text, result2.IsError)
	}

	result3, err := gw.HandleToolCall(CallToolParams{
		Name:      "realtime__subscribe",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall realtime__subscribe: %v", err)
	}
	if result3.IsError || result3.Content[0].Text != "result from WS upstream" {
		t.Errorf("WS upstream: expected 'result from WS upstream', got %q (isError=%v)", result3.Content[0].Text, result3.IsError)
	}
}

func TestGatewayHTTPTransport(t *testing.T) {
	httpSrv := mockHTTPMCPServer(t)
	defer httpSrv.Close()

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "httpsvc", Command: httpSrv.URL, Transport: TransportHTTP},
		},
	})

	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "httpsvc__search" {
		t.Errorf("expected httpsvc__search, got %q", tools[0].Name)
	}
}

func TestGatewayWSTransport(t *testing.T) {
	wsSrv := mockWSMCPServer(t)
	defer wsSrv.Close()

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "wssvc", Command: wsSrv.URL, Transport: TransportWS},
		},
	})

	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "wssvc__subscribe" {
		t.Errorf("expected wssvc__subscribe, got %q", tools[0].Name)
	}
}

func TestGatewayDefaultTransportIsStdio(t *testing.T) {
	script := writeMockServer(t)

	// No Transport field set. Should default to stdio.
	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "default", Command: "bash", Args: []string{script}},
		},
	})

	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
}

func TestGatewayUnknownTransport(t *testing.T) {
	_, err := NewGateway(GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "bad", Command: "http://example.com", Transport: "grpc"},
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown transport")
	}
}

// --- Stop cleanup ---

func TestGatewayStop(t *testing.T) {
	script := writeMockServer(t)
	gw, err := NewGateway(GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "a", Command: "bash", Args: []string{script}},
			{Name: "b", Command: "bash", Args: []string{script}},
		},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	// Stop should not panic and should clean up all upstreams.
	done := make(chan struct{})
	go func() {
		gw.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not complete within 10 seconds")
	}
}

// --- Credential resolver integration ---

func TestGatewayCredentialResolverInjectsEnv(t *testing.T) {
	script := writeMockServer(t)

	resolver := func(name string) (string, error) {
		if name == "test_secret" {
			return "real_value_123", nil
		}
		return "", fmt.Errorf("credential %q not found", name)
	}

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "creds",
			Command: "bash",
			Args:    []string{script},
			Env: map[string]string{
				"SECRET_KEY": "vault:test_secret",
				"PLAIN_KEY":  "plain_value",
			},
		}},
		CredentialResolver: resolver,
	})

	// Gateway should start successfully with resolved credentials.
	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	// Verify original config is preserved with vault: prefix for restart.
	cfg := gw.upstreamCfgs["creds"]
	if cfg.Env["SECRET_KEY"] != "vault:test_secret" {
		t.Errorf("original config should keep vault: prefix, got %q", cfg.Env["SECRET_KEY"])
	}
}

func TestGatewayCredentialResolverFailure(t *testing.T) {
	script := writeMockServer(t)

	resolver := func(_ string) (string, error) {
		return "", fmt.Errorf("vault is sealed")
	}

	_, err := NewGateway(GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "bad",
			Command: "bash",
			Args:    []string{script},
			Env: map[string]string{
				"TOKEN": "vault:missing_cred",
			},
		}},
		CredentialResolver: resolver,
	})
	if err == nil {
		t.Fatal("expected error when credential resolution fails")
	}
	if !strings.Contains(err.Error(), "missing_cred") {
		t.Errorf("error should mention credential name, got: %v", err)
	}
}

func TestGatewayRestartUpstream(t *testing.T) {
	script := writeMockServer(t)

	callCount := 0
	resolver := func(name string) (string, error) {
		callCount++
		if name == "rotating_secret" {
			return fmt.Sprintf("value_%d", callCount), nil
		}
		return "", fmt.Errorf("credential %q not found", name)
	}

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:    "restart-test",
			Command: "bash",
			Args:    []string{script},
			Env: map[string]string{
				"SECRET": "vault:rotating_secret",
			},
		}},
		CredentialResolver: resolver,
	})

	// Initial startup resolves the credential.
	if callCount != 1 {
		t.Fatalf("expected 1 resolver call after startup, got %d", callCount)
	}

	// Verify tools work before restart.
	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "restart-test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall before restart: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success before restart, got error: %s", result.Content[0].Text)
	}

	// Restart the upstream (simulating credential rotation).
	if err := gw.RestartUpstream("restart-test"); err != nil {
		t.Fatalf("RestartUpstream: %v", err)
	}

	// Resolver should have been called again.
	if callCount != 2 {
		t.Fatalf("expected 2 resolver calls after restart, got %d", callCount)
	}

	// Verify tools still work after restart.
	result2, err := gw.HandleToolCall(CallToolParams{
		Name:      "restart-test__greet",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall after restart: %v", err)
	}
	if result2.IsError {
		t.Fatalf("expected success after restart, got error: %s", result2.Content[0].Text)
	}
}

func TestGatewayRestartUpstreamNotFound(t *testing.T) {
	gw := newGatewayForTest(t, GatewayConfig{})
	err := gw.RestartUpstream("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent upstream")
	}
}

// --- Upstream crash mid-call ---

// mockMCPServerCrash handles initialize and tools/list, then exits (crashes)
// before responding to tools/call.
const mockMCPServerCrash = `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  id=$(echo "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$method" in
    initialize)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"crasher\",\"version\":\"0.1.0\"}}}"
      ;;
    notifications/initialized)
      ;;
    tools/list)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"boom\",\"description\":\"Will crash\"}]}}"
      ;;
    tools/call)
      # Exit without responding to simulate a crash.
      exit 1
      ;;
  esac
done
`

func TestGatewayUpstreamCrashMidCall(t *testing.T) {
	script := writeMockServerScript(t, mockMCPServerCrash)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{{
			Name:       "crasher",
			Command:    "bash",
			Args:       []string{script},
			TimeoutSec: 5,
		}},
	})

	tools := gw.Tools()
	if len(tools) != 1 || tools[0].Name != "crasher__boom" {
		t.Fatalf("expected tool 'crasher__boom', got %v", tools)
	}

	// The tool call should return an error because the upstream crashes.
	result, err := gw.HandleToolCall(CallToolParams{
		Name:      "crasher__boom",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall should not return Go error, got: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError when upstream crashes mid-call")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "Upstream error") {
		t.Errorf("error message should mention upstream error, got: %v", result.Content)
	}
}

// --- Tool namespace collision ---

// mockMCPServerCollision returns a tool named "list" (same as the other upstream).
const mockMCPServerCollision = `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  id=$(echo "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$method" in
    initialize)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"collision\",\"version\":\"0.1.0\"}}}"
      ;;
    notifications/initialized)
      ;;
    tools/list)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"list\",\"description\":\"List items\"}]}}"
      ;;
    tools/call)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"collision response\"}]}}"
      ;;
  esac
done
`

func TestGatewayToolNamespacePreventsCollision(t *testing.T) {
	// Two upstreams both exposing a tool named "list". Namespacing should
	// produce "svc_a__list" and "svc_b__list" with no collision.
	script1 := writeMockServerScript(t, mockMCPServerCollision)
	script2 := writeMockServerScript(t, mockMCPServerCollision)

	gw := newGatewayForTest(t, GatewayConfig{
		Upstreams: []UpstreamConfig{
			{Name: "svc_a", Command: "bash", Args: []string{script1}},
			{Name: "svc_b", Command: "bash", Args: []string{script2}},
		},
	})

	tools := gw.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	if !names["svc_a__list"] {
		t.Error("missing svc_a__list")
	}
	if !names["svc_b__list"] {
		t.Error("missing svc_b__list")
	}

	// Verify routing: each call goes to the correct upstream.
	result1, err := gw.HandleToolCall(CallToolParams{
		Name:      "svc_a__list",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall svc_a__list: %v", err)
	}
	if result1.IsError {
		t.Errorf("expected success, got error: %s", result1.Content[0].Text)
	}

	result2, err := gw.HandleToolCall(CallToolParams{
		Name:      "svc_b__list",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("HandleToolCall svc_b__list: %v", err)
	}
	if result2.IsError {
		t.Errorf("expected success, got error: %s", result2.Content[0].Text)
	}
}
