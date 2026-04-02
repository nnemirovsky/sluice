package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockMCPServer is a bash script that acts as a minimal MCP server.
// It reads JSON-RPC requests from stdin, line by line, and responds.
const mockMCPServer = `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  id=$(echo "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$method" in
    initialize)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"mock\",\"version\":\"0.1.0\"}}}"
      ;;
    notifications/initialized)
      # notification, no response
      ;;
    tools/list)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"greet\",\"description\":\"Say hello\"},{\"name\":\"add\",\"description\":\"Add numbers\"}]}}"
      ;;
    tools/call)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello from mock\"}]}}"
      ;;
    *)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}"
      ;;
  esac
done
`

func writeMockServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mock_mcp.sh")
	if err := os.WriteFile(path, []byte(mockMCPServer), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStartUpstreamAndInitialize(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:    "mock",
		Command: "bash",
		Args:    []string{script},
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer func() { _ = u.Stop() }()

	if err := u.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
}

func TestUpstreamDiscoverTools(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:    "mock",
		Command: "bash",
		Args:    []string{script},
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer func() { _ = u.Stop() }()

	if err := u.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	tools, err := u.DiscoverTools()
	if err != nil {
		t.Fatalf("DiscoverTools: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	// Check namespacing
	if tools[0].Name != "mock__greet" {
		t.Errorf("expected mock__greet, got %q", tools[0].Name)
	}
	if tools[1].Name != "mock__add" {
		t.Errorf("expected mock__add, got %q", tools[1].Name)
	}

	// Check descriptions preserved
	if tools[0].Description != "Say hello" {
		t.Errorf("expected description 'Say hello', got %q", tools[0].Description)
	}
}

func TestUpstreamCallTool(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:    "mock",
		Command: "bash",
		Args:    []string{script},
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer u.Stop()

	if err := u.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"name": "world"})
	resp, err := u.CallTool("greet", json.RawMessage(args))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("CallTool error: %s", resp.Error.Message)
	}

	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(result.Content) != 1 || result.Content[0].Text != "hello from mock" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestUpstreamStartFailure(t *testing.T) {
	cfg := UpstreamConfig{
		Name:    "bad",
		Command: "/nonexistent/binary",
	}

	_, err := StartUpstream(cfg)
	if err == nil {
		t.Fatal("expected error starting nonexistent binary")
	}
}

func TestUpstreamStop(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:    "mock",
		Command: "bash",
		Args:    []string{script},
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}

	if err := u.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestUpstreamCustomTimeout(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:       "mock",
		Command:    "bash",
		Args:       []string{script},
		TimeoutSec: 30,
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer u.Stop()

	if u.timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", u.timeout)
	}

	// Verify the upstream still works with the custom timeout.
	if err := u.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
}

func TestUpstreamDefaultTimeout(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:    "mock",
		Command: "bash",
		Args:    []string{script},
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer u.Stop()

	if u.timeout != defaultUpstreamTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultUpstreamTimeout, u.timeout)
	}
}

func TestUpstreamZeroTimeoutUsesDefault(t *testing.T) {
	script := writeMockServer(t)
	cfg := UpstreamConfig{
		Name:       "mock",
		Command:    "bash",
		Args:       []string{script},
		TimeoutSec: 0,
	}

	u, err := StartUpstream(cfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer u.Stop()

	if u.timeout != defaultUpstreamTimeout {
		t.Errorf("expected default timeout %v for TimeoutSec=0, got %v", defaultUpstreamTimeout, u.timeout)
	}
}
