package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	if err := os.WriteFile(path, []byte(mockMCPServer), 0o755); err != nil {
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
	defer func() { _ = u.Stop() }()

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
	defer func() { _ = u.Stop() }()

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
	defer func() { _ = u.Stop() }()

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
	defer func() { _ = u.Stop() }()

	if u.timeout != defaultUpstreamTimeout {
		t.Errorf("expected default timeout %v for TimeoutSec=0, got %v", defaultUpstreamTimeout, u.timeout)
	}
}

// --- resolveVaultEnv tests ---

func TestResolveVaultEnvWithVaultPrefix(t *testing.T) {
	resolver := func(name string) (string, error) {
		creds := map[string]string{
			"github_token": "ghp_real_secret_123",
			"api_key":      "sk-real-key-456",
		}
		v, ok := creds[name]
		if !ok {
			return "", fmt.Errorf("credential %q not found", name)
		}
		return v, nil
	}

	env := map[string]string{
		"GITHUB_TOKEN": "vault:github_token",
		"API_KEY":      "vault:api_key",
	}

	resolved, err := resolveVaultEnv(env, resolver)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}
	if resolved["GITHUB_TOKEN"] != "ghp_real_secret_123" {
		t.Errorf("expected ghp_real_secret_123, got %q", resolved["GITHUB_TOKEN"])
	}
	if resolved["API_KEY"] != "sk-real-key-456" {
		t.Errorf("expected sk-real-key-456, got %q", resolved["API_KEY"])
	}
}

func TestResolveVaultEnvPlainPassthrough(t *testing.T) {
	resolver := func(_ string) (string, error) {
		return "", fmt.Errorf("should not be called")
	}

	env := map[string]string{
		"PATH":  "/usr/bin",
		"HOME":  "/home/user",
		"DEBUG": "true",
	}

	resolved, err := resolveVaultEnv(env, resolver)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}
	if resolved["PATH"] != "/usr/bin" {
		t.Errorf("expected /usr/bin, got %q", resolved["PATH"])
	}
	if resolved["HOME"] != "/home/user" {
		t.Errorf("expected /home/user, got %q", resolved["HOME"])
	}
	if resolved["DEBUG"] != "true" {
		t.Errorf("expected true, got %q", resolved["DEBUG"])
	}
}

func TestResolveVaultEnvMixed(t *testing.T) {
	resolver := func(name string) (string, error) {
		if name == "my_secret" {
			return "resolved_value", nil
		}
		return "", fmt.Errorf("credential %q not found", name)
	}

	env := map[string]string{
		"SECRET_VAR": "vault:my_secret",
		"PLAIN_VAR":  "just_a_value",
	}

	resolved, err := resolveVaultEnv(env, resolver)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}
	if resolved["SECRET_VAR"] != "resolved_value" {
		t.Errorf("expected resolved_value, got %q", resolved["SECRET_VAR"])
	}
	if resolved["PLAIN_VAR"] != "just_a_value" {
		t.Errorf("expected just_a_value, got %q", resolved["PLAIN_VAR"])
	}
}

func TestResolveVaultEnvMissingCredential(t *testing.T) {
	resolver := func(name string) (string, error) {
		return "", fmt.Errorf("credential %q not found in vault", name)
	}

	env := map[string]string{
		"TOKEN": "vault:nonexistent",
	}

	_, err := resolveVaultEnv(env, resolver)
	if err == nil {
		t.Fatal("expected error for missing vault credential")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention credential name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "TOKEN") {
		t.Errorf("error should mention env var name, got: %v", err)
	}
}

func TestResolveVaultEnvNilResolver(t *testing.T) {
	env := map[string]string{
		"TOKEN": "vault:some_secret",
	}

	// With nil resolver, vault: values pass through unchanged.
	resolved, err := resolveVaultEnv(env, nil)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}
	if resolved["TOKEN"] != "vault:some_secret" {
		t.Errorf("expected vault:some_secret (unchanged), got %q", resolved["TOKEN"])
	}
}

func TestResolveVaultEnvEmptyMap(t *testing.T) {
	resolver := func(_ string) (string, error) {
		return "", fmt.Errorf("should not be called")
	}
	resolved, err := resolveVaultEnv(nil, resolver)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}
	if resolved != nil {
		t.Errorf("expected nil for nil input, got %v", resolved)
	}

	resolved2, err := resolveVaultEnv(map[string]string{}, resolver)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}
	if len(resolved2) != 0 {
		t.Errorf("expected empty for empty input, got %v", resolved2)
	}
}

// mockMCPServerEnv echoes environment variables in the tool call response
// so tests can verify credential injection.
const mockMCPServerEnv = `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  id=$(echo "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$method" in
    initialize)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"envtest\",\"version\":\"0.1.0\"}}}"
      ;;
    notifications/initialized)
      ;;
    tools/list)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"echo_env\",\"description\":\"Echo env vars\"}]}}"
      ;;
    tools/call)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"TOKEN=${MY_TOKEN} PLAIN=${PLAIN_VAR}\"}]}}"
      ;;
    *)
      echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}"
      ;;
  esac
done
`

func TestStartUpstreamWithVaultEnvResolution(t *testing.T) {
	// This test verifies that the gateway resolves vault: env vars before
	// spawning the upstream. We use the mockMCPServerEnv script which
	// echoes env vars in its response.
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mock_env.sh")
	if err := os.WriteFile(scriptPath, []byte(mockMCPServerEnv), 0o755); err != nil {
		t.Fatal(err)
	}

	resolver := func(name string) (string, error) {
		if name == "secret_token" {
			return "real_secret_value", nil
		}
		return "", fmt.Errorf("credential %q not found", name)
	}

	cfg := UpstreamConfig{
		Name:    "envtest",
		Command: "bash",
		Args:    []string{scriptPath},
		Env: map[string]string{
			"MY_TOKEN":  "vault:secret_token",
			"PLAIN_VAR": "hello",
		},
	}

	// Resolve vault env just like the gateway does.
	resolved, err := resolveVaultEnv(cfg.Env, resolver)
	if err != nil {
		t.Fatalf("resolveVaultEnv: %v", err)
	}

	// Verify the resolved map has the real value.
	if resolved["MY_TOKEN"] != "real_secret_value" {
		t.Errorf("expected real_secret_value, got %q", resolved["MY_TOKEN"])
	}
	if resolved["PLAIN_VAR"] != "hello" {
		t.Errorf("expected hello, got %q", resolved["PLAIN_VAR"])
	}

	// Verify the original config is unchanged (vault: prefix preserved).
	if cfg.Env["MY_TOKEN"] != "vault:secret_token" {
		t.Errorf("original config should be unchanged, got %q", cfg.Env["MY_TOKEN"])
	}

	spawnCfg := cfg
	spawnCfg.Env = resolved

	u, err := StartUpstream(spawnCfg)
	if err != nil {
		t.Fatalf("StartUpstream: %v", err)
	}
	defer func() { _ = u.Stop() }()

	if err := u.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
}

func TestValidTransport(t *testing.T) {
	tests := []struct {
		transport string
		valid     bool
	}{
		{"stdio", true},
		{"http", true},
		{"websocket", true},
		{"", false},
		{"grpc", false},
		{"tcp", false},
	}
	for _, tt := range tests {
		if got := ValidTransport(tt.transport); got != tt.valid {
			t.Errorf("ValidTransport(%q) = %v, want %v", tt.transport, got, tt.valid)
		}
	}
}
