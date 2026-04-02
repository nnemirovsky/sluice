package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/nemirovsky/sluice/internal/mcp"
	"github.com/nemirovsky/sluice/internal/policy"
)

// TestMCPConfigParsing verifies that mcpConfig correctly parses MCP upstream
// sections from TOML policy files.
func TestMCPConfigParsing(t *testing.T) {
	data := []byte(`
[policy]
default = "deny"

[[mcp_upstream]]
name = "github"
command = "github-mcp-server"
args = ["--token", "ghp_test"]
timeout_sec = 60

[[mcp_upstream]]
name = "filesystem"
command = "fs-server"
args = ["--root", "/tmp"]
`)

	var cfg mcpConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(cfg.MCPUpstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(cfg.MCPUpstreams))
	}

	gh := cfg.MCPUpstreams[0]
	if gh.Name != "github" {
		t.Errorf("upstream 0 name: got %q, want %q", gh.Name, "github")
	}
	if gh.Command != "github-mcp-server" {
		t.Errorf("upstream 0 command: got %q, want %q", gh.Command, "github-mcp-server")
	}
	if len(gh.Args) != 2 || gh.Args[0] != "--token" {
		t.Errorf("upstream 0 args: got %v", gh.Args)
	}
	if gh.TimeoutSec != 60 {
		t.Errorf("upstream 0 timeout_sec: got %d, want 60", gh.TimeoutSec)
	}

	fs := cfg.MCPUpstreams[1]
	if fs.Name != "filesystem" {
		t.Errorf("upstream 1 name: got %q, want %q", fs.Name, "filesystem")
	}
	if fs.TimeoutSec != 0 {
		t.Errorf("upstream 1 timeout_sec: got %d, want 0 (unset)", fs.TimeoutSec)
	}
}

// TestMCPConfigNoUpstreams verifies parsing when no MCP upstreams are defined.
func TestMCPConfigNoUpstreams(t *testing.T) {
	data := []byte(`
[policy]
default = "allow"
`)

	var cfg mcpConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(cfg.MCPUpstreams) != 0 {
		t.Errorf("expected 0 upstreams, got %d", len(cfg.MCPUpstreams))
	}
}

// TestMCPConfigWithEnv verifies env map parsing for upstreams.
func TestMCPConfigWithEnv(t *testing.T) {
	data := []byte(`
[policy]
default = "deny"

[[mcp_upstream]]
name = "custom"
command = "custom-server"
[mcp_upstream.env]
API_KEY = "test123"
DEBUG = "true"
`)

	var cfg mcpConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(cfg.MCPUpstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(cfg.MCPUpstreams))
	}

	env := cfg.MCPUpstreams[0].Env
	if env["API_KEY"] != "test123" {
		t.Errorf("env API_KEY: got %q, want %q", env["API_KEY"], "test123")
	}
	if env["DEBUG"] != "true" {
		t.Errorf("env DEBUG: got %q, want %q", env["DEBUG"], "true")
	}
}

// TestMCPToolPolicyFromConfig verifies that tool rules parsed from TOML
// compile into a working ToolPolicy.
func TestMCPToolPolicyFromConfig(t *testing.T) {
	data := []byte(`
[policy]
default = "ask"

[[tool_allow]]
tool = "github__list_*"
note = "Read-only GitHub operations"

[[tool_deny]]
tool = "exec__*"
note = "Block all exec"

[[tool_ask]]
tool = "filesystem__write_file"
note = "File writes need approval"
`)

	eng, err := policy.LoadFromBytes(data)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	toolRules := eng.ToolRules()
	if len(toolRules) != 3 {
		t.Fatalf("expected 3 tool rules, got %d", len(toolRules))
	}

	tp, err := mcp.NewToolPolicy(toolRules, eng.Default)
	if err != nil {
		t.Fatalf("compile tool policy: %v", err)
	}

	tests := []struct {
		tool    string
		want    policy.Verdict
	}{
		{"github__list_repos", policy.Allow},
		{"github__list_issues", policy.Allow},
		{"exec__run", policy.Deny},
		{"exec__shell", policy.Deny},
		{"filesystem__write_file", policy.Ask},
		{"filesystem__read_file", policy.Ask}, // falls through to default
	}

	for _, tc := range tests {
		got := tp.Evaluate(tc.tool)
		if got != tc.want {
			t.Errorf("Evaluate(%q): got %s, want %s", tc.tool, got, tc.want)
		}
	}
}

// TestMCPUpstreamNameValidation tests upstream name validation rules.
func TestMCPUpstreamNameValidation(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"github", false},
		{"my-server", false},
		{"server_1", false},
		{"", true},               // empty
		{"has__double", true},     // contains namespace separator
		{"bad name", true},        // space
		{"-starts-dash", true},    // starts with non-alphanumeric
		{"valid123", false},
	}

	for _, tc := range tests {
		err := mcp.ValidateUpstreamName(tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateUpstreamName(%q): err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

// TestHandleMCPCommandMissingPolicy verifies handleMCPCommand returns
// an error when the policy file does not exist.
func TestHandleMCPCommandMissingPolicy(t *testing.T) {
	err := handleMCPCommand([]string{"--policy", "/nonexistent/policy.toml"})
	if err == nil {
		t.Fatal("expected error for missing policy file")
	}
}

// TestHandleMCPCommandInvalidPolicy verifies handleMCPCommand returns
// an error when the policy file has invalid TOML.
func TestHandleMCPCommandInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	badPolicy := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(badPolicy, []byte("[policy\nbroken"), 0644); err != nil {
		t.Fatal(err)
	}

	err := handleMCPCommand([]string{"--policy", badPolicy})
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

// TestHandleMCPCommandNoUpstreams verifies handleMCPCommand starts and
// exits cleanly when stdin is closed (no upstreams configured).
func TestHandleMCPCommandNoUpstreams(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
[policy]
default = "deny"
`), 0644); err != nil {
		t.Fatal(err)
	}

	if os.Getenv("TEST_MCP_SUBPROCESS") == "no_upstreams" {
		// Replace stdin with a pipe that is immediately closed on the
		// write end so RunStdio sees EOF and returns cleanly.
		r, w, pipeErr := os.Pipe()
		if pipeErr != nil {
			fmt.Fprintf(os.Stderr, "os.Pipe: %v\n", pipeErr)
			os.Exit(1)
		}
		w.Close()
		os.Stdin = r
		err := handleMCPCommand([]string{"--policy", os.Getenv("TEST_POLICY_PATH")})
		if err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleMCPCommandNoUpstreams")
	cmd.Env = append(os.Environ(),
		"TEST_MCP_SUBPROCESS=no_upstreams",
		"TEST_POLICY_PATH="+policyPath,
		"TELEGRAM_BOT_TOKEN=",
		"TELEGRAM_CHAT_ID=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected clean exit, got error: %v\noutput: %s", err, out)
	}
}

// TestHandleMCPCommandInvalidChatID verifies handleMCPCommand exits
// when the Telegram chat ID is not a valid integer.
func TestHandleMCPCommandInvalidChatID(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
[policy]
default = "deny"
`), 0644); err != nil {
		t.Fatal(err)
	}

	if os.Getenv("TEST_MCP_SUBPROCESS") == "invalid_chat_id" {
		err := handleMCPCommand([]string{
			"--policy", os.Getenv("TEST_POLICY_PATH"),
			"--telegram-token", "fake-token",
			"--telegram-chat-id", "not-a-number",
		})
		if err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleMCPCommandInvalidChatID")
	cmd.Env = append(os.Environ(),
		"TEST_MCP_SUBPROCESS=invalid_chat_id",
		"TEST_POLICY_PATH="+policyPath,
	)
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code for invalid chat ID")
}
