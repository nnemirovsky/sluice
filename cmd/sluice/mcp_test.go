package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nemirovsky/sluice/internal/mcp"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
)

// TestMCPUpstreamFromStore verifies that MCP upstreams stored in SQLite can be
// read back and converted to UpstreamConfig for the gateway.
func TestMCPUpstreamFromStore(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Add two upstreams.
	_, err = db.AddMCPUpstream("github", "github-mcp-server", store.MCPUpstreamOpts{
		Args:       []string{"--token", "ghp_test"},
		TimeoutSec: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddMCPUpstream("filesystem", "fs-server", store.MCPUpstreamOpts{
		Args: []string{"--root", "/tmp"},
	})
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(rows))
	}

	// Convert to UpstreamConfig.
	configs := make([]mcp.UpstreamConfig, len(rows))
	for i, r := range rows {
		configs[i] = mcp.UpstreamConfig{
			Name:       r.Name,
			Command:    r.Command,
			Args:       r.Args,
			Env:        r.Env,
			TimeoutSec: r.TimeoutSec,
		}
	}

	gh := configs[0]
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

	fs := configs[1]
	if fs.Name != "filesystem" {
		t.Errorf("upstream 1 name: got %q, want %q", fs.Name, "filesystem")
	}
	// Default timeout is 120 from store.
	if fs.TimeoutSec != 120 {
		t.Errorf("upstream 1 timeout_sec: got %d, want 120 (default)", fs.TimeoutSec)
	}
}

// TestMCPUpstreamFromStoreEmpty verifies that an empty store returns no upstreams.
func TestMCPUpstreamFromStoreEmpty(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 upstreams, got %d", len(rows))
	}
}

// TestMCPUpstreamWithEnv verifies env map storage and retrieval for upstreams.
func TestMCPUpstreamWithEnv(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.AddMCPUpstream("custom", "custom-server", store.MCPUpstreamOpts{
		Env: map[string]string{
			"API_KEY": "test123",
			"DEBUG":   "true",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(rows))
	}

	env := rows[0].Env
	if env["API_KEY"] != "test123" {
		t.Errorf("env API_KEY: got %q, want %q", env["API_KEY"], "test123")
	}
	if env["DEBUG"] != "true" {
		t.Errorf("env DEBUG: got %q, want %q", env["DEBUG"], "true")
	}
}

// TestMCPToolPolicyFromStore verifies that tool rules from the store compile
// into a working ToolPolicy.
func TestMCPToolPolicyFromStore(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dvTP := "ask"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvTP})
	_, _ = db.AddRule("allow", store.RuleOpts{Tool: "github__list_*", Name: "Read-only GitHub operations"})
	_, _ = db.AddRule("deny", store.RuleOpts{Tool: "exec__*", Name: "Block all exec"})
	_, _ = db.AddRule("ask", store.RuleOpts{Tool: "filesystem__write_file", Name: "File writes need approval"})

	eng, err := policy.LoadFromStore(db)
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
		tool string
		want policy.Verdict
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
		{"", true},            // empty
		{"has__double", true}, // contains namespace separator
		{"bad name", true},    // space
		{"-starts-dash", true},
		{"valid123", false},
	}

	for _, tc := range tests {
		err := mcp.ValidateUpstreamName(tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateUpstreamName(%q): err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

// TestHandleMCPAddAndList verifies the add and list subcommands work correctly.
func TestHandleMCPAddAndList(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Add an upstream.
	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "npx",
		"--args", "-y,@mcp/server-github",
		"--timeout", "60",
		"github",
	})
	if err != nil {
		t.Fatalf("mcp add: %v", err)
	}

	// Verify it's in the store.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	if upstreams[0].Name != "github" {
		t.Errorf("expected name github, got %q", upstreams[0].Name)
	}
	if upstreams[0].Command != "npx" {
		t.Errorf("expected command npx, got %q", upstreams[0].Command)
	}
	if len(upstreams[0].Args) != 2 || upstreams[0].Args[0] != "-y" || upstreams[0].Args[1] != "@mcp/server-github" {
		t.Errorf("expected args [-y @mcp/server-github], got %v", upstreams[0].Args)
	}
	if upstreams[0].TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", upstreams[0].TimeoutSec)
	}
}

// TestHandleMCPAddNameBeforeFlags verifies that the upstream name can appear
// before the flags, matching what the usage string documents. The stdlib
// flag parser normally stops at the first non-flag arg; handleMCPAdd
// reorders args via reorderFlagsBeforePositional to handle both orders.
func TestHandleMCPAddNameBeforeFlags(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"github", // name first
		"--db", dbPath,
		"--transport", "http",
		"--command", "https://api.githubcopilot.com/mcp/",
		"--header", "Authorization=Bearer token123",
	})
	if err != nil {
		t.Fatalf("mcp add: %v", err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	u := upstreams[0]
	if u.Name != "github" {
		t.Errorf("expected name github, got %q", u.Name)
	}
	if u.Transport != "http" {
		t.Errorf("expected transport http, got %q", u.Transport)
	}
	if u.Command != "https://api.githubcopilot.com/mcp/" {
		t.Errorf("expected command URL, got %q", u.Command)
	}
	if u.Headers["Authorization"] != "Bearer token123" {
		t.Errorf("expected Authorization header, got %v", u.Headers)
	}
}

// TestHandleMCPAddWithEnv verifies that environment variables are parsed correctly.
func TestHandleMCPAddWithEnv(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "custom-server",
		"--env", "API_KEY=test123,DEBUG=true",
		"custom",
	})
	if err != nil {
		t.Fatalf("mcp add: %v", err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	if upstreams[0].Env["API_KEY"] != "test123" {
		t.Errorf("expected env API_KEY=test123, got %q", upstreams[0].Env["API_KEY"])
	}
	if upstreams[0].Env["DEBUG"] != "true" {
		t.Errorf("expected env DEBUG=true, got %q", upstreams[0].Env["DEBUG"])
	}
}

// TestHandleMCPAddDuplicate verifies that adding a duplicate upstream name fails.
func TestHandleMCPAddDuplicate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server1",
		"myserver",
	})
	if err != nil {
		t.Fatalf("first add: %v", err)
	}

	err = handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server2",
		"myserver",
	})
	if err == nil {
		t.Fatal("expected error for duplicate upstream name")
	}
}

// TestHandleMCPAddInvalidName verifies that invalid upstream names are rejected.
func TestHandleMCPAddInvalidName(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server",
		"has__double",
	})
	if err == nil {
		t.Fatal("expected error for invalid upstream name")
	}
}

// TestHandleMCPRemove verifies removing an upstream by name.
func TestHandleMCPRemove(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Add first.
	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server",
		"myserver",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Remove.
	err = handleMCPRemove([]string{
		"--db", dbPath,
		"myserver",
	})
	if err != nil {
		t.Fatalf("mcp remove: %v", err)
	}

	// Verify it's gone.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 0 {
		t.Errorf("expected 0 upstreams after remove, got %d", len(upstreams))
	}
}

// TestHandleMCPRemoveNameBeforeFlags is a regression for the v0.8.0 flag
// ordering bug: handleMCPRemove called fs.Parse(args) directly, so the
// positional name appearing before --db caused the parser to stop and
// silently fall through to the default "data/sluice.db", removing the
// wrong upstream.
func TestHandleMCPRemoveNameBeforeFlags(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	if err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server",
		"myserver",
	}); err != nil {
		t.Fatal(err)
	}

	if err := handleMCPRemove([]string{"myserver", "--db", dbPath}); err != nil {
		t.Fatalf("mcp remove with name-before-flags: %v", err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 0 {
		t.Errorf("expected 0 upstreams after name-before-flags removal, got %d", len(upstreams))
	}
}

// TestHandleMCPList verifies the list subcommand output.
func TestHandleMCPList(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Empty list should not error.
	err := handleMCPList([]string{"--db", dbPath})
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}

	// Add an upstream and list again.
	err = handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server",
		"--args", "arg1,arg2",
		"myserver",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = handleMCPList([]string{"--db", dbPath})
	if err != nil {
		t.Fatalf("list with upstream: %v", err)
	}
}

// TestMCPGatewayFromStoreSeeded verifies the gateway reads upstreams from the
// store when seeded via TOML import.
func TestMCPGatewayFromStoreSeeded(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	tomlData := `[policy]
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
`

	result, err := db.ImportTOML([]byte(tomlData))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.UpstreamsInserted != 2 {
		t.Errorf("expected 2 upstreams inserted, got %d", result.UpstreamsInserted)
	}

	// Read back and verify conversion to UpstreamConfig.
	rows, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(rows))
	}

	configs := make([]mcp.UpstreamConfig, len(rows))
	for i, r := range rows {
		configs[i] = mcp.UpstreamConfig{
			Name:       r.Name,
			Command:    r.Command,
			Args:       r.Args,
			Env:        r.Env,
			TimeoutSec: r.TimeoutSec,
		}
	}

	if configs[0].Name != "github" {
		t.Errorf("expected name github, got %q", configs[0].Name)
	}
	if configs[0].TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", configs[0].TimeoutSec)
	}
	if configs[1].Name != "filesystem" {
		t.Errorf("expected name filesystem, got %q", configs[1].Name)
	}
}

// TestMCPSubcommandRouting verifies that subcommand routing works correctly.
func TestMCPSubcommandRouting(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// "mcp add" should route to handleMCPAdd.
	err := handleMCPCommand([]string{"add", "--db", dbPath, "--command", "server", "myserver"})
	if err != nil {
		t.Fatalf("mcp add via routing: %v", err)
	}

	// "mcp list" should route to handleMCPList.
	err = handleMCPCommand([]string{"list", "--db", dbPath})
	if err != nil {
		t.Fatalf("mcp list via routing: %v", err)
	}

	// "mcp remove" should route to handleMCPRemove.
	err = handleMCPCommand([]string{"remove", "--db", dbPath, "myserver"})
	if err != nil {
		t.Fatalf("mcp remove via routing: %v", err)
	}
}

// TestHandleMCPGatewayNoUpstreams verifies the gateway starts and exits cleanly
// when stdin is closed (no upstreams configured).
func TestHandleMCPGatewayNoUpstreams(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Pre-create the DB with policy config so gateway can load.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	dvMCP := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvMCP})
	_ = db.Close()

	if os.Getenv("TEST_MCP_SUBPROCESS") == "no_upstreams" {
		// Replace stdin with a pipe that is immediately closed on the
		// write end so RunStdio sees EOF and returns cleanly.
		r, w, pipeErr := os.Pipe()
		if pipeErr != nil {
			fmt.Fprintf(os.Stderr, "os.Pipe: %v\n", pipeErr)
			os.Exit(1)
		}
		_ = w.Close()
		os.Stdin = r
		err := handleMCPGateway([]string{"--db", os.Getenv("TEST_DB_PATH")})
		if err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleMCPGatewayNoUpstreams")
	cmd.Env = append(os.Environ(),
		"TEST_MCP_SUBPROCESS=no_upstreams",
		"TEST_DB_PATH="+dbPath,
		"TELEGRAM_BOT_TOKEN=",
		"TELEGRAM_CHAT_ID=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected clean exit, got error: %v\noutput: %s", err, out)
	}
}

// TestHandleMCPGatewayInvalidChatID verifies the gateway exits when the
// Telegram chat ID is not a valid integer.
func TestHandleMCPGatewayInvalidChatID(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	dvMCP2 := "deny"
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvMCP2})
	_ = db.Close()

	if os.Getenv("TEST_MCP_SUBPROCESS") == "invalid_chat_id" {
		err := handleMCPGateway([]string{
			"--db", os.Getenv("TEST_DB_PATH"),
			"--telegram-token", "fake-token",
			"--telegram-chat-id", "not-a-number",
		})
		if err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleMCPGatewayInvalidChatID")
	cmd.Env = append(os.Environ(),
		"TEST_MCP_SUBPROCESS=invalid_chat_id",
		"TEST_DB_PATH="+dbPath,
	)
	err = cmd.Run()
	var e *exec.ExitError
	if errors.As(err, &e) && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code for invalid chat ID")
}

// TestHandleMCPAddEnvInvalidFormat verifies that bad env format is rejected.
func TestHandleMCPAddEnvInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server",
		"--env", "BADFORMAT",
		"myserver",
	})
	if err == nil {
		t.Fatal("expected error for invalid env format")
	}
}

// TestHandleMCPAddWithTransportHTTP verifies that the --transport flag stores
// the correct transport type for HTTP upstreams.
func TestHandleMCPAddWithTransportHTTP(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "https://remote-server/mcp",
		"--transport", "http",
		"--timeout", "60",
		"github",
	})
	if err != nil {
		t.Fatalf("mcp add --transport http: %v", err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	if upstreams[0].Name != "github" {
		t.Errorf("expected name github, got %q", upstreams[0].Name)
	}
	if upstreams[0].Command != "https://remote-server/mcp" {
		t.Errorf("expected command https://remote-server/mcp, got %q", upstreams[0].Command)
	}
	if upstreams[0].Transport != "http" {
		t.Errorf("expected transport http, got %q", upstreams[0].Transport)
	}
	if upstreams[0].TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", upstreams[0].TimeoutSec)
	}
}

// TestHandleMCPAddWithTransportWebSocket verifies the --transport websocket flag.
func TestHandleMCPAddWithTransportWebSocket(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "wss://mcp.example.com/ws",
		"--transport", "websocket",
		"realtime",
	})
	if err != nil {
		t.Fatalf("mcp add --transport websocket: %v", err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	if upstreams[0].Transport != "websocket" {
		t.Errorf("expected transport websocket, got %q", upstreams[0].Transport)
	}
}

// TestHandleMCPAddWithTransportInvalid verifies that invalid transport types are rejected.
func TestHandleMCPAddWithTransportInvalid(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "server",
		"--transport", "grpc",
		"myserver",
	})
	if err == nil {
		t.Fatal("expected error for invalid transport type")
	}
}

// TestHandleMCPAddDefaultTransportIsStdio verifies that omitting --transport defaults to stdio.
func TestHandleMCPAddDefaultTransportIsStdio(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handleMCPAdd([]string{
		"--db", dbPath,
		"--command", "my-server",
		"local",
	})
	if err != nil {
		t.Fatalf("mcp add (default transport): %v", err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	upstreams, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	if upstreams[0].Transport != "stdio" {
		t.Errorf("expected transport stdio, got %q", upstreams[0].Transport)
	}
}

// TestHandleMCPGatewayInvalidDB verifies error on bad database path.
func TestHandleMCPGatewayInvalidDB(t *testing.T) {
	err := handleMCPGateway([]string{"--db", "/nonexistent/dir/sluice.db"})
	if err == nil {
		t.Fatal("expected error for invalid DB path")
	}
}

// TestHandleMCPGatewayEmptyDB verifies the gateway can start with an empty DB
// and no upstreams. It uses stdin close to trigger immediate exit.
func TestHandleMCPGatewayEmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Pre-create the DB so it's valid.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Close stdin immediately to make RunStdio return.
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_ = w.Close() // close immediately so scanner sees EOF
	defer func() { os.Stdin = oldStdin }()

	err = handleMCPGateway([]string{"--db", dbPath})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// TestHandleMCPGatewayWithConfigSeed verifies that --config seeds an empty DB.
func TestHandleMCPGatewayWithConfigSeed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	configPath := filepath.Join(dir, "config.toml")

	// Write a minimal config file.
	if err := os.WriteFile(configPath, []byte(`
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
name = "test rule"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-create the DB.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Close stdin immediately.
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	err = handleMCPGateway([]string{"--db", dbPath, "--config", configPath})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the config was imported.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule after seed, got %d", len(rules))
	}
	if rules[0].Destination != "api.example.com" {
		t.Errorf("rule destination = %q, want %q", rules[0].Destination, "api.example.com")
	}
}

// TestHandleMCPGatewayWithAudit verifies audit logger setup.
func TestHandleMCPGatewayWithAudit(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	auditPath := filepath.Join(dir, "audit.jsonl")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	err = handleMCPGateway([]string{"--db", dbPath, "--audit", auditPath})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify audit file was created.
	if _, err := os.Stat(auditPath); err != nil {
		t.Errorf("audit file should have been created: %v", err)
	}
}

// TestHandleMCPCommandUnknown verifies error on unrecognized subcommand.
func TestHandleMCPCommandUnknown(t *testing.T) {
	err := handleMCPCommand([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

// TestHandleMCPCommandRoutesToGateway verifies flag-style args start the gateway.
func TestHandleMCPCommandRoutesToGateway(t *testing.T) {
	// --db with an invalid path should fail fast.
	err := handleMCPCommand([]string{"--db", "/nonexistent/dir/sluice.db"})
	if err == nil {
		t.Fatal("expected error for invalid DB path through command routing")
	}
}

// TestMCPGatewayStoreBackedUpstreams verifies that a gateway config can be
// built from store-backed upstreams with all fields populated correctly.
func TestMCPGatewayStoreBackedUpstreams(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Add upstreams with various options.
	_, _ = db.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Args:       []string{"-y", "@mcp/server-github"},
		Env:        map[string]string{"GITHUB_TOKEN": "ghp_test"},
		TimeoutSec: 60,
	})
	_, _ = db.AddMCPUpstream("fs", "fs-server", store.MCPUpstreamOpts{
		Args: []string{"--root", "/tmp"},
	})

	// Read and convert.
	rows, err := db.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(rows))
	}

	configs := make([]mcp.UpstreamConfig, len(rows))
	for i, r := range rows {
		configs[i] = mcp.UpstreamConfig{
			Name:       r.Name,
			Command:    r.Command,
			Args:       r.Args,
			Env:        r.Env,
			TimeoutSec: r.TimeoutSec,
		}
	}

	// Verify github upstream.
	gh := configs[0]
	if gh.Name != "github" {
		t.Errorf("expected name github, got %q", gh.Name)
	}
	if gh.Command != "npx" {
		t.Errorf("expected command npx, got %q", gh.Command)
	}
	if len(gh.Args) != 2 || gh.Args[0] != "-y" {
		t.Errorf("expected args [-y @mcp/server-github], got %v", gh.Args)
	}
	if gh.Env["GITHUB_TOKEN"] != "ghp_test" {
		t.Errorf("expected GITHUB_TOKEN=ghp_test, got %q", gh.Env["GITHUB_TOKEN"])
	}
	if gh.TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", gh.TimeoutSec)
	}

	// Verify fs upstream with default timeout.
	fsUpstream := configs[1]
	if fsUpstream.Name != "fs" {
		t.Errorf("expected name fs, got %q", fsUpstream.Name)
	}
	if fsUpstream.TimeoutSec != 120 {
		t.Errorf("expected default timeout 120, got %d", fsUpstream.TimeoutSec)
	}
}
