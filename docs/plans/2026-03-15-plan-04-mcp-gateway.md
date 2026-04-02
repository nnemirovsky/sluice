# Sluice Plan 4: MCP Gateway

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an MCP gateway that intercepts tool calls between the AI agent and upstream MCP servers. Provides semantic governance (tool names, arguments, per-action policy) and Telegram approval for tool calls. Catches local tools (filesystem, exec) that never hit the network.

**Architecture:** Sluice spawns upstream MCP servers as child processes, performs MCP initialize handshake, discovers tools, and namespaces them. Agent connects to Sluice MCP gateway (stdio or HTTP). On tool call, Sluice evaluates tool-level policy, optionally asks Telegram for approval, then forwards to the correct upstream.

**Tech Stack:** Go, JSON-RPC 2.0 over stdio/HTTP, MCP protocol

**Depends on:** Plan 1 (SOCKS5 Proxy Core), Plan 2 (Telegram Approval)

---

## File Structure

```
sluice/
  internal/
    mcp/
      gateway.go         # Core gateway: intercept, govern, forward
      gateway_test.go
      upstream.go        # Upstream server process management
      upstream_test.go
      transport.go       # Stdio and HTTP transports
      transport_test.go
      types.go           # JSON-RPC and MCP protocol types
      policy.go          # Tool-level policy evaluation
      policy_test.go
  cmd/
    sluice/
      main.go            # Modify: add mcp subcommand
```

---

## Chunk 1: MCP Protocol Types and Upstream Management

### Task 1: MCP and JSON-RPC types

**Files:**
- Create: `internal/mcp/types.go`

- [x] **Step 1: Implement protocol types**

```go
// internal/mcp/types.go
package mcp

import "encoding/json"

// JSON-RPC 2.0

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP Protocol

type InitializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ClientInfo      Info       `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      Info         `json:"serverInfo"`
}

type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

type ToolsCapability struct{}

type Info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type ToolResult struct {
	Content []ToolContent          `json:"content"`
	Meta    map[string]interface{} `json:"_meta,omitempty"`
	IsError bool                   `json:"isError,omitempty"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
```

- [x] **Step 2: Commit**

```bash
git add internal/mcp/types.go
git commit -m "feat: MCP and JSON-RPC protocol types"
```

---

### Task 2: Upstream server management

**Files:**
- Create: `internal/mcp/upstream.go`
- Create: `internal/mcp/upstream_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/mcp/upstream_test.go
package mcp

import "testing"

func TestUpstreamConfig(t *testing.T) {
	cfg := UpstreamConfig{
		Name:    "test",
		Command: "echo",
		Args:    []string{"hello"},
	}
	if cfg.Name != "test" {
		t.Errorf("expected name test, got %q", cfg.Name)
	}
}
```

- [ ] **Step 2: Implement upstream.go**

```go
// internal/mcp/upstream.go
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
	"sync/atomic"
)

type UpstreamConfig struct {
	Name    string            `toml:"name"`
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
}

type Upstream struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
	tools   []Tool
	nextID  atomic.Int64
}

func StartUpstream(cfg UpstreamConfig) (*Upstream, error) {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	for k, v := range cfg.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %q: %w", cfg.Command, err)
	}

	u := &Upstream{
		name:    cfg.Name,
		cmd:     cmd,
		stdin:   stdin,
		scanner: bufio.NewScanner(stdout),
	}
	u.scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	return u, nil
}

func (u *Upstream) Send(req JSONRPCRequest) (*JSONRPCResponse, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := u.stdin.Write(data); err != nil {
		return nil, fmt.Errorf("write to upstream %s: %w", u.name, err)
	}

	if !u.scanner.Scan() {
		return nil, fmt.Errorf("upstream %s closed", u.name)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(u.scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse upstream %s response: %w", u.name, err)
	}
	return &resp, nil
}

func (u *Upstream) Initialize() error {
	id := json.RawMessage(`1`)
	params, _ := json.Marshal(InitializeParams{
		ProtocolVersion: "2025-03-26",
		Capabilities:    Capabilities{Tools: &ToolsCapability{}},
		ClientInfo:      Info{Name: "sluice", Version: "0.1.0"},
	})

	resp, err := u.Send(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "initialize",
		Params:  params,
	})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("initialize error: %s", resp.Error.Message)
	}

	// Send initialized notification
	notif, _ := json.Marshal(JSONRPCRequest{JSONRPC: "2.0", Method: "notifications/initialized"})
	notif = append(notif, '\n')
	u.mu.Lock()
	u.stdin.Write(notif)
	u.mu.Unlock()

	return nil
}

func (u *Upstream) DiscoverTools() ([]Tool, error) {
	id := json.RawMessage(`2`)
	resp, err := u.Send(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/list",
	})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("list_tools error: %s", resp.Error.Message)
	}

	var result ListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tools: %w", err)
	}

	// Namespace tools with upstream name
	for i := range result.Tools {
		result.Tools[i].Name = u.name + "__" + result.Tools[i].Name
	}
	u.tools = result.Tools

	log.Printf("upstream %s: discovered %d tools", u.name, len(result.Tools))
	return result.Tools, nil
}

func (u *Upstream) CallTool(toolName string, arguments json.RawMessage) (*JSONRPCResponse, error) {
	id := json.RawMessage(fmt.Sprintf(`%d`, u.nextID.Add(1)))
	params, _ := json.Marshal(CallToolParams{Name: toolName, Arguments: arguments})

	return u.Send(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  params,
	})
}

func (u *Upstream) Stop() error {
	u.stdin.Close()
	return u.cmd.Wait()
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/mcp/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/mcp/
git commit -m "feat: MCP upstream server management"
```

---

## Chunk 2: Tool Policy and Gateway

### Task 3: Tool-level policy

**Files:**
- Create: `internal/mcp/policy.go`
- Create: `internal/mcp/policy_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/mcp/policy_test.go
package mcp

import (
	"testing"

	"github.com/nemirovsky/sluice/internal/policy"
)

func TestToolPolicyEvaluate(t *testing.T) {
	tp := NewToolPolicy([]ToolRule{
		{Tool: "github__list_*", Verdict: "allow"},
		{Tool: "github__delete_*", Verdict: "deny"},
		{Tool: "filesystem__write_*", Verdict: "ask"},
		{Tool: "exec__*", Verdict: "deny"},
	}, policy.Ask)

	tests := []struct {
		tool string
		want policy.Verdict
	}{
		{"github__list_repositories", policy.Allow},
		{"github__list_issues", policy.Allow},
		{"github__delete_repository", policy.Deny},
		{"filesystem__write_file", policy.Ask},
		{"filesystem__read_file", policy.Ask}, // default
		{"exec__run", policy.Deny},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			got := tp.Evaluate(tt.tool)
			if got != tt.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcp/ -v -run TestToolPolicyEvaluate`
Expected: FAIL

- [ ] **Step 3: Implement policy.go**

```go
// internal/mcp/policy.go
package mcp

import (
	"github.com/nemirovsky/sluice/internal/policy"
)

type ToolRule struct {
	Tool    string `toml:"tool"`
	Verdict string `toml:"verdict"`
	Note    string `toml:"note"`
}

type compiledToolRule struct {
	glob    *policy.Glob
	verdict policy.Verdict
}

type ToolPolicy struct {
	rules    []compiledToolRule
	fallback policy.Verdict
}

func NewToolPolicy(rules []ToolRule, fallback policy.Verdict) *ToolPolicy {
	compiled := make([]compiledToolRule, 0, len(rules))
	for _, r := range rules {
		g, err := policy.CompileGlob(r.Tool)
		if err != nil {
			continue
		}
		var v policy.Verdict
		switch r.Verdict {
		case "allow":
			v = policy.Allow
		case "deny":
			v = policy.Deny
		case "ask":
			v = policy.Ask
		default:
			continue
		}
		compiled = append(compiled, compiledToolRule{glob: g, verdict: v})
	}
	return &ToolPolicy{rules: compiled, fallback: fallback}
}

func (tp *ToolPolicy) Evaluate(toolName string) policy.Verdict {
	// Deny rules first
	for _, r := range tp.rules {
		if r.verdict == policy.Deny && r.glob.Match(toolName) {
			return policy.Deny
		}
	}
	// Then allow
	for _, r := range tp.rules {
		if r.verdict == policy.Allow && r.glob.Match(toolName) {
			return policy.Allow
		}
	}
	// Then ask
	for _, r := range tp.rules {
		if r.verdict == policy.Ask && r.glob.Match(toolName) {
			return policy.Ask
		}
	}
	return tp.fallback
}
```

- [ ] **Step 4: Run test**

Run: `go test ./internal/mcp/ -v -run TestToolPolicyEvaluate`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/mcp/policy.go internal/mcp/policy_test.go
git commit -m "feat: tool-level policy evaluation for MCP gateway"
```

---

### Task 4: MCP Gateway core

**Files:**
- Create: `internal/mcp/gateway.go`

- [ ] **Step 1: Implement the gateway**

```go
// internal/mcp/gateway.go
package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	tg "github.com/nemirovsky/sluice/internal/telegram"
)

type GatewayConfig struct {
	Upstreams  []UpstreamConfig
	ToolPolicy *ToolPolicy
	Audit      *audit.FileLogger
	Broker     *tg.ApprovalBroker
	TimeoutSec int
}

type Gateway struct {
	upstreams  map[string]*Upstream // upstream name -> upstream
	toolMap    map[string]string    // namespaced tool -> upstream name
	allTools   []Tool
	policy     *ToolPolicy
	audit      *audit.FileLogger
	broker     *tg.ApprovalBroker
	timeoutSec int
}

func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	gw := &Gateway{
		upstreams:  make(map[string]*Upstream),
		toolMap:    make(map[string]string),
		policy:     cfg.ToolPolicy,
		audit:      cfg.Audit,
		broker:     cfg.Broker,
		timeoutSec: cfg.TimeoutSec,
	}
	if gw.timeoutSec == 0 {
		gw.timeoutSec = 120
	}

	for _, ucfg := range cfg.Upstreams {
		u, err := StartUpstream(ucfg)
		if err != nil {
			return nil, fmt.Errorf("start upstream %s: %w", ucfg.Name, err)
		}
		if err := u.Initialize(); err != nil {
			return nil, fmt.Errorf("initialize upstream %s: %w", ucfg.Name, err)
		}
		tools, err := u.DiscoverTools()
		if err != nil {
			return nil, fmt.Errorf("discover tools %s: %w", ucfg.Name, err)
		}
		gw.upstreams[ucfg.Name] = u
		gw.allTools = append(gw.allTools, tools...)
		for _, t := range tools {
			gw.toolMap[t.Name] = ucfg.Name
		}
	}
	return gw, nil
}

func (gw *Gateway) Tools() []Tool {
	return gw.allTools
}

func (gw *Gateway) HandleToolCall(req CallToolParams) (*ToolResult, error) {
	// 1. Evaluate tool policy
	verdict := gw.policy.Evaluate(req.Name)

	if gw.audit != nil {
		gw.audit.Log(audit.Event{
			Tool:    req.Name,
			Action:  "tool_call",
			Verdict: verdict.String(),
		})
	}

	switch verdict {
	case policy.Deny:
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: "Tool call denied by policy"}},
			IsError: true,
		}, nil

	case policy.Ask:
		if gw.broker == nil {
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Tool call requires approval (no broker configured)"}},
				IsError: true,
			}, nil
		}
		argsStr := string(req.Arguments)
		if len(argsStr) > 200 {
			argsStr = argsStr[:200] + "..."
		}
		log.Printf("[MCP ASK] %s (args: %s)", req.Name, argsStr)
		// Reuse the approval broker (port=0 to indicate MCP, not network)
		timeout := time.Duration(gw.timeoutSec) * time.Second
		resp, err := gw.broker.Request(fmt.Sprintf("MCP:%s", req.Name), 0, timeout)
		if err != nil {
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Approval timeout"}},
				IsError: true,
			}, nil
		}
		if resp == tg.ResponseDeny {
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Denied by user"}},
				IsError: true,
			}, nil
		}
		// Fall through to forward
	}

	// 2. Find upstream
	upstreamName, ok := gw.toolMap[req.Name]
	if !ok {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", req.Name)}},
			IsError: true,
		}, nil
	}
	upstream := gw.upstreams[upstreamName]

	// 3. Strip namespace prefix for upstream call
	originalName := strings.TrimPrefix(req.Name, upstreamName+"__")

	// 4. Forward to upstream
	resp, err := upstream.CallTool(originalName, req.Arguments)
	if err != nil {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Upstream error: %v", err)}},
			IsError: true,
		}, nil
	}
	if resp.Error != nil {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: resp.Error.Message}},
			IsError: true,
		}, nil
	}

	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tool result: %w", err)
	}

	// 5. Add governance metadata
	if result.Meta == nil {
		result.Meta = make(map[string]interface{})
	}
	result.Meta["governance"] = map[string]interface{}{
		"verdict": verdict.String(),
		"tool":    req.Name,
		"version": "0.1.0",
	}

	return &result, nil
}

func (gw *Gateway) Stop() {
	for name, u := range gw.upstreams {
		log.Printf("stopping upstream %s", name)
		u.Stop()
	}
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/mcp/gateway.go
git commit -m "feat: MCP gateway core with tool policy and approval"
```

---

### Task 5: Stdio transport for MCP gateway

**Files:**
- Create: `internal/mcp/transport.go`

- [ ] **Step 1: Implement stdio server**

```go
// internal/mcp/transport.go
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func (gw *Gateway) RunStdio() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		var req JSONRPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			log.Printf("parse error: %v", err)
			continue
		}

		resp := gw.handleRequest(req)
		if resp != nil {
			encoder.Encode(resp)
		}
	}
	return scanner.Err()
}

func (gw *Gateway) handleRequest(req JSONRPCRequest) *JSONRPCResponse {
	switch req.Method {
	case "initialize":
		result, _ := json.Marshal(InitializeResult{
			ProtocolVersion: "2025-03-26",
			Capabilities:    Capabilities{Tools: &ToolsCapability{}},
			ServerInfo:      Info{Name: "sluice", Version: "0.1.0"},
		})
		return &JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

	case "notifications/initialized":
		return nil // notification, no response

	case "tools/list":
		result, _ := json.Marshal(ListToolsResult{Tools: gw.allTools})
		return &JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

	case "tools/call":
		var params CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0", ID: req.ID,
				Error: &JSONRPCError{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)},
			}
		}
		toolResult, err := gw.HandleToolCall(params)
		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0", ID: req.ID,
				Error: &JSONRPCError{Code: -32603, Message: err.Error()},
			}
		}
		result, _ := json.Marshal(toolResult)
		return &JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &JSONRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/mcp/transport.go
git commit -m "feat: MCP gateway stdio transport"
```

---

### Task 6: Add MCP tool policy to TOML config

**Files:**
- Modify: `internal/policy/types.go`

- [ ] **Step 1: Add tool policy sections to the policy file struct**

Add to `policyFile` struct in types.go:

```go
ToolAllow []mcp.ToolRule `toml:"tool_allow"`
ToolDeny  []mcp.ToolRule `toml:"tool_deny"`
ToolAsk   []mcp.ToolRule `toml:"tool_ask"`
```

Note: to avoid circular imports, ToolRule should be defined in the policy package or a shared types package. Move the struct:

```go
// internal/policy/types.go
type ToolRule struct {
	Tool    string `toml:"tool"`
	Verdict string `toml:"verdict"`
	Note    string `toml:"note"`
}
```

Update the Engine to include tool rules and expose them.

- [ ] **Step 2: Write test with tool policy in TOML**

Create `testdata/policy_with_tools.toml`:

```toml
[policy]
default = "ask"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[tool_allow]]
tool = "github__list_*"

[[tool_deny]]
tool = "exec__*"

[[tool_ask]]
tool = "filesystem__write_*"
```

- [ ] **Step 3: Test loading**

```go
func TestLoadPolicyWithTools(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_with_tools.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.ToolAllowRules) != 1 {
		t.Errorf("expected 1 tool_allow, got %d", len(eng.ToolAllowRules))
	}
	if len(eng.ToolDenyRules) != 1 {
		t.Errorf("expected 1 tool_deny, got %d", len(eng.ToolDenyRules))
	}
}
```

- [ ] **Step 4: Run all tests**

Run: `go test ./... -v -timeout 30s`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ testdata/
git commit -m "feat: tool-level policy rules in TOML config"
```

---

### Task 7: Wire MCP gateway into CLI

**Files:**
- Modify: `cmd/sluice/main.go`

- [ ] **Step 1: Add mcp subcommand**

```go
case "mcp":
	handleMCPCommand(os.Args[2:])
	return
```

Implement `handleMCPCommand` that loads policy, creates tool policy from TOML rules, starts upstream servers, creates gateway, and runs stdio transport.

- [ ] **Step 2: Test manually**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | ./sluice mcp
```

Expected: JSON response with server info

- [ ] **Step 3: Commit**

```bash
git add cmd/
git commit -m "feat: wire MCP gateway into CLI"
```

---

## Chunk 4: Content Inspection

### Task 8: Argument inspection and response redaction

The MCP gateway currently forwards tool calls after policy check. Add
content inspection to detect secrets/PII in tool arguments (before
forwarding) and redact sensitive data in responses (before returning to
the agent).

**Files:**
- Create: `internal/mcp/inspect.go`
- Create: `internal/mcp/inspect_test.go`
- Modify: `internal/mcp/gateway.go` (add inspection hooks)

- [ ] **Step 1: Define inspection rules in policy TOML**

```toml
# Content inspection rules (in policy.toml)
[[inspect_block]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
name = "api_key_leak"
note = "Block tool args containing API key patterns"

[[inspect_block]]
pattern = "(?i)(password|passwd|secret)\\s*[:=]\\s*\\S+"
name = "credential_in_args"
note = "Block tool args containing inline credentials"

[[inspect_redact]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
replacement = "[REDACTED_API_KEY]"
name = "api_key_in_response"
note = "Redact API keys in tool responses before agent sees them"

[[inspect_redact]]
pattern = "(?i)\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
replacement = "[REDACTED_EMAIL]"
name = "email_in_response"
note = "Redact email addresses in tool responses"
```

- [ ] **Step 2: Implement inspection engine**

```go
// internal/mcp/inspect.go

type InspectionResult struct {
    Blocked  bool
    Reason   string
    Findings []Finding
}

type Finding struct {
    RuleName string
    Match    string
    Location string // "args" or "response"
}

// InspectArguments checks tool arguments for blocked patterns.
func InspectArguments(args map[string]interface{}, rules []InspectBlockRule) InspectionResult

// RedactResponse sanitizes tool response content before returning to agent.
func RedactResponse(content string, rules []InspectRedactRule) string
```

- [ ] **Step 3: Write tests for argument blocking**

```go
func TestInspectBlocksAPIKeyInArgs(t *testing.T) {
    // Tool args containing "sk-ant-api03-abc123..." should be blocked
}
func TestInspectAllowsCleanArgs(t *testing.T) {
    // Normal tool args without secrets should pass
}
```

- [ ] **Step 4: Write tests for response redaction**

```go
func TestRedactAPIKeyInResponse(t *testing.T) {
    // Response containing "sk-ant-api03-abc123..." -> "[REDACTED_API_KEY]"
}
func TestRedactEmailInResponse(t *testing.T) {
    // Response containing "user@example.com" -> "[REDACTED_EMAIL]"
}
func TestRedactPreservesCleanContent(t *testing.T) {
    // Response without sensitive content should be unchanged
}
```

- [ ] **Step 5: Integrate into gateway.go**

In the tool call handler:
1. Before forwarding: run `InspectArguments`. If blocked, return error
   to agent and log to audit.
2. After receiving response: run `RedactResponse` on content before
   returning to agent.

- [ ] **Step 6: Add inspection rules to TOML parser**

Extend `policyFile` struct to include `InspectBlock` and `InspectRedact`
rule arrays.

- [ ] **Step 7: Run tests**

Run: `go test ./internal/mcp/ -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/mcp/inspect.go internal/mcp/inspect_test.go internal/mcp/gateway.go
git commit -m "feat: content inspection with argument blocking and response redaction"
```
