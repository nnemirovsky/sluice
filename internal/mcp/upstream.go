package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamConfig describes how to launch an upstream MCP server process.
type UpstreamConfig struct {
	Name    string            `toml:"name"`
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
}

// Upstream manages a running upstream MCP server process. Communication
// happens over JSON-RPC 2.0 via the process's stdin/stdout.
type Upstream struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
	tools   []Tool
	nextID  atomic.Int64
}

// StartUpstream launches an upstream MCP server process.
func StartUpstream(cfg UpstreamConfig) (*Upstream, error) {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	if len(cfg.Env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range cfg.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
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

// Send writes a JSON-RPC request to the upstream process and reads one response.
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

// Initialize performs the MCP initialize handshake with the upstream server.
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

	// Send initialized notification (no response expected, write directly)
	notif, _ := json.Marshal(JSONRPCRequest{JSONRPC: "2.0", Method: "notifications/initialized"})
	notif = append(notif, '\n')
	u.mu.Lock()
	_, err = u.stdin.Write(notif)
	u.mu.Unlock()

	return err
}

// DiscoverTools calls tools/list on the upstream and namespaces the results.
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

// CallTool invokes tools/call on the upstream server.
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

// Stop closes stdin and waits for the upstream process to exit. If the
// process does not exit within 5 seconds, it is killed.
func (u *Upstream) Stop() error {
	u.stdin.Close()
	done := make(chan error, 1)
	go func() {
		done <- u.cmd.Wait()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		u.cmd.Process.Kill()
		<-done
		return fmt.Errorf("upstream %s killed after timeout", u.name)
	}
}
