package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Transport type constants for MCP upstream connections.
const (
	TransportStdio = "stdio"     // child process (default)
	TransportHTTP  = "http"      // Streamable HTTP client
	TransportWS    = "websocket" // WebSocket client
)

// vaultPrefix marks env values that should be resolved from the vault.
const vaultPrefix = "vault:"

// CredentialResolver resolves a credential name to its plaintext value.
// Typically wraps a vault.Provider. The caller should treat the returned
// string as sensitive and avoid logging it.
type CredentialResolver func(name string) (string, error)

// ValidTransport returns true if t is a recognized transport type.
func ValidTransport(t string) bool {
	return t == TransportStdio || t == TransportHTTP || t == TransportWS
}

// MCPUpstream is the interface satisfied by all upstream transport types
// (stdio, HTTP, WebSocket). The gateway uses this to interact with upstreams
// without knowing which transport is in use.
type MCPUpstream interface {
	Initialize() error
	DiscoverTools() ([]Tool, error)
	CallTool(toolName string, arguments json.RawMessage) (*JSONRPCResponse, error)
	Stop() error
}

// StartUpstreamForTransport creates and returns the correct MCPUpstream
// implementation based on the transport field in the config. For stdio
// upstreams it spawns a child process. For HTTP and WebSocket upstreams
// it creates a client pointing at the URL in the Command field.
func StartUpstreamForTransport(cfg UpstreamConfig) (MCPUpstream, error) {
	transport := cfg.Transport
	if transport == "" {
		transport = TransportStdio
	}
	switch transport {
	case TransportStdio:
		return StartUpstream(cfg)
	case TransportHTTP:
		return NewHTTPUpstream(cfg.Name, cfg.Command, cfg.TimeoutSec), nil
	case TransportWS:
		return NewWSUpstream(cfg.Name, cfg.Command, cfg.TimeoutSec), nil
	default:
		return nil, fmt.Errorf("unknown transport %q for upstream %s", transport, cfg.Name)
	}
}

// UpstreamConfig describes how to launch an upstream MCP server process.
type UpstreamConfig struct {
	Name       string
	Command    string
	Args       []string
	Env        map[string]string
	TimeoutSec int
	Transport  string // "stdio" (default), "http", or "websocket"
}

// resolveVaultEnv returns a copy of env with "vault:" prefixed values resolved
// through the credential resolver. Plain values are copied unchanged. Returns
// an error if any vault credential cannot be resolved.
func resolveVaultEnv(env map[string]string, resolver CredentialResolver) (map[string]string, error) {
	if resolver == nil || len(env) == 0 {
		return env, nil
	}
	resolved := make(map[string]string, len(env))
	for k, v := range env {
		if strings.HasPrefix(v, vaultPrefix) {
			credName := strings.TrimPrefix(v, vaultPrefix)
			val, err := resolver(credName)
			if err != nil {
				return nil, fmt.Errorf("resolve credential %q for env var %s: %w", credName, k, err)
			}
			resolved[k] = val
		} else {
			resolved[k] = v
		}
	}
	return resolved, nil
}

// Upstream manages a running upstream MCP server process. Communication
// happens over JSON-RPC 2.0 via the process's stdin/stdout. A background
// goroutine reads lines from stdout so that Send can enforce a read timeout.
type Upstream struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	lines   chan []byte     // lines read by the background goroutine
	scanErr atomic.Value   // stores the scanner error, if any
	waitCh  chan error      // receives cmd.Wait() result exactly once
	done    chan struct{}   // closed by Stop to unblock the scanner goroutine
	stopOnce sync.Once
	mu      sync.Mutex
	nextID  atomic.Int64
	timeout time.Duration
}

const defaultUpstreamTimeout = 120 * time.Second

var validUpstreamName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// ValidateUpstreamName checks that the name is non-empty, contains only
// alphanumeric characters, hyphens, and single underscores, and does not
// contain the "__" namespace separator.
func ValidateUpstreamName(name string) error {
	if name == "" {
		return fmt.Errorf("upstream name must not be empty")
	}
	if strings.Contains(name, "__") {
		return fmt.Errorf("upstream name %q must not contain \"__\" (namespace separator)", name)
	}
	if !validUpstreamName.MatchString(name) {
		return fmt.Errorf("upstream name %q must match [a-zA-Z0-9][a-zA-Z0-9_-]*", name)
	}
	return nil
}

// StartUpstream launches an upstream MCP server process and starts a
// background goroutine that reads lines from its stdout into a channel.
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

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %q: %w", cfg.Command, err)
	}

	timeout := defaultUpstreamTimeout
	if cfg.TimeoutSec > 0 {
		timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}

	u := &Upstream{
		name:    cfg.Name,
		cmd:     cmd,
		stdin:   stdin,
		lines:   make(chan []byte, 64),
		waitCh:  make(chan error, 1),
		done:    make(chan struct{}),
		timeout: timeout,
	}

	// Background goroutine owns the scanner. Lines are copied into the
	// channel so Send can read them with a timeout via select.
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	go func() {
		for scanner.Scan() {
			data := make([]byte, len(scanner.Bytes()))
			copy(data, scanner.Bytes())
			select {
			case u.lines <- data:
			case <-u.done:
				// Stop was called; discard remaining output so we can
				// reach cmd.Wait and avoid a deadlock.
				goto drain
			}
		}
	drain:
		if err := scanner.Err(); err != nil {
			u.scanErr.Store(err)
		}
		close(u.lines)
		// Reap the process to prevent zombies. Wait is called exactly
		// once here; Stop() reads the result from waitCh.
		u.waitCh <- u.cmd.Wait()
	}()

	return u, nil
}

// readLine reads a single line from the background reader channel.
// The caller-provided deadline channel enforces an overall timeout across
// multiple readLine calls (e.g. when skipping notifications in Send).
func (u *Upstream) readLine(deadline <-chan time.Time) ([]byte, error) {
	select {
	case line, ok := <-u.lines:
		if !ok {
			if err, ok := u.scanErr.Load().(error); ok {
				return nil, fmt.Errorf("upstream %s: %w", u.name, err)
			}
			return nil, fmt.Errorf("upstream %s closed", u.name)
		}
		return line, nil
	case <-deadline:
		return nil, fmt.Errorf("upstream %s: read timeout after %v", u.name, u.timeout)
	}
}

// Send writes a JSON-RPC request to the upstream process and reads the
// matching response. Notifications (no id) and server-initiated requests
// (id present but includes a method field) are logged and skipped so they
// cannot be misattributed. The response id must match the request id.
// Returns an error if no matching response arrives within the timeout.
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

	// Normalize the request id for comparison (e.g. strip whitespace).
	wantID := string(req.ID)

	// Single deadline for the entire Send operation. Notifications, server
	// requests, and mismatched responses no longer reset the clock.
	deadline := time.After(u.timeout)

	for {
		line, err := u.readLine(deadline)
		if err != nil {
			return nil, err
		}

		// Peek at the raw message to check for id and method fields.
		var peek struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(line, &peek); err != nil {
			return nil, fmt.Errorf("parse upstream %s response: %w", u.name, err)
		}

		// Skip notifications (no id).
		if peek.ID == nil {
			log.Printf("upstream %s: skipping notification", u.name)
			continue
		}

		// Skip server-initiated requests (has id AND method).
		if peek.Method != "" {
			log.Printf("upstream %s: skipping server request %q (id=%s)", u.name, peek.Method, string(peek.ID))
			continue
		}

		// Verify the response id matches our request id.
		if string(peek.ID) != wantID {
			log.Printf("upstream %s: skipping mismatched response id=%s (want %s)", u.name, string(peek.ID), wantID)
			continue
		}

		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("parse upstream %s response: %w", u.name, err)
		}
		return &resp, nil
	}
}

// Initialize performs the MCP initialize handshake with the upstream server.
func (u *Upstream) Initialize() error {
	id := json.RawMessage(fmt.Sprintf(`%d`, u.nextID.Add(1)))
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
	id := json.RawMessage(fmt.Sprintf(`%d`, u.nextID.Add(1)))
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
// process does not exit within 5 seconds, it is killed. The background
// scanner goroutine calls cmd.Wait() exactly once and sends the result
// to waitCh.
func (u *Upstream) Stop() error {
	var result error
	u.stopOnce.Do(func() {
		_ = u.stdin.Close()
		close(u.done) // unblock the scanner goroutine if the channel is full
		select {
		case err := <-u.waitCh:
			result = err
		case <-time.After(5 * time.Second):
			_ = u.cmd.Process.Kill()
			result = <-u.waitCh
		}
	})
	return result
}
