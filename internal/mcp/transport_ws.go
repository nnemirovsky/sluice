package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// WSUpstream connects to a remote MCP server via WebSocket using the
// "mcp" subprotocol. JSON-RPC messages are exchanged as text frames.
type WSUpstream struct {
	name    string
	url     string
	conn    *websocket.Conn
	mu      sync.Mutex
	nextID  atomic.Int64
	timeout time.Duration
	ctx     context.Context    // cancelled by Stop to unblock in-flight reads
	cancel  context.CancelFunc // cancels ctx
}

// NewWSUpstream creates a WSUpstream for the given WebSocket URL and timeout.
func NewWSUpstream(name, url string, timeoutSec int) *WSUpstream {
	timeout := defaultUpstreamTimeout
	if timeoutSec > 0 {
		timeout = time.Duration(timeoutSec) * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WSUpstream{
		name:    name,
		url:     url,
		timeout: timeout,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// connect dials the WebSocket server with the "mcp" subprotocol.
func (w *WSUpstream) connect() error {
	dialCtx, dialCancel := context.WithTimeout(w.ctx, w.timeout)
	defer dialCancel()

	conn, _, err := websocket.Dial(dialCtx, w.url, &websocket.DialOptions{
		Subprotocols: []string{"mcp"},
	})
	if err != nil {
		return fmt.Errorf("upstream %s: dial %s: %w", w.name, w.url, err)
	}
	conn.SetReadLimit(10 * 1024 * 1024)
	w.conn = conn
	return nil
}

// Send writes a JSON-RPC request as a WebSocket text frame and reads the
// matching response. Notifications and server-initiated requests are logged
// and skipped. The response id must match the request id. Returns an error
// if no matching response arrives within the timeout.
func (w *WSUpstream) Send(req JSONRPCRequest) (*JSONRPCResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn == nil {
		return nil, fmt.Errorf("upstream %s: not connected", w.name)
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
	defer cancel()

	if err := w.conn.Write(ctx, websocket.MessageText, data); err != nil {
		return nil, fmt.Errorf("upstream %s: write: %w", w.name, err)
	}

	// Notifications have no id; do not wait for a response.
	if req.ID == nil {
		return nil, nil
	}

	wantID := string(req.ID)

	for {
		_, msg, err := w.conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: read: %w", w.name, err)
		}

		var peek struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(msg, &peek); err != nil {
			return nil, fmt.Errorf("upstream %s: parse message: %w", w.name, err)
		}

		// Skip notifications (no id).
		if peek.ID == nil {
			log.Printf("upstream %s: skipping WS notification", w.name)
			continue
		}

		// Skip server-initiated requests (has id AND method).
		if peek.Method != "" {
			log.Printf("upstream %s: skipping WS server request %q (id=%s)", w.name, peek.Method, string(peek.ID))
			continue
		}

		// Verify the response id matches our request id.
		if string(peek.ID) != wantID {
			log.Printf("upstream %s: skipping WS response id=%s (want %s)", w.name, string(peek.ID), wantID)
			continue
		}

		var resp JSONRPCResponse
		if err := json.Unmarshal(msg, &resp); err != nil {
			return nil, fmt.Errorf("upstream %s: parse response: %w", w.name, err)
		}
		return &resp, nil
	}
}

// Initialize connects to the WebSocket server and performs the MCP
// initialize handshake.
func (w *WSUpstream) Initialize() error {
	if err := w.connect(); err != nil {
		return err
	}

	id := json.RawMessage(fmt.Sprintf(`%d`, w.nextID.Add(1)))
	params, _ := json.Marshal(InitializeParams{
		ProtocolVersion: "2025-03-26",
		Capabilities:    Capabilities{Tools: &ToolsCapability{}},
		ClientInfo:      Info{Name: "sluice", Version: "0.1.0"},
	})

	resp, err := w.Send(JSONRPCRequest{
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

	// Send initialized notification (no response expected).
	_, err = w.Send(JSONRPCRequest{JSONRPC: "2.0", Method: "notifications/initialized"})
	if err != nil {
		log.Printf("upstream %s: initialized notification: %v", w.name, err)
	}
	return nil
}

// DiscoverTools calls tools/list on the upstream and namespaces the results.
func (w *WSUpstream) DiscoverTools() ([]Tool, error) {
	id := json.RawMessage(fmt.Sprintf(`%d`, w.nextID.Add(1)))
	resp, err := w.Send(JSONRPCRequest{
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

	for i := range result.Tools {
		result.Tools[i].Name = w.name + "__" + result.Tools[i].Name
	}
	log.Printf("upstream %s: discovered %d tools via WebSocket", w.name, len(result.Tools))
	return result.Tools, nil
}

// CallTool invokes tools/call on the upstream server.
func (w *WSUpstream) CallTool(toolName string, arguments json.RawMessage) (*JSONRPCResponse, error) {
	id := json.RawMessage(fmt.Sprintf(`%d`, w.nextID.Add(1)))
	params, _ := json.Marshal(CallToolParams{Name: toolName, Arguments: arguments})

	return w.Send(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  params,
	})
}

// Reconnect closes the current connection and establishes a new one,
// performing the full MCP handshake again. Call this after a connection
// drop to re-establish communication with the upstream server.
func (w *WSUpstream) Reconnect() error {
	w.cancel()

	w.mu.Lock()
	if w.conn != nil {
		_ = w.conn.Close(websocket.StatusGoingAway, "reconnecting")
		w.conn = nil
	}
	// Reset context for the new connection.
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.mu.Unlock()

	return w.Initialize()
}

// Stop cancels in-flight operations and closes the WebSocket connection.
func (w *WSUpstream) Stop() error {
	// Cancel the context first to unblock any in-flight Send waiting on Read.
	w.cancel()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn == nil {
		return nil
	}
	err := w.conn.Close(websocket.StatusNormalClosure, "stopping")
	w.conn = nil
	return err
}
