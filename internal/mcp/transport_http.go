package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPUpstream connects to a remote MCP server via Streamable HTTP.
// It POSTs JSON-RPC requests to a single endpoint and tracks the session
// via the Mcp-Session-Id response header.
type HTTPUpstream struct {
	name      string
	url       string
	client    *http.Client
	sessionID string
	mu        sync.Mutex
	tools     []Tool
	nextID    atomic.Int64
	timeout   time.Duration
}

// NewHTTPUpstream creates an HTTPUpstream for the given URL and timeout.
func NewHTTPUpstream(name, url string, timeoutSec int) *HTTPUpstream {
	timeout := defaultUpstreamTimeout
	if timeoutSec > 0 {
		timeout = time.Duration(timeoutSec) * time.Second
	}
	return &HTTPUpstream{
		name:    name,
		url:     url,
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

// Send posts a JSON-RPC request to the upstream HTTP endpoint and returns
// the response. It attaches the Mcp-Session-Id header if a session has
// been established.
func (h *HTTPUpstream) Send(req JSONRPCRequest) (*JSONRPCResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if h.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", h.sessionID)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: POST %s: %w", h.name, h.url, err)
	}
	defer resp.Body.Close()

	// Store session ID from response.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.sessionID = sid
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("upstream %s: HTTP %d: %s", h.name, resp.StatusCode, string(respBody))
	}

	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		return h.readSSEResponse(resp.Body, req.ID)
	}

	var rpcResp JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("upstream %s: decode response: %w", h.name, err)
	}
	return &rpcResp, nil
}

// readSSEResponse reads a Server-Sent Events stream and extracts the
// JSON-RPC response matching the given request ID. Notifications and
// progress events are logged and skipped.
func (h *HTTPUpstream) readSSEResponse(r io.Reader, reqID json.RawMessage) (*JSONRPCResponse, error) {
	wantID := string(reqID)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line signals the end of an SSE event.
		if line == "" {
			if len(dataLines) > 0 {
				data := strings.Join(dataLines, "\n")
				dataLines = nil

				resp, done, err := h.processSSEData(data, wantID)
				if err != nil {
					return nil, err
				}
				if done {
					return resp, nil
				}
			}
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
		// Ignore event:, id:, retry:, and comment lines.
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("upstream %s: SSE read error: %w", h.name, err)
	}

	// Stream ended without a matching response. If we have buffered data
	// lines (no trailing blank line), try to process them.
	if len(dataLines) > 0 {
		data := strings.Join(dataLines, "\n")
		resp, done, err := h.processSSEData(data, wantID)
		if err != nil {
			return nil, err
		}
		if done {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("upstream %s: SSE stream ended without response for id %s", h.name, wantID)
}

// processSSEData parses a single SSE data payload as JSON-RPC and checks
// if it matches the expected request ID. Returns (response, true, nil) if
// matched, (nil, false, nil) if skipped, or (nil, false, err) on error.
func (h *HTTPUpstream) processSSEData(data, wantID string) (*JSONRPCResponse, bool, error) {
	var peek struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal([]byte(data), &peek); err != nil {
		return nil, false, fmt.Errorf("upstream %s: parse SSE data: %w", h.name, err)
	}

	// Skip notifications (no id).
	if peek.ID == nil {
		log.Printf("upstream %s: skipping SSE notification", h.name)
		return nil, false, nil
	}

	// Skip server-initiated requests (has id AND method).
	if peek.Method != "" {
		log.Printf("upstream %s: skipping SSE server request %q", h.name, peek.Method)
		return nil, false, nil
	}

	// Check if this response matches our request ID.
	if string(peek.ID) != wantID {
		log.Printf("upstream %s: skipping SSE response id=%s (want %s)", h.name, string(peek.ID), wantID)
		return nil, false, nil
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(data), &resp); err != nil {
		return nil, false, fmt.Errorf("upstream %s: parse SSE response: %w", h.name, err)
	}
	return &resp, true, nil
}

// Initialize performs the MCP initialize handshake with the remote server.
func (h *HTTPUpstream) Initialize() error {
	id := json.RawMessage(fmt.Sprintf(`%d`, h.nextID.Add(1)))
	params, _ := json.Marshal(InitializeParams{
		ProtocolVersion: "2025-03-26",
		Capabilities:    Capabilities{Tools: &ToolsCapability{}},
		ClientInfo:      Info{Name: "sluice", Version: "0.1.0"},
	})

	resp, err := h.Send(JSONRPCRequest{
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
	_, err = h.Send(JSONRPCRequest{JSONRPC: "2.0", Method: "notifications/initialized"})
	// Notifications may return nil response with no error, or the server
	// may return 202 Accepted. Either way, only propagate actual errors.
	if err != nil {
		// Some servers return non-200 for notifications. Log but do not fail.
		log.Printf("upstream %s: initialized notification: %v", h.name, err)
	}
	return nil
}

// DiscoverTools calls tools/list on the upstream and namespaces the results.
func (h *HTTPUpstream) DiscoverTools() ([]Tool, error) {
	id := json.RawMessage(fmt.Sprintf(`%d`, h.nextID.Add(1)))
	resp, err := h.Send(JSONRPCRequest{
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
		result.Tools[i].Name = h.name + "__" + result.Tools[i].Name
	}
	h.tools = result.Tools

	log.Printf("upstream %s: discovered %d tools via HTTP", h.name, len(result.Tools))
	return result.Tools, nil
}

// CallTool invokes tools/call on the upstream server.
func (h *HTTPUpstream) CallTool(toolName string, arguments json.RawMessage) (*JSONRPCResponse, error) {
	id := json.RawMessage(fmt.Sprintf(`%d`, h.nextID.Add(1)))
	params, _ := json.Marshal(CallToolParams{Name: toolName, Arguments: arguments})

	return h.Send(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  params,
	})
}

// Stop sends a DELETE request to close the MCP session.
func (h *HTTPUpstream) Stop() error {
	h.mu.Lock()
	sid := h.sessionID
	h.mu.Unlock()

	if sid == "" {
		return nil
	}

	req, err := http.NewRequest(http.MethodDelete, h.url, nil)
	if err != nil {
		return fmt.Errorf("upstream %s: create DELETE request: %w", h.name, err)
	}
	req.Header.Set("Mcp-Session-Id", sid)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("upstream %s: DELETE session: %w", h.name, err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("upstream %s: DELETE returned %d", h.name, resp.StatusCode)
	}
	return nil
}
