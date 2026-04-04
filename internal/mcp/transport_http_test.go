package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// mockHTTPMCPServer returns an httptest.Server that behaves as a minimal
// Streamable HTTP MCP server. It generates a session ID on initialize and
// requires it on subsequent requests.
func mockHTTPMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		mu        sync.Mutex
		sessionID string
	)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.Method == http.MethodDelete {
			sid := r.Header.Get("Mcp-Session-Id")
			if sid == "" || sid != sessionID {
				http.Error(w, "invalid session", http.StatusBadRequest)
				return
			}
			sessionID = ""
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Check session ID for non-initialize requests.
		if req.Method != "initialize" && req.Method != "notifications/initialized" {
			sid := r.Header.Get("Mcp-Session-Id")
			if sid == "" || sid != sessionID {
				http.Error(w, "missing or invalid session", http.StatusUnauthorized)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			sessionID = "test-session-42"
			w.Header().Set("Mcp-Session-Id", sessionID)
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
			}
			result, _ := json.Marshal(InitializeResult{
				ProtocolVersion: "2025-03-26",
				Capabilities:    Capabilities{Tools: &ToolsCapability{}},
				ServerInfo:      Info{Name: "mock-http", Version: "0.1.0"},
			})
			resp.Result = result
			json.NewEncoder(w).Encode(resp)

		case "notifications/initialized":
			// Notification. Return empty 200.
			w.WriteHeader(http.StatusOK)

		case "tools/list":
			w.Header().Set("Mcp-Session-Id", sessionID)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			result, _ := json.Marshal(ListToolsResult{
				Tools: []Tool{
					{Name: "search", Description: "Search the web"},
					{Name: "fetch", Description: "Fetch a URL"},
				},
			})
			resp.Result = result
			json.NewEncoder(w).Encode(resp)

		case "tools/call":
			w.Header().Set("Mcp-Session-Id", sessionID)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			result, _ := json.Marshal(ToolResult{
				Content: []ToolContent{{Type: "text", Text: "result from HTTP upstream"}},
			})
			resp.Result = result
			json.NewEncoder(w).Encode(resp)

		default:
			resp := JSONRPCResponse{
				JSONRPC: "2.0", ID: req.ID,
				Error: &JSONRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
}

func TestHTTPUpstreamInitialize(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 0)

	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if h.sessionID != "test-session-42" {
		t.Errorf("expected session ID 'test-session-42', got %q", h.sessionID)
	}
}

func TestHTTPUpstreamDiscoverTools(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 0)

	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	tools, err := h.DiscoverTools()
	if err != nil {
		t.Fatalf("DiscoverTools: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	if tools[0].Name != "remote__search" {
		t.Errorf("expected remote__search, got %q", tools[0].Name)
	}
	if tools[1].Name != "remote__fetch" {
		t.Errorf("expected remote__fetch, got %q", tools[1].Name)
	}
	if tools[0].Description != "Search the web" {
		t.Errorf("expected description 'Search the web', got %q", tools[0].Description)
	}
}

func TestHTTPUpstreamCallTool(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 0)

	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"query": "test"})
	resp, err := h.CallTool("search", json.RawMessage(args))
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
	if len(result.Content) != 1 || result.Content[0].Text != "result from HTTP upstream" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestHTTPUpstreamSessionIDRequired(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	// Skip Initialize so no session ID is set.
	h := NewHTTPUpstream("remote", srv.URL, 0)

	_, err := h.DiscoverTools()
	if err == nil {
		t.Fatal("expected error when calling DiscoverTools without session")
	}
}

func TestHTTPUpstreamSessionIDPersists(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 0)

	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	firstSID := h.sessionID

	// Second call should reuse the same session.
	_, err := h.DiscoverTools()
	if err != nil {
		t.Fatalf("DiscoverTools: %v", err)
	}
	if h.sessionID != firstSID {
		t.Errorf("session ID changed: %q -> %q", firstSID, h.sessionID)
	}
}

func TestHTTPUpstreamStop(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 0)

	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := h.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestHTTPUpstreamStopWithoutSession(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 0)

	// Stop without Initialize should be a no-op.
	if err := h.Stop(); err != nil {
		t.Fatalf("Stop without session: %v", err)
	}
}

func TestHTTPUpstreamCustomTimeout(t *testing.T) {
	srv := mockHTTPMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("remote", srv.URL, 30)

	if h.timeout != 30*1e9 {
		t.Errorf("expected timeout 30s, got %v", h.timeout)
	}
	if h.client.Timeout != 30*1e9 {
		t.Errorf("expected client timeout 30s, got %v", h.client.Timeout)
	}
}

func TestHTTPUpstreamDefaultTimeout(t *testing.T) {
	h := NewHTTPUpstream("remote", "http://localhost:9999", 0)

	if h.timeout != defaultUpstreamTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultUpstreamTimeout, h.timeout)
	}
}

// mockSSEMCPServer returns an httptest.Server that responds with SSE
// for tools/call requests and plain JSON for everything else.
func mockSSEMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "sse-session-1")
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			result, _ := json.Marshal(InitializeResult{
				ProtocolVersion: "2025-03-26",
				Capabilities:    Capabilities{Tools: &ToolsCapability{}},
				ServerInfo:      Info{Name: "mock-sse", Version: "0.1.0"},
			})
			resp.Result = result
			json.NewEncoder(w).Encode(resp)

		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)

		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			result, _ := json.Marshal(ListToolsResult{
				Tools: []Tool{{Name: "slow-op", Description: "A slow operation"}},
			})
			resp.Result = result
			json.NewEncoder(w).Encode(resp)

		case "tools/call":
			// Respond with SSE stream containing progress notifications
			// followed by the final result.
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming not supported", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			// Send a progress notification (no id).
			notif, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "notifications/progress",
				"params":  map[string]interface{}{"progress": 50, "total": 100},
			})
			fmt.Fprintf(w, "data: %s\n\n", notif)
			flusher.Flush()

			// Send the final result matching the request ID.
			result, _ := json.Marshal(ToolResult{
				Content: []ToolContent{{Type: "text", Text: "streamed result"}},
			})
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
			resp.Result = result
			respJSON, _ := json.Marshal(resp)
			fmt.Fprintf(w, "data: %s\n\n", respJSON)
			flusher.Flush()
		}
	}))
}

func TestHTTPUpstreamSSEResponse(t *testing.T) {
	srv := mockSSEMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("sse-remote", srv.URL, 0)

	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	tools, err := h.DiscoverTools()
	if err != nil {
		t.Fatalf("DiscoverTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "sse-remote__slow-op" {
		t.Fatalf("unexpected tools: %+v", tools)
	}

	args, _ := json.Marshal(map[string]string{})
	resp, err := h.CallTool("slow-op", json.RawMessage(args))
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
	if len(result.Content) != 1 || result.Content[0].Text != "streamed result" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestHTTPUpstreamSSESkipsNotifications(t *testing.T) {
	// The SSE mock sends a notification before the result.
	// Verify HTTPUpstream correctly skips it and returns the final result.
	srv := mockSSEMCPServer(t)
	defer srv.Close()

	h := NewHTTPUpstream("sse-remote", srv.URL, 0)
	if err := h.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	args, _ := json.Marshal(map[string]string{})
	resp, err := h.CallTool("slow-op", json.RawMessage(args))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	// Should have the streamed result, not the notification.
	if result.Content[0].Text != "streamed result" {
		t.Errorf("expected 'streamed result', got %q", result.Content[0].Text)
	}
}

func TestHTTPUpstreamConnectionRefused(t *testing.T) {
	h := NewHTTPUpstream("dead", "http://127.0.0.1:1", 5)

	err := h.Initialize()
	if err == nil {
		t.Fatal("expected error connecting to dead server")
	}
}

func TestHTTPUpstreamServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := NewHTTPUpstream("error-srv", srv.URL, 0)
	err := h.Initialize()
	if err == nil {
		t.Fatal("expected error from 500 response")
	}
}
