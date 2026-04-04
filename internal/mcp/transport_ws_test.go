package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/coder/websocket"
)

// mockWSMCPServer returns an httptest.Server that behaves as a minimal
// WebSocket MCP server. It accepts the "mcp" subprotocol and handles
// initialize, tools/list, and tools/call.
func mockWSMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"mcp"},
		})
		if err != nil {
			t.Logf("accept: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		for {
			_, data, err := conn.Read(context.Background())
			if err != nil {
				return
			}

			var req JSONRPCRequest
			if err := json.Unmarshal(data, &req); err != nil {
				return
			}

			switch req.Method {
			case "initialize":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(InitializeResult{
						ProtocolVersion: "2025-03-26",
						Capabilities:    Capabilities{Tools: &ToolsCapability{}},
						ServerInfo:      Info{Name: "mock-ws", Version: "0.1.0"},
					}),
				})

			case "notifications/initialized":
				// No response.

			case "tools/list":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(ListToolsResult{
						Tools: []Tool{
							{Name: "subscribe", Description: "Subscribe to events"},
							{Name: "query", Description: "Query data"},
						},
					}),
				})

			case "tools/call":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(ToolResult{
						Content: []ToolContent{{Type: "text", Text: "result from WS upstream"}},
					}),
				})

			default:
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &JSONRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
				})
			}
		}
	}))
}

// mockWSMCPServerWithNotifications returns a server that sends a notification
// and a server-initiated request before the tools/call response.
func mockWSMCPServerWithNotifications(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"mcp"},
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		for {
			_, data, err := conn.Read(context.Background())
			if err != nil {
				return
			}

			var req JSONRPCRequest
			if err := json.Unmarshal(data, &req); err != nil {
				return
			}

			switch req.Method {
			case "initialize":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(InitializeResult{
						ProtocolVersion: "2025-03-26",
						Capabilities:    Capabilities{Tools: &ToolsCapability{}},
						ServerInfo:      Info{Name: "mock-ws-notif", Version: "0.1.0"},
					}),
				})

			case "notifications/initialized":
				// No response.

			case "tools/list":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(ListToolsResult{
						Tools: []Tool{{Name: "slow-op", Description: "A slow operation"}},
					}),
				})

			case "tools/call":
				// Send a notification before the result.
				notif, _ := json.Marshal(map[string]interface{}{
					"jsonrpc": "2.0",
					"method":  "notifications/progress",
					"params":  map[string]interface{}{"progress": 50, "total": 100},
				})
				conn.Write(context.Background(), websocket.MessageText, notif)

				// Send a server-initiated request (has both id and method).
				serverReq, _ := json.Marshal(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      999,
					"method":  "sampling/createMessage",
					"params":  map[string]interface{}{},
				})
				conn.Write(context.Background(), websocket.MessageText, serverReq)

				// Now send the actual response.
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(ToolResult{
						Content: []ToolContent{{Type: "text", Text: "result after notifications"}},
					}),
				})
			}
		}
	}))
}

// mockWSMCPServerWithDisconnect returns a server that closes the connection
// after responding to the first tools/call on the first connection.
// Subsequent connections work normally.
func mockWSMCPServerWithDisconnect(t *testing.T) *httptest.Server {
	t.Helper()
	var connCount atomic.Int32

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"mcp"},
		})
		if err != nil {
			return
		}
		connNum := connCount.Add(1)

		for {
			_, data, err := conn.Read(context.Background())
			if err != nil {
				return
			}

			var req JSONRPCRequest
			if err := json.Unmarshal(data, &req); err != nil {
				return
			}

			switch req.Method {
			case "initialize":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(InitializeResult{
						ProtocolVersion: "2025-03-26",
						Capabilities:    Capabilities{Tools: &ToolsCapability{}},
						ServerInfo:      Info{Name: "mock-ws-disconnect", Version: "0.1.0"},
					}),
				})

			case "notifications/initialized":
				// No response.

			case "tools/list":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(ListToolsResult{
						Tools: []Tool{{Name: "query", Description: "Query data"}},
					}),
				})

			case "tools/call":
				writeWSResponse(conn, JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  mustMarshal(ToolResult{
						Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("result-%d", connNum)}},
					}),
				})

				// Close the connection after the first tools/call on the
				// first connection to simulate a disconnect.
				if connNum == 1 {
					conn.Close(websocket.StatusGoingAway, "simulating disconnect")
					return
				}
			}
		}
	}))
}

func writeWSResponse(conn *websocket.Conn, resp JSONRPCResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(context.Background(), websocket.MessageText, data)
}

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

func TestWSUpstreamInitialize(t *testing.T) {
	srv := mockWSMCPServer(t)
	defer srv.Close()

	ws := NewWSUpstream("wsremote", srv.URL, 0)

	if err := ws.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if ws.conn == nil {
		t.Fatal("expected connection to be established")
	}

	ws.Stop()
}

func TestWSUpstreamDiscoverTools(t *testing.T) {
	srv := mockWSMCPServer(t)
	defer srv.Close()

	ws := NewWSUpstream("wsremote", srv.URL, 0)

	if err := ws.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	tools, err := ws.DiscoverTools()
	if err != nil {
		t.Fatalf("DiscoverTools: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	if tools[0].Name != "wsremote__subscribe" {
		t.Errorf("expected wsremote__subscribe, got %q", tools[0].Name)
	}
	if tools[1].Name != "wsremote__query" {
		t.Errorf("expected wsremote__query, got %q", tools[1].Name)
	}
	if tools[0].Description != "Subscribe to events" {
		t.Errorf("expected description 'Subscribe to events', got %q", tools[0].Description)
	}

	ws.Stop()
}

func TestWSUpstreamCallTool(t *testing.T) {
	srv := mockWSMCPServer(t)
	defer srv.Close()

	ws := NewWSUpstream("wsremote", srv.URL, 0)

	if err := ws.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"topic": "test"})
	resp, err := ws.CallTool("subscribe", json.RawMessage(args))
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
	if len(result.Content) != 1 || result.Content[0].Text != "result from WS upstream" {
		t.Errorf("unexpected result: %+v", result)
	}

	ws.Stop()
}

func TestWSUpstreamNotificationsSkipped(t *testing.T) {
	srv := mockWSMCPServerWithNotifications(t)
	defer srv.Close()

	ws := NewWSUpstream("wsnotif", srv.URL, 0)

	if err := ws.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	args, _ := json.Marshal(map[string]string{})
	resp, err := ws.CallTool("slow-op", json.RawMessage(args))
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
	// Should get the actual result, not the notification or server request.
	if result.Content[0].Text != "result after notifications" {
		t.Errorf("expected 'result after notifications', got %q", result.Content[0].Text)
	}

	ws.Stop()
}

func TestWSUpstreamReconnection(t *testing.T) {
	srv := mockWSMCPServerWithDisconnect(t)
	defer srv.Close()

	ws := NewWSUpstream("reconnect", srv.URL, 5)

	// First connection.
	if err := ws.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// First call succeeds.
	args, _ := json.Marshal(map[string]string{})
	resp, err := ws.CallTool("query", json.RawMessage(args))
	if err != nil {
		t.Fatalf("first CallTool: %v", err)
	}
	var result1 ToolResult
	if err := json.Unmarshal(resp.Result, &result1); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result1.Content[0].Text != "result-1" {
		t.Errorf("expected result-1, got %q", result1.Content[0].Text)
	}

	// Server closed connection after first tools/call; next call should fail.
	_, err = ws.CallTool("query", json.RawMessage(args))
	if err == nil {
		t.Fatal("expected error after server disconnect")
	}

	// Reconnect should re-establish the connection.
	if err := ws.Reconnect(); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}

	// Call succeeds on the new connection.
	resp, err = ws.CallTool("query", json.RawMessage(args))
	if err != nil {
		t.Fatalf("CallTool after reconnect: %v", err)
	}
	var result2 ToolResult
	if err := json.Unmarshal(resp.Result, &result2); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result2.Content[0].Text != "result-2" {
		t.Errorf("expected result-2, got %q", result2.Content[0].Text)
	}

	ws.Stop()
}

func TestWSUpstreamStop(t *testing.T) {
	srv := mockWSMCPServer(t)
	defer srv.Close()

	ws := NewWSUpstream("wsremote", srv.URL, 0)

	if err := ws.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if err := ws.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After stop, conn should be nil.
	if ws.conn != nil {
		t.Error("expected conn to be nil after Stop")
	}
}

func TestWSUpstreamStopWithoutConnection(t *testing.T) {
	ws := NewWSUpstream("wsremote", "ws://localhost:1", 0)

	// Stop without Initialize should be a no-op.
	if err := ws.Stop(); err != nil {
		t.Fatalf("Stop without connection: %v", err)
	}
}

func TestWSUpstreamConnectionRefused(t *testing.T) {
	ws := NewWSUpstream("dead", "ws://127.0.0.1:1", 5)

	err := ws.Initialize()
	if err == nil {
		t.Fatal("expected error connecting to dead server")
	}
}

func TestWSUpstreamCustomTimeout(t *testing.T) {
	ws := NewWSUpstream("wsremote", "ws://localhost:9999", 30)

	if ws.timeout != 30*1e9 {
		t.Errorf("expected timeout 30s, got %v", ws.timeout)
	}
}

func TestWSUpstreamDefaultTimeout(t *testing.T) {
	ws := NewWSUpstream("wsremote", "ws://localhost:9999", 0)

	if ws.timeout != defaultUpstreamTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultUpstreamTimeout, ws.timeout)
	}
}

func TestWSUpstreamSendWithoutConnection(t *testing.T) {
	ws := NewWSUpstream("wsremote", "ws://localhost:9999", 0)

	_, err := ws.Send(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "test",
	})
	if err == nil {
		t.Fatal("expected error when sending without connection")
	}
}
