// Command mock_mcp_upstream is a minimal MCP upstream server for e2e testing.
// It speaks JSON-RPC 2.0 over stdin/stdout and exposes configurable tools.
//
// Usage: go run mock_mcp_upstream.go [--slow-ms N] [--name NAME]
//
// Supported tools:
//   - echo: returns its arguments as text
//   - secret: returns a response containing a secret pattern (for redaction tests)
//   - slow: sleeps for the configured duration before responding (for timeout tests)
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type toolResult struct {
	Content []toolContent          `json:"content"`
	Meta    map[string]interface{} `json:"_meta,omitempty"`
	IsError bool                   `json:"isError,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func main() {
	slowMS := flag.Int("slow-ms", 0, "milliseconds to sleep for the slow tool")
	name := flag.String("name", "mock", "server name reported in initialize")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	tools := []tool{
		{
			Name:        "echo",
			Description: "Echoes arguments back as text",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}}}`),
		},
		{
			Name:        "secret",
			Description: "Returns a response containing secret patterns",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		{
			Name:        "slow",
			Description: "Responds after a configurable delay",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
	}

	for scanner.Scan() {
		var req jsonrpcRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			resp := jsonrpcResponse{
				JSONRPC: "2.0",
				Error:   &jsonrpcError{Code: -32700, Message: fmt.Sprintf("parse error: %v", err)},
			}
			_ = encoder.Encode(resp)
			continue
		}

		// Skip notifications (no response expected).
		if req.ID == nil {
			continue
		}

		var resp jsonrpcResponse
		switch req.Method {
		case "initialize":
			result, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": *name, "version": "1.0.0"},
			})
			resp = jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

		case "tools/list":
			result, _ := json.Marshal(map[string]interface{}{"tools": tools})
			resp = jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

		case "tools/call":
			var params callToolParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				resp = jsonrpcResponse{
					JSONRPC: "2.0", ID: req.ID,
					Error: &jsonrpcError{Code: -32602, Message: "invalid params"},
				}
				break
			}

			var tr toolResult
			switch params.Name {
			case "echo":
				tr = toolResult{
					Content: []toolContent{{Type: "text", Text: string(params.Arguments)}},
				}
			case "secret":
				tr = toolResult{
					Content: []toolContent{{Type: "text", Text: "The API key is sk-secret1234567890 and password is hunter2"}},
				}
			case "slow":
				if *slowMS > 0 {
					time.Sleep(time.Duration(*slowMS) * time.Millisecond)
				}
				tr = toolResult{
					Content: []toolContent{{Type: "text", Text: "slow response completed"}},
				}
			default:
				tr = toolResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("unknown tool: %s", params.Name)}},
					IsError: true,
				}
			}
			result, _ := json.Marshal(tr)
			resp = jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

		default:
			resp = jsonrpcResponse{
				JSONRPC: "2.0", ID: req.ID,
				Error: &jsonrpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
			}
		}

		_ = encoder.Encode(resp)
	}
}
