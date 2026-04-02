package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func marshalResult(id json.RawMessage, v interface{}) *JSONRPCResponse {
	result, err := json.Marshal(v)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0", ID: id,
			Error: &JSONRPCError{Code: -32603, Message: fmt.Sprintf("internal marshal error: %v", err)},
		}
	}
	return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// RunStdio reads JSON-RPC requests from stdin, dispatches them through the
// gateway, and writes responses to stdout. It runs until stdin is closed.
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
			if err := encoder.Encode(resp); err != nil {
				return fmt.Errorf("write response: %w", err)
			}
		}
	}
	return scanner.Err()
}

// handleRequest dispatches a single JSON-RPC request to the appropriate
// MCP handler and returns the response (or nil for notifications).
func (gw *Gateway) handleRequest(req JSONRPCRequest) *JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return marshalResult(req.ID, InitializeResult{
			ProtocolVersion: "2025-03-26",
			Capabilities:    Capabilities{Tools: &ToolsCapability{}},
			ServerInfo:      Info{Name: "sluice", Version: "0.1.0"},
		})

	case "notifications/initialized":
		return nil // notification, no response

	case "tools/list":
		return marshalResult(req.ID, ListToolsResult{Tools: gw.allTools})

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
		return marshalResult(req.ID, toolResult)

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &JSONRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}
