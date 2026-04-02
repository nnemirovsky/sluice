// Package mcp implements a Model Context Protocol gateway with tool-level
// policy enforcement. It sits between an AI agent and upstream MCP servers,
// providing argument inspection, response redaction, and Telegram approval.
package mcp

import "encoding/json"

// JSONRPCRequest represents a JSON-RPC 2.0 request message.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response message.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents an error object in a JSON-RPC 2.0 response.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// InitializeParams holds the parameters sent by a client during the MCP
// initialize handshake.
type InitializeParams struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ClientInfo      Info         `json:"clientInfo"`
}

// InitializeResult holds the response from an MCP server during the
// initialize handshake.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      Info         `json:"serverInfo"`
}

// Capabilities describes the optional features supported by an MCP
// client or server.
type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability indicates that tools are supported. Its presence in
// Capabilities enables tool listing and invocation.
type ToolsCapability struct{}

// Info identifies an MCP client or server by name and version.
type Info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool describes a single tool exposed by an upstream MCP server.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ListToolsResult holds the response to a tools/list request.
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams holds the parameters for a tools/call request.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolResult holds the response from a tools/call invocation.
type ToolResult struct {
	Content []ToolContent          `json:"content"`
	Meta    map[string]interface{} `json:"_meta,omitempty"`
	IsError bool                   `json:"isError,omitempty"`
}

// ToolContent represents a single content block within a ToolResult.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
