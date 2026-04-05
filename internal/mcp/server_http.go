package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MCPHTTPHandler serves the MCP protocol over Streamable HTTP.
// It handles POST for JSON-RPC requests and DELETE for session cleanup.
// Sessions are tracked via the Mcp-Session-Id header.
type MCPHTTPHandler struct { //nolint:revive // stuttering accepted for clarity
	gw        *Gateway
	sessions  sync.Map   // session ID -> *mcpSession
	sessionMu sync.Mutex // serializes newSession to enforce cap atomically
}

type mcpSession struct {
	id             string
	createdAt      time.Time
	lastAccessedAt atomic.Int64 // UnixNano; atomic for concurrent read/write safety
}

// NewMCPHTTPHandler creates an HTTP handler that serves the MCP protocol
// over Streamable HTTP, backed by the given Gateway.
func NewMCPHTTPHandler(gw *Gateway) *MCPHTTPHandler {
	return &MCPHTTPHandler{gw: gw}
}

// ServeHTTP dispatches POST and DELETE requests for the MCP Streamable
// HTTP protocol.
func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *MCPHTTPHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	var req JSONRPCRequest
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024) // 10 MB
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCError{Code: -32700, Message: fmt.Sprintf("parse error: %v", err)},
		})
		return
	}

	sessionID := r.Header.Get("Mcp-Session-Id")

	if req.Method == "initialize" {
		sess := h.newSession()
		w.Header().Set("Mcp-Session-Id", sess.id)
	} else if req.Method == "notifications/initialized" { //nolint:revive // notifications do not require a session
	} else if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	} else {
		v, ok := h.sessions.Load(sessionID)
		if !ok {
			http.Error(w, "Invalid or expired session", http.StatusNotFound)
			return
		}
		v.(*mcpSession).lastAccessedAt.Store(time.Now().UnixNano())
		w.Header().Set("Mcp-Session-Id", sessionID)
	}

	resp := h.gw.handleRequest(req)

	// Notifications return nil response per JSON-RPC 2.0.
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Use SSE for tool calls when the client accepts it.
	acceptSSE := strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	if req.Method == "tools/call" && acceptSSE {
		h.writeSSE(w, resp)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// writeSSE sends a JSON-RPC response as a single Server-Sent Event.
func (h *MCPHTTPHandler) writeSSE(w http.ResponseWriter, resp *JSONRPCResponse) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	data, _ := json.Marshal(resp)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

func (h *MCPHTTPHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	if _, loaded := h.sessions.LoadAndDelete(sessionID); !loaded {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SessionCount returns the number of active sessions. Intended for tests.
func (h *MCPHTTPHandler) SessionCount() int {
	count := 0
	h.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// maxSessions is the upper bound on concurrent sessions to prevent unbounded
// memory growth from repeated initialize requests without cleanup.
const maxSessions = 1000

func (h *MCPHTTPHandler) newSession() *mcpSession {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	// Enforce session cap.
	if h.SessionCount() >= maxSessions {
		h.pruneOldestSession()
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	now := time.Now()
	sess := &mcpSession{id: id, createdAt: now}
	sess.lastAccessedAt.Store(now.UnixNano())
	h.sessions.Store(id, sess)
	return sess
}

// pruneOldestSession removes the session with the earliest lastAccessedAt
// time so that active sessions survive while idle ones are evicted.
func (h *MCPHTTPHandler) pruneOldestSession() {
	var oldestID string
	var oldestNano int64
	h.sessions.Range(func(key, value interface{}) bool {
		sess := value.(*mcpSession)
		accessedAt := sess.lastAccessedAt.Load()
		if oldestID == "" || accessedAt < oldestNano {
			oldestID = key.(string)
			oldestNano = accessedAt
		}
		return true
	})
	if oldestID != "" {
		h.sessions.Delete(oldestID)
	}
}
