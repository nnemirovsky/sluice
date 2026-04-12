// Package channel defines the Channel interface and Broker for coordinating
// approval requests across multiple notification channels (Telegram, HTTP
// webhooks, etc.). The Broker broadcasts approval requests to all enabled
// channels and resolves on the first response.
package channel

import (
	"context"
	"time"
)

// ChannelType enumerates supported notification/approval channels.
type ChannelType int //nolint:revive // stuttering accepted for clarity

const (
	// ChannelTelegram is a Telegram bot channel.
	ChannelTelegram ChannelType = 0
	// ChannelHTTP is an HTTP webhook channel.
	ChannelHTTP ChannelType = 1
)

func (ct ChannelType) String() string {
	switch ct {
	case ChannelTelegram:
		return "telegram"
	case ChannelHTTP:
		return "http"
	default:
		return "unknown"
	}
}

// Response represents a human operator's decision on an approval request.
type Response int

const (
	// ResponseAllowOnce permits the connection for this request only.
	ResponseAllowOnce Response = iota
	// ResponseAlwaysAllow permits the connection and adds a dynamic allow rule.
	ResponseAlwaysAllow
	// ResponseDeny rejects the connection request.
	ResponseDeny
	// ResponseAlwaysDeny rejects the connection and adds a persistent deny rule.
	ResponseAlwaysDeny
)

func (r Response) String() string {
	switch r {
	case ResponseAllowOnce:
		return "allow_once"
	case ResponseAlwaysAllow:
		return "always_allow"
	case ResponseDeny:
		return "deny"
	case ResponseAlwaysDeny:
		return "always_deny"
	default:
		return "unknown"
	}
}

// ApprovalRequest represents a pending connection that requires human approval.
type ApprovalRequest struct {
	ID          string
	Destination string
	Port        int
	Protocol    string // detected protocol (e.g. "https", "ssh", "mcp")
	ToolArgs    string // truncated tool arguments (MCP only)
	// Method is the HTTP method for per-request approvals (e.g. "GET", "POST").
	// Empty for connection-level approvals and non-HTTP protocols.
	Method string
	// Path is the request URL path for per-request approvals (e.g. "/users/me").
	// Empty for connection-level approvals and non-HTTP protocols.
	Path string
	// HTTPVersion is the negotiated HTTP version (e.g. "HTTP/1.1", "HTTP/2").
	// Empty for non-HTTP protocols.
	HTTPVersion string
	CreatedAt   time.Time
}

// Command represents an admin command received from a channel (e.g. Telegram
// /policy, /cred commands).
type Command struct {
	// Name is the command name without the leading slash (e.g. "policy").
	Name string
	// Args is the raw argument string after the command name.
	Args string
	// ChannelType identifies which channel sent this command.
	ChannelType ChannelType
	// Reply sends a text response back to the channel that sent this command.
	Reply func(ctx context.Context, text string) error
}

// Channel is a single notification/approval endpoint (Telegram bot, HTTP
// webhook, etc.). Channels handle delivery only. The Broker coordinates
// across multiple channels.
type Channel interface {
	// RequestApproval delivers an approval prompt to this channel (non-blocking).
	// The channel should present the request to the operator and call
	// Broker.Resolve when a response is received.
	RequestApproval(ctx context.Context, req ApprovalRequest) error
	// CancelApproval cleans up a resolved/timed-out approval on this channel
	// (e.g. edit Telegram message, POST cancellation webhook).
	CancelApproval(id string) error
	// Commands returns incoming admin commands from this channel (nil if
	// unsupported).
	Commands() <-chan Command
	// Notify sends a one-way message (fire and forget).
	Notify(ctx context.Context, msg string) error
	Start() error
	Stop()
	Type() ChannelType
}
