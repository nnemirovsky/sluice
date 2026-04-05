package telegram

import (
	"fmt"
	"regexp"

	"github.com/nemirovsky/sluice/internal/channel"
)

// tokenPattern matches Telegram bot tokens embedded in URLs or error messages.
// Tokens follow the format <numeric-id>:<alphanumeric-string> and typically
// appear right after "bot" in API URLs (e.g. /bot123456:AAH.../sendMessage).
var tokenPattern = regexp.MustCompile(`[0-9]+:[A-Za-z0-9_-]{20,}`)

// sanitizeError removes bot tokens from error messages to prevent leaking
// secrets in logs. The telegram-bot-api library includes the full request URL
// (containing the bot token) in HTTP/network error strings.
func sanitizeError(err error) string {
	return tokenPattern.ReplaceAllString(err.Error(), "<REDACTED>")
}

// telegramMaxMessage is Telegram's maximum message length (4096 UTF-8 chars).
// We leave a small margin for the truncation notice.
const telegramMaxMessage = 4000

// FormatApprovalMessage builds the Telegram message text for an approval
// request. MCP tool calls (protocol == "mcp") show the tool name and
// arguments. Network connections show the protocol, destination, and port.
func FormatApprovalMessage(req channel.ApprovalRequest) string {
	if req.Protocol == "mcp" {
		msg := fmt.Sprintf("OpenClaw wants to call tool:\n\n%s", req.Destination)
		if req.ToolArgs != "" {
			msg += fmt.Sprintf("\n\nArguments:\n%s", req.ToolArgs)
		}
		msg += "\n\nAllow this tool call?"
		return msg
	}
	proto := req.Protocol
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("OpenClaw wants to connect to:\n\n%s://%s:%d\n\nAllow this connection?", proto, req.Destination, req.Port)
}
