package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

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

// protoDisplayName returns the human-readable display name for a protocol.
var protoDisplayName = map[string]string{
	"http":    "HTTP",
	"https":   "HTTPS",
	"ssh":     "SSH",
	"imap":    "IMAP",
	"smtp":    "SMTP",
	"ws":      "WebSocket",
	"wss":     "WebSocket (TLS)",
	"grpc":    "gRPC",
	"dns":     "DNS",
	"quic":    "QUIC",
	"apns":    "APNS",
	"tcp":     "TCP",
	"udp":     "UDP",
	"generic": "TCP",
}

// FormatApprovalMessage builds the Telegram message text for an approval
// request. MCP tool calls (protocol == "mcp") show the tool name and
// arguments. Per-request HTTP approvals (Method and Path set) show the
// method and full URL. Network connections show the protocol, destination,
// and port.
//
// The returned string uses Telegram HTML parse mode: the tool name is
// escaped plain text and arguments are rendered inside a <pre><code>
// block with pretty-printed JSON when the input parses, falling back
// to the raw string otherwise (truncated args may not be valid JSON).
// Callers must set ParseMode to HTML when sending the message.
func FormatApprovalMessage(req channel.ApprovalRequest) string {
	if req.Protocol == "mcp" {
		msg := "OpenClaw wants to call tool:\n\n" + htmlCode(req.Destination)
		if req.ToolArgs != "" {
			pretty := prettyJSONOrRaw(req.ToolArgs)
			msg += "\n\nArguments:\n<pre><code class=\"language-json\">" + htmlEscape(pretty) + "</code></pre>"
		}
		msg += "\n\nAllow this tool call?"
		return msg
	}
	display := protoDisplayName[req.Protocol]
	if display == "" {
		display = req.Protocol
	}
	destPort := fmt.Sprintf("%s:%d", req.Destination, req.Port)
	if req.Method != "" {
		ver := ""
		if req.HTTPVersion != "" {
			ver = " (" + htmlEscape(req.HTTPVersion) + ")"
		}
		return fmt.Sprintf(
			"OpenClaw wants to connect to:\n\n%s %s\n%s %s%s\n\nAllow this request?",
			htmlEscape(display), htmlCode(destPort),
			htmlEscape(req.Method), htmlCode(buildRequestURL(req)), ver,
		)
	}
	return fmt.Sprintf(
		"OpenClaw wants to connect to:\n\n%s %s\n\nAllow this connection?",
		htmlEscape(display), htmlCode(destPort),
	)
}

// schemeForApproval returns the URL scheme that best matches the approval
// protocol/port hint. Unknown protocols with port 443 are shown as https
// for convenience; everything else defaults to http.
func schemeForApproval(req channel.ApprovalRequest) string {
	switch req.Protocol {
	case "wss":
		return "wss"
	case "ws":
		return "ws"
	case "https", "grpc", "quic":
		return "https"
	case "http":
		return "http"
	}
	if req.Port == 443 {
		return "https"
	}
	return "http"
}

// isStandardPort returns true when port matches the default for scheme.
// Used so we omit the port from the rendered URL (e.g. example.com/foo
// instead of example.com:443/foo) for cleaner Telegram messages.
func isStandardPort(scheme string, port int) bool {
	if port == 0 {
		return true
	}
	return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
}

// buildRequestURL constructs a human-readable URL for a per-request
// approval by choosing the scheme from the protocol/port and joining host,
// port, and path. Standard ports (80/443) are omitted.
func buildRequestURL(req channel.ApprovalRequest) string {
	scheme := schemeForApproval(req)
	host := req.Destination
	if !isStandardPort(scheme, req.Port) {
		host = fmt.Sprintf("%s:%d", req.Destination, req.Port)
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// htmlEscape escapes the minimum set of characters required by Telegram
// HTML parse mode: & < >. See https://core.telegram.org/bots/api#html-style
func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// prettyJSONOrRaw attempts to re-indent the input as JSON with 2-space
// indent. If parsing fails (e.g. the caller truncated mid-object) the
// raw string is returned unchanged so the user still sees something.
func prettyJSONOrRaw(raw string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err != nil {
		return raw
	}
	return buf.String()
}
