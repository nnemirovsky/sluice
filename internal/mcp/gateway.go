package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	tg "github.com/nemirovsky/sluice/internal/telegram"
)

// GatewayConfig holds configuration for the MCP gateway.
type GatewayConfig struct {
	Upstreams  []UpstreamConfig
	ToolPolicy *ToolPolicy
	Inspector  *ContentInspector
	Audit      *audit.FileLogger
	Broker     *tg.ApprovalBroker
	TimeoutSec int
}

// Gateway intercepts tool calls between an AI agent and upstream MCP servers,
// applying tool-level policy and optional Telegram approval.
type Gateway struct {
	upstreams  map[string]*Upstream // upstream name -> upstream
	toolMap    map[string]string    // namespaced tool -> upstream name
	allTools   []Tool
	policy     *ToolPolicy
	inspector  *ContentInspector
	audit      *audit.FileLogger
	broker     *tg.ApprovalBroker
	timeoutSec int
}

// NewGateway starts all upstream servers, performs MCP handshakes, discovers
// tools, and returns a ready-to-use gateway.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	gw := &Gateway{
		upstreams:  make(map[string]*Upstream),
		toolMap:    make(map[string]string),
		allTools:   []Tool{},
		policy:     cfg.ToolPolicy,
		inspector:  cfg.Inspector,
		audit:      cfg.Audit,
		broker:     cfg.Broker,
		timeoutSec: cfg.TimeoutSec,
	}
	if gw.timeoutSec == 0 {
		gw.timeoutSec = 120
	}
	if gw.policy == nil {
		gw.policy = NewToolPolicy(nil, policy.Allow)
	}

	for _, ucfg := range cfg.Upstreams {
		if _, exists := gw.upstreams[ucfg.Name]; exists {
			gw.Stop()
			return nil, fmt.Errorf("duplicate upstream name %q", ucfg.Name)
		}
		u, err := StartUpstream(ucfg)
		if err != nil {
			gw.Stop()
			return nil, fmt.Errorf("start upstream %s: %w", ucfg.Name, err)
		}
		// Register immediately so Stop() cleans it up on later errors.
		gw.upstreams[ucfg.Name] = u
		if err := u.Initialize(); err != nil {
			gw.Stop()
			return nil, fmt.Errorf("initialize upstream %s: %w", ucfg.Name, err)
		}
		tools, err := u.DiscoverTools()
		if err != nil {
			gw.Stop()
			return nil, fmt.Errorf("discover tools %s: %w", ucfg.Name, err)
		}
		for _, t := range tools {
			if _, exists := gw.toolMap[t.Name]; exists {
				gw.Stop()
				return nil, fmt.Errorf("duplicate tool name %q from upstream %s", t.Name, ucfg.Name)
			}
			gw.toolMap[t.Name] = ucfg.Name
		}
		gw.allTools = append(gw.allTools, tools...)
	}
	return gw, nil
}

// Tools returns all discovered tools from all upstreams (namespaced).
func (gw *Gateway) Tools() []Tool {
	return gw.allTools
}

// HandleToolCall evaluates policy, optionally requests approval, and forwards
// the call to the correct upstream server.
func (gw *Gateway) HandleToolCall(req CallToolParams) (*ToolResult, error) {
	verdict := gw.policy.Evaluate(req.Name)
	finalVerdict := verdict

	switch verdict {
	case policy.Deny:
		gw.logAudit(req.Name, "tool_call", finalVerdict)
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: "Tool call denied by policy"}},
			IsError: true,
		}, nil
	}

	// Inspect arguments before approval flow so that secrets in arguments
	// are never logged or sent to the approval broker.
	if gw.inspector != nil {
		inspection := gw.inspector.InspectArguments(req.Arguments)
		if inspection.Blocked {
			gw.logAudit(req.Name, "inspect_block", policy.Deny)
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Tool call blocked: %s", inspection.Reason)}},
				IsError: true,
			}, nil
		}
	}

	if verdict == policy.Ask {
		if gw.broker == nil {
			gw.logAudit(req.Name, "tool_call", policy.Deny)
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Tool call requires approval (no broker configured)"}},
				IsError: true,
			}, nil
		}
		argsStr := string(req.Arguments)
		if len(argsStr) > 200 {
			// Truncate without splitting multi-byte UTF-8 characters
			argsStr = argsStr[:200]
			for !utf8.ValidString(argsStr) {
				argsStr = argsStr[:len(argsStr)-1]
			}
			argsStr += "..."
		}
		log.Printf("[MCP ASK] %s (args: %s)", req.Name, argsStr)
		timeout := time.Duration(gw.timeoutSec) * time.Second
		resp, err := gw.broker.Request(fmt.Sprintf("MCP:%s", req.Name), 0, timeout)
		if err != nil {
			gw.logAudit(req.Name, "tool_call", policy.Deny)
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Approval timeout"}},
				IsError: true,
			}, nil
		}
		if resp == tg.ResponseDeny {
			gw.logAudit(req.Name, "tool_call", policy.Deny)
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Denied by user"}},
				IsError: true,
			}, nil
		}
		if resp == tg.ResponseAlwaysAllow {
			gw.policy.AddDynamicAllow(req.Name)
			log.Printf("[MCP ALWAYS ALLOW] %s", req.Name)
		}
		finalVerdict = policy.Allow
	}

	gw.logAudit(req.Name, "tool_call", finalVerdict)

	// Find upstream
	upstreamName, ok := gw.toolMap[req.Name]
	if !ok {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", req.Name)}},
			IsError: true,
		}, nil
	}
	upstream := gw.upstreams[upstreamName]

	// Strip namespace prefix for upstream call
	originalName := strings.TrimPrefix(req.Name, upstreamName+"__")

	// Forward to upstream
	resp, err := upstream.CallTool(originalName, req.Arguments)
	if err != nil {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Upstream error: %v", err)}},
			IsError: true,
		}, nil
	}
	if resp.Error != nil {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: resp.Error.Message}},
			IsError: true,
		}, nil
	}

	var result ToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tool result: %w", err)
	}

	// Redact sensitive content in response
	if gw.inspector != nil {
		for i, c := range result.Content {
			if c.Type == "text" && c.Text != "" {
				result.Content[i].Text = gw.inspector.RedactResponse(c.Text)
			}
		}
	}

	// Add governance metadata
	if result.Meta == nil {
		result.Meta = make(map[string]interface{})
	}
	result.Meta["governance"] = map[string]interface{}{
		"verdict": finalVerdict.String(),
		"tool":    req.Name,
		"version": "0.1.0",
	}

	return &result, nil
}

func (gw *Gateway) logAudit(tool, action string, verdict policy.Verdict) {
	if gw.audit != nil {
		if err := gw.audit.Log(audit.Event{
			Tool:    tool,
			Action:  action,
			Verdict: verdict.String(),
		}); err != nil {
			log.Printf("[MCP AUDIT ERROR] %v", err)
		}
	}
}

// Stop terminates all upstream server processes.
func (gw *Gateway) Stop() {
	for name, u := range gw.upstreams {
		log.Printf("stopping upstream %s", name)
		u.Stop()
	}
}
