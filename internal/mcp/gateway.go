package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

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
		policy:     cfg.ToolPolicy,
		inspector:  cfg.Inspector,
		audit:      cfg.Audit,
		broker:     cfg.Broker,
		timeoutSec: cfg.TimeoutSec,
	}
	if gw.timeoutSec == 0 {
		gw.timeoutSec = 120
	}

	for _, ucfg := range cfg.Upstreams {
		u, err := StartUpstream(ucfg)
		if err != nil {
			gw.Stop()
			return nil, fmt.Errorf("start upstream %s: %w", ucfg.Name, err)
		}
		if err := u.Initialize(); err != nil {
			gw.Stop()
			return nil, fmt.Errorf("initialize upstream %s: %w", ucfg.Name, err)
		}
		tools, err := u.DiscoverTools()
		if err != nil {
			gw.Stop()
			return nil, fmt.Errorf("discover tools %s: %w", ucfg.Name, err)
		}
		gw.upstreams[ucfg.Name] = u
		gw.allTools = append(gw.allTools, tools...)
		for _, t := range tools {
			gw.toolMap[t.Name] = ucfg.Name
		}
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

	if gw.audit != nil {
		gw.audit.Log(audit.Event{
			Tool:    req.Name,
			Action:  "tool_call",
			Verdict: verdict.String(),
		})
	}

	switch verdict {
	case policy.Deny:
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: "Tool call denied by policy"}},
			IsError: true,
		}, nil

	case policy.Ask:
		if gw.broker == nil {
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Tool call requires approval (no broker configured)"}},
				IsError: true,
			}, nil
		}
		argsStr := string(req.Arguments)
		if len(argsStr) > 200 {
			argsStr = argsStr[:200] + "..."
		}
		log.Printf("[MCP ASK] %s (args: %s)", req.Name, argsStr)
		timeout := time.Duration(gw.timeoutSec) * time.Second
		resp, err := gw.broker.Request(fmt.Sprintf("MCP:%s", req.Name), 0, timeout)
		if err != nil {
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Approval timeout"}},
				IsError: true,
			}, nil
		}
		if resp == tg.ResponseDeny {
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Denied by user"}},
				IsError: true,
			}, nil
		}
		// Approved: fall through to forward
	}

	// Inspect arguments before forwarding
	if gw.inspector != nil {
		inspection := gw.inspector.InspectArguments(req.Arguments)
		if inspection.Blocked {
			if gw.audit != nil {
				gw.audit.Log(audit.Event{
					Tool:    req.Name,
					Action:  "inspect_block",
					Verdict: "deny",
					Reason:  inspection.Reason,
				})
			}
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Tool call blocked: %s", inspection.Reason)}},
				IsError: true,
			}, nil
		}
	}

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
		"verdict": verdict.String(),
		"tool":    req.Name,
		"version": "0.1.0",
	}

	return &result, nil
}

// Stop terminates all upstream server processes.
func (gw *Gateway) Stop() {
	for name, u := range gw.upstreams {
		log.Printf("stopping upstream %s", name)
		u.Stop()
	}
}
