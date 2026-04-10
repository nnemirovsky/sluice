package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
)

// GatewayConfig holds configuration for the MCP gateway.
type GatewayConfig struct {
	Upstreams          []UpstreamConfig
	ToolPolicy         *ToolPolicy
	Inspector          *ContentInspector
	Audit              *audit.FileLogger
	Broker             *channel.Broker
	TimeoutSec         int
	Store              *store.Store
	CredentialResolver CredentialResolver
}

// Gateway intercepts tool calls between an AI agent and upstream MCP servers,
// applying tool-level policy and optional Telegram approval.
type Gateway struct {
	mu           sync.RWMutex
	upstreams    map[string]MCPUpstream    // upstream name -> upstream
	upstreamCfgs map[string]UpstreamConfig // original configs (with vault: prefixes) for restart
	toolMap      map[string]string         // namespaced tool -> upstream name
	allTools     []Tool
	policy       *ToolPolicy
	inspector    *ContentInspector
	audit        *audit.FileLogger
	broker       *channel.Broker
	timeoutSec   int
	store        *store.Store
	credResolver CredentialResolver
}

// NewGateway starts all upstream servers, performs MCP handshakes, discovers
// tools, and returns a ready-to-use gateway.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	gw := &Gateway{
		upstreams:    make(map[string]MCPUpstream),
		upstreamCfgs: make(map[string]UpstreamConfig),
		toolMap:      make(map[string]string),
		allTools:     []Tool{},
		policy:       cfg.ToolPolicy,
		inspector:    cfg.Inspector,
		audit:        cfg.Audit,
		broker:       cfg.Broker,
		timeoutSec:   cfg.TimeoutSec,
		store:        cfg.Store,
		credResolver: cfg.CredentialResolver,
	}
	if gw.timeoutSec == 0 {
		gw.timeoutSec = 120
	}
	if gw.policy == nil {
		// nil rules cannot fail compilation, so error is always nil here.
		gw.policy, _ = NewToolPolicy(nil, policy.Allow)
	}

	for _, ucfg := range cfg.Upstreams {
		// Propagate the global timeout as a default for upstreams
		// that do not specify their own timeout_sec.
		if ucfg.TimeoutSec == 0 && gw.timeoutSec > 0 {
			ucfg.TimeoutSec = gw.timeoutSec
		}
		if err := ValidateUpstreamName(ucfg.Name); err != nil {
			gw.Stop()
			return nil, err
		}
		if _, exists := gw.upstreams[ucfg.Name]; exists {
			gw.Stop()
			return nil, fmt.Errorf("duplicate upstream name %q", ucfg.Name)
		}

		// Store the original config (with vault: prefixes intact) for restart.
		gw.upstreamCfgs[ucfg.Name] = ucfg

		// Resolve vault: prefixed env and header values before spawning.
		spawnCfg := ucfg
		if gw.credResolver != nil {
			resolvedEnv, err := resolveVaultEnv(ucfg.Env, gw.credResolver)
			if err != nil {
				gw.Stop()
				return nil, fmt.Errorf("upstream %s: %w", ucfg.Name, err)
			}
			spawnCfg.Env = resolvedEnv
			resolvedHeaders, err := resolveVaultHeaders(ucfg.Headers, gw.credResolver)
			if err != nil {
				gw.Stop()
				return nil, fmt.Errorf("upstream %s: %w", ucfg.Name, err)
			}
			spawnCfg.Headers = resolvedHeaders
		}

		u, err := StartUpstreamForTransport(spawnCfg)
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
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.allTools
}

// HandleToolCall evaluates policy, optionally requests approval, and forwards
// the call to the correct upstream server.
func (gw *Gateway) HandleToolCall(req CallToolParams) (*ToolResult, error) {
	verdict := gw.policy.Evaluate(req.Name)
	finalVerdict := verdict

	switch verdict { //nolint:exhaustive // only Deny needs special handling before approval
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
		resp, err := gw.broker.Request(req.Name, 0, "mcp", timeout, channel.WithToolArgs(argsStr))
		if err != nil {
			gw.logAudit(req.Name, "tool_call", policy.Deny)
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Approval timeout"}},
				IsError: true,
			}, nil
		}
		if resp == channel.ResponseDeny {
			gw.logAudit(req.Name, "tool_call", policy.Deny)
			return &ToolResult{
				Content: []ToolContent{{Type: "text", Text: "Denied by user"}},
				IsError: true,
			}, nil
		}
		if resp == channel.ResponseAlwaysAllow {
			if gw.store != nil {
				if _, storeErr := gw.store.AddRule("allow", store.RuleOpts{Tool: req.Name, Name: "user approved always", Source: "approval"}); storeErr != nil {
					log.Printf("[WARN] failed to persist tool allow rule for %s: %v", req.Name, storeErr)
				}
			}
			gw.policy.AddDynamicAllow(req.Name)
			log.Printf("[MCP ALWAYS ALLOW] %s", req.Name)
		}
		finalVerdict = policy.Allow
	}

	gw.logAudit(req.Name, "tool_call", finalVerdict)

	// Find upstream (read lock protects map access during RestartUpstream).
	gw.mu.RLock()
	upstreamName, ok := gw.toolMap[req.Name]
	var upstream MCPUpstream
	if ok {
		upstream = gw.upstreams[upstreamName]
	}
	gw.mu.RUnlock()
	if !ok {
		return &ToolResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", req.Name)}},
			IsError: true,
		}, nil
	}

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

// RestartUpstream stops a running upstream and restarts it with freshly
// resolved credentials. Call this after a vault credential rotation to
// pick up new values. The upstream's tools are re-discovered and the
// tool map is updated.
func (gw *Gateway) RestartUpstream(name string) error {
	gw.mu.RLock()
	u, ok := gw.upstreams[name]
	cfg, cfgOK := gw.upstreamCfgs[name]
	gw.mu.RUnlock()

	if !ok {
		return fmt.Errorf("upstream %q not found", name)
	}
	if !cfgOK {
		return fmt.Errorf("no stored config for upstream %q", name)
	}

	log.Printf("restarting upstream %s for credential rotation", name)
	_ = u.Stop()

	// Re-resolve vault: prefixed env and header values to pick up rotated credentials.
	spawnCfg := cfg
	if gw.credResolver != nil {
		resolvedEnv, err := resolveVaultEnv(cfg.Env, gw.credResolver)
		if err != nil {
			return fmt.Errorf("upstream %s: %w", name, err)
		}
		spawnCfg.Env = resolvedEnv
		resolvedHeaders, err := resolveVaultHeaders(cfg.Headers, gw.credResolver)
		if err != nil {
			return fmt.Errorf("upstream %s: %w", name, err)
		}
		spawnCfg.Headers = resolvedHeaders
	}

	newU, err := StartUpstreamForTransport(spawnCfg)
	if err != nil {
		return fmt.Errorf("restart upstream %s: %w", name, err)
	}
	if err := newU.Initialize(); err != nil {
		_ = newU.Stop()
		return fmt.Errorf("reinitialize upstream %s: %w", name, err)
	}

	tools, err := newU.DiscoverTools()
	if err != nil {
		_ = newU.Stop()
		return fmt.Errorf("rediscover tools %s: %w", name, err)
	}

	// Hold write lock while swapping maps and slices.
	gw.mu.Lock()
	oldTools := make(map[string]bool)
	for toolName, upName := range gw.toolMap {
		if upName == name {
			oldTools[toolName] = true
			delete(gw.toolMap, toolName)
		}
	}
	for _, t := range tools {
		gw.toolMap[t.Name] = name
	}
	filtered := make([]Tool, 0, len(gw.allTools))
	for _, t := range gw.allTools {
		if !oldTools[t.Name] {
			filtered = append(filtered, t)
		}
	}
	gw.allTools = append(filtered, tools...)
	gw.upstreams[name] = newU
	gw.mu.Unlock()

	log.Printf("upstream %s restarted, %d tools discovered", name, len(tools))
	return nil
}

// Stop terminates all upstream server processes.
func (gw *Gateway) Stop() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	for name, u := range gw.upstreams {
		log.Printf("stopping upstream %s", name)
		_ = u.Stop()
	}
}
