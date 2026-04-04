package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// Server implements the generated ServerInterface for the sluice REST API.
type Server struct {
	Unimplemented
	store     *store.Store
	broker    *channel.Broker
	proxySrv  *proxy.Server
	vault     *vault.Store
	auditPath string
	enginePtr *atomic.Pointer[policy.Engine]
	reloadMu  *sync.Mutex
}

// NewServer creates a new API server. enginePtr and reloadMu are optional
// and only needed when rule/config mutations should trigger engine recompilation.
func NewServer(st *store.Store, broker *channel.Broker, proxySrv *proxy.Server, auditPath string) *Server {
	return &Server{
		store:     st,
		broker:    broker,
		proxySrv:  proxySrv,
		auditPath: auditPath,
	}
}

// SetVault sets the vault store for credential management handlers.
func (s *Server) SetVault(v *vault.Store) {
	s.vault = v
}

// SetEnginePtr sets the shared engine pointer and reload mutex for rule
// mutation handlers. This is called after construction when the proxy
// server is available.
func (s *Server) SetEnginePtr(ptr *atomic.Pointer[policy.Engine], mu *sync.Mutex) {
	s.enginePtr = ptr
	s.reloadMu = mu
}

// recompileEngine rebuilds the policy engine from the store and atomically
// swaps it. Returns an error if recompilation fails.
func (s *Server) recompileEngine() error {
	if s.enginePtr == nil {
		return nil
	}
	newEng, err := policy.LoadFromStore(s.store)
	if err != nil {
		return err
	}
	if err := newEng.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	s.enginePtr.Store(newEng)
	return nil
}

// GetHealthz returns 200 when the proxy is listening.
func (s *Server) GetHealthz(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if s.proxySrv == nil || !s.proxySrv.IsListening() {
		status = "not ready"
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: status})
}

// GetApiApprovals returns pending approval requests from the broker.
func (s *Server) GetApiApprovals(w http.ResponseWriter, r *http.Request) {
	var approvals []ApprovalRequest
	if s.broker != nil {
		pending := s.broker.PendingRequests()
		approvals = make([]ApprovalRequest, len(pending))
		for i, p := range pending {
			approvals[i] = ApprovalRequest{
				Id:          p.ID,
				Destination: p.Destination,
				Port:        p.Port,
				CreatedAt:   p.CreatedAt,
			}
		}
	}
	if approvals == nil {
		approvals = []ApprovalRequest{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(approvals)
}

// PostApiApprovalsIdResolve resolves a pending approval request.
func (s *Server) PostApiApprovalsIdResolve(w http.ResponseWriter, r *http.Request, id string) {
	var req ResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if !req.Verdict.Valid() {
		writeError(w, http.StatusBadRequest, "invalid verdict", "")
		return
	}

	if s.broker == nil {
		writeError(w, http.StatusServiceUnavailable, "no approval broker configured", "")
		return
	}

	var resp channel.Response
	switch req.Verdict {
	case ResolveRequestVerdictAllowOnce:
		resp = channel.ResponseAllowOnce
	case ResolveRequestVerdictAlwaysAllow:
		resp = channel.ResponseAlwaysAllow
	case ResolveRequestVerdictDeny:
		resp = channel.ResponseDeny
	}

	if !s.broker.Resolve(id, resp) {
		writeError(w, http.StatusNotFound, "approval request not found or already resolved", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ResolveResponse{
		Id:      id,
		Verdict: string(req.Verdict),
	})
}

// GetApiStatus returns proxy status and channel information.
func (s *Server) GetApiStatus(w http.ResponseWriter, r *http.Request) {
	listening := s.proxySrv != nil && s.proxySrv.IsListening()

	pendingCount := 0
	if s.broker != nil {
		pendingCount = s.broker.PendingCount()
	}

	var channelStatuses []ChannelStatus
	if s.broker != nil {
		for _, ch := range s.broker.Channels() {
			var typeName ChannelStatusType
			switch ch.Type() {
			case channel.ChannelTelegram:
				typeName = ChannelStatusTypeTelegram
			case channel.ChannelHTTP:
				typeName = ChannelStatusTypeHttp
			}
			channelStatuses = append(channelStatuses, ChannelStatus{
				Type:    typeName,
				Enabled: true,
			})
		}
	}
	if channelStatuses == nil {
		channelStatuses = []ChannelStatus{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(StatusResponse{
		ProxyListening:   listening,
		PendingApprovals: pendingCount,
		Channels:         channelStatuses,
	})
}

// BearerAuthMiddleware validates the Authorization header against SLUICE_API_TOKEN.
// If the env var is not set, all /api/* requests return 403.
func BearerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /healthz bypasses auth (no security scheme in OpenAPI spec).
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		token := os.Getenv("SLUICE_API_TOKEN")
		if token == "" {
			writeError(w, http.StatusForbidden, "API token not configured", "unauthorized")
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header", "unauthorized")
			return
		}

		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			writeError(w, http.StatusUnauthorized, "invalid authorization format", "unauthorized")
			return
		}

		if auth[len(prefix):] != token {
			writeError(w, http.StatusUnauthorized, "invalid token", "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ChannelGateMiddleware returns 403 on /api/* routes when no HTTP channel
// (type=1) is enabled in the store. /healthz is always accessible.
// Auth check runs before channel check (via middleware ordering) so bad
// tokens never reveal channel state.
func ChannelGateMiddleware(st *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			channels, err := st.ListChannels()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check channel state", "")
				return
			}

			httpEnabled := false
			for _, ch := range channels {
				if ch.Type == int(channel.ChannelHTTP) && ch.Enabled {
					httpEnabled = true
					break
				}
			}

			if !httpEnabled {
				writeError(w, http.StatusForbidden, "HTTP channel is not enabled", "channel_disabled")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// --- Rule management handlers ---

// GetApiRules returns policy rules with optional filtering.
func (s *Server) GetApiRules(w http.ResponseWriter, r *http.Request, params GetApiRulesParams) {
	filter := store.RuleFilter{}
	if params.Verdict != nil {
		filter.Verdict = string(*params.Verdict)
	}
	if params.Type != nil {
		filter.Type = string(*params.Type)
	}

	rules, err := s.store.ListRules(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list rules", "")
		return
	}

	result := make([]Rule, len(rules))
	for i, r := range rules {
		result[i] = storeRuleToAPI(r)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// PostApiRules adds a new policy rule and recompiles the engine.
func (s *Server) PostApiRules(w http.ResponseWriter, r *http.Request) {
	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if !req.Verdict.Valid() {
		writeError(w, http.StatusBadRequest, "invalid verdict", "")
		return
	}

	opts := store.RuleOpts{
		Name:   ptrStr(req.Name),
		Source: "api",
	}
	if req.Destination != nil {
		opts.Destination = *req.Destination
	}
	if req.Tool != nil {
		opts.Tool = *req.Tool
	}
	if req.Pattern != nil {
		opts.Pattern = *req.Pattern
	}
	if req.Replacement != nil {
		opts.Replacement = *req.Replacement
	}
	if req.Ports != nil {
		opts.Ports = *req.Ports
	}
	if req.Protocols != nil {
		opts.Protocols = *req.Protocols
	}

	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	id, err := s.store.AddRule(string(req.Verdict), opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	if err := s.recompileEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "rule added but engine recompile failed: "+err.Error(), "")
		return
	}

	// Read back the rule to return the full object.
	rules, err := s.store.ListRules(store.RuleFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back rule", "")
		return
	}
	for _, rule := range rules {
		if rule.ID == id {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(storeRuleToAPI(rule))
			return
		}
	}

	// Fallback: return minimal response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(Rule{Id: id, Verdict: RuleVerdict(req.Verdict)})
}

// DeleteApiRulesId removes a policy rule and recompiles the engine.
func (s *Server) DeleteApiRulesId(w http.ResponseWriter, r *http.Request, id int64) {
	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	deleted, err := s.store.RemoveRule(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove rule", "")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "rule not found", "")
		return
	}

	if err := s.recompileEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "rule removed but engine recompile failed: "+err.Error(), "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// PostApiRulesImport imports rules from a TOML file upload.
func (s *Server) PostApiRulesImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form: "+err.Error(), "")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field", "")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read file", "")
		return
	}

	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	result, err := s.store.ImportTOML(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "import failed: "+err.Error(), "")
		return
	}

	if err := s.recompileEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "import succeeded but engine recompile failed: "+err.Error(), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ImportResult{
		RulesInserted:    result.RulesInserted,
		RulesSkipped:     result.RulesSkipped,
		BindingsInserted: result.BindingsInserted,
		BindingsSkipped:  result.BindingsSkipped,
		UpstreamsInserted: result.UpstreamsInserted,
		UpstreamsSkipped:  result.UpstreamsSkipped,
		ConfigSet:        result.ConfigSet,
	})
}

// GetApiRulesExport exports the current rules as TOML.
func (s *Server) GetApiRulesExport(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer

	cfg, err := s.store.GetConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read config", "")
		return
	}

	if cfg.DefaultVerdict != "" || cfg.TimeoutSec != 0 {
		buf.WriteString("[policy]\n")
		if cfg.DefaultVerdict != "" {
			fmt.Fprintf(&buf, "default = %q\n", cfg.DefaultVerdict)
		}
		if cfg.TimeoutSec != 0 {
			fmt.Fprintf(&buf, "timeout_sec = %d\n", cfg.TimeoutSec)
		}
		buf.WriteString("\n")
	}

	if cfg.VaultProvider != "" || cfg.VaultDir != "" || len(cfg.VaultProviders) > 0 {
		buf.WriteString("[vault]\n")
		if cfg.VaultProvider != "" {
			fmt.Fprintf(&buf, "provider = %q\n", cfg.VaultProvider)
		}
		if cfg.VaultDir != "" {
			fmt.Fprintf(&buf, "dir = %q\n", cfg.VaultDir)
		}
		if len(cfg.VaultProviders) > 0 {
			quoted := make([]string, len(cfg.VaultProviders))
			for i, p := range cfg.VaultProviders {
				quoted[i] = fmt.Sprintf("%q", p)
			}
			fmt.Fprintf(&buf, "providers = [%s]\n", strings.Join(quoted, ", "))
		}
		buf.WriteString("\n")
	}

	// Network, tool, and pattern rules.
	for _, verdict := range []string{"allow", "deny", "ask"} {
		networkRules, err := s.store.ListRules(store.RuleFilter{Verdict: verdict, Type: "network"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list rules", "")
			return
		}
		for _, rule := range networkRules {
			fmt.Fprintf(&buf, "[[%s]]\n", verdict)
			fmt.Fprintf(&buf, "destination = %q\n", rule.Destination)
			if len(rule.Ports) > 0 {
				portsJSON, _ := json.Marshal(rule.Ports)
				fmt.Fprintf(&buf, "ports = %s\n", string(portsJSON))
			}
			if len(rule.Protocols) > 0 {
				protocolsJSON, _ := json.Marshal(rule.Protocols)
				fmt.Fprintf(&buf, "protocols = %s\n", string(protocolsJSON))
			}
			if rule.Name != "" {
				fmt.Fprintf(&buf, "name = %q\n", rule.Name)
			}
			buf.WriteString("\n")
		}

		toolRules, err := s.store.ListRules(store.RuleFilter{Verdict: verdict, Type: "tool"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list rules", "")
			return
		}
		for _, rule := range toolRules {
			fmt.Fprintf(&buf, "[[%s]]\n", verdict)
			fmt.Fprintf(&buf, "tool = %q\n", rule.Tool)
			if rule.Name != "" {
				fmt.Fprintf(&buf, "name = %q\n", rule.Name)
			}
			buf.WriteString("\n")
		}
	}

	// Content deny patterns.
	denyPatterns, err := s.store.ListRules(store.RuleFilter{Verdict: "deny", Type: "pattern"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list rules", "")
		return
	}
	for _, rule := range denyPatterns {
		buf.WriteString("[[deny]]\n")
		fmt.Fprintf(&buf, "pattern = %q\n", rule.Pattern)
		if rule.Name != "" {
			fmt.Fprintf(&buf, "name = %q\n", rule.Name)
		}
		buf.WriteString("\n")
	}

	// Redact rules.
	redactRules, err := s.store.ListRules(store.RuleFilter{Verdict: "redact", Type: "pattern"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list rules", "")
		return
	}
	for _, rule := range redactRules {
		buf.WriteString("[[redact]]\n")
		fmt.Fprintf(&buf, "pattern = %q\n", rule.Pattern)
		if rule.Replacement != "" {
			fmt.Fprintf(&buf, "replacement = %q\n", rule.Replacement)
		}
		if rule.Name != "" {
			fmt.Fprintf(&buf, "name = %q\n", rule.Name)
		}
		buf.WriteString("\n")
	}

	// Bindings.
	bindings, err := s.store.ListBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list bindings", "")
		return
	}
	for _, b := range bindings {
		buf.WriteString("[[binding]]\n")
		fmt.Fprintf(&buf, "destination = %q\n", b.Destination)
		if len(b.Ports) > 0 {
			portsJSON, _ := json.Marshal(b.Ports)
			fmt.Fprintf(&buf, "ports = %s\n", string(portsJSON))
		}
		fmt.Fprintf(&buf, "credential = %q\n", b.Credential)
		if b.Header != "" {
			fmt.Fprintf(&buf, "header = %q\n", b.Header)
		}
		if b.Template != "" {
			fmt.Fprintf(&buf, "template = %q\n", b.Template)
		}
		if len(b.Protocols) > 0 {
			protocolsJSON, _ := json.Marshal(b.Protocols)
			fmt.Fprintf(&buf, "protocols = %s\n", string(protocolsJSON))
		}
		buf.WriteString("\n")
	}

	// MCP upstreams.
	upstreams, err := s.store.ListMCPUpstreams()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list upstreams", "")
		return
	}
	for _, u := range upstreams {
		buf.WriteString("[[mcp_upstream]]\n")
		fmt.Fprintf(&buf, "name = %q\n", u.Name)
		fmt.Fprintf(&buf, "command = %q\n", u.Command)
		if len(u.Args) > 0 {
			argsJSON, _ := json.Marshal(u.Args)
			fmt.Fprintf(&buf, "args = %s\n", string(argsJSON))
		}
		if u.TimeoutSec != 120 {
			fmt.Fprintf(&buf, "timeout_sec = %d\n", u.TimeoutSec)
		}
		if len(u.Env) > 0 {
			keys := make([]string, 0, len(u.Env))
			for k := range u.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(u.Env))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%q = %q", k, u.Env[k]))
			}
			fmt.Fprintf(&buf, "env = {%s}\n", strings.Join(parts, ", "))
		}
		buf.WriteString("\n")
	}

	w.Header().Set("Content-Type", "application/toml")
	w.Write(buf.Bytes())
}

// --- Config handlers ---

// GetApiConfig returns the current configuration.
func (s *Server) GetApiConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read config", "")
		return
	}

	resp := Config{}
	if cfg.DefaultVerdict != "" {
		dv := ConfigDefaultVerdict(cfg.DefaultVerdict)
		resp.DefaultVerdict = &dv
	}
	if cfg.TimeoutSec != 0 {
		resp.TimeoutSec = &cfg.TimeoutSec
	}
	if cfg.VaultProvider != "" {
		resp.VaultProvider = &cfg.VaultProvider
	}
	if cfg.VaultDir != "" {
		resp.VaultDir = &cfg.VaultDir
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// PatchApiConfig updates configuration and recompiles the engine.
func (s *Server) PatchApiConfig(w http.ResponseWriter, r *http.Request) {
	var req ConfigUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	update := store.ConfigUpdate{}
	if req.DefaultVerdict != nil {
		dv := string(*req.DefaultVerdict)
		update.DefaultVerdict = &dv
	}
	if req.TimeoutSec != nil {
		update.TimeoutSec = req.TimeoutSec
	}

	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	if err := s.store.UpdateConfig(update); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	if err := s.recompileEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "config updated but engine recompile failed: "+err.Error(), "")
		return
	}

	// Return the updated config.
	s.GetApiConfig(w, r)
}

// --- Credential handlers ---

// GetApiCredentials lists credential names from the vault.
func (s *Server) GetApiCredentials(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	names, err := s.vault.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list credentials", "")
		return
	}

	creds := make([]Credential, len(names))
	for i, n := range names {
		creds[i] = Credential{Name: n}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

// PostApiCredentials adds a credential to the vault. If destination is
// provided, also creates an allow rule and binding.
func (s *Server) PostApiCredentials(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	var req CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if req.Name == "" || req.Value == "" {
		writeError(w, http.StatusBadRequest, "name and value are required", "")
		return
	}

	// Check if credential already exists.
	existing, err := s.vault.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check existing credentials", "")
		return
	}
	for _, n := range existing {
		if n == req.Name {
			writeError(w, http.StatusConflict, "credential already exists", "")
			return
		}
	}

	if _, err := s.vault.Add(req.Name, req.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store credential: "+err.Error(), "")
		return
	}

	// If destination is provided, create allow rule + binding.
	if req.Destination != nil && *req.Destination != "" {
		ruleOpts := store.RuleOpts{
			Destination: *req.Destination,
			Name:        "credential: " + req.Name,
			Source:      "api",
		}
		if req.Ports != nil {
			ruleOpts.Ports = *req.Ports
		}

		bindingOpts := store.BindingOpts{
			Header:   ptrStr(req.Header),
			Template: ptrStr(req.Template),
		}
		if req.Ports != nil {
			bindingOpts.Ports = *req.Ports
		}

		if s.reloadMu != nil {
			s.reloadMu.Lock()
			defer s.reloadMu.Unlock()
		}

		if _, _, err := s.store.AddRuleAndBinding("allow", ruleOpts, req.Name, bindingOpts); err != nil {
			writeError(w, http.StatusBadRequest, "credential stored but rule/binding creation failed: "+err.Error(), "")
			return
		}

		if err := s.recompileEngine(); err != nil {
			writeError(w, http.StatusInternalServerError, "credential stored but engine recompile failed: "+err.Error(), "")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(Credential{Name: req.Name})
}

// DeleteApiCredentialsName removes a credential and its associated bindings/rules.
func (s *Server) DeleteApiCredentialsName(w http.ResponseWriter, r *http.Request, name string) {
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	// Check if credential exists.
	existing, err := s.vault.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list credentials", "")
		return
	}
	found := false
	for _, n := range existing {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "credential not found", "")
		return
	}

	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	// Remove associated bindings and rules.
	if _, err := s.store.RemoveBindingsByCredential(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove bindings: "+err.Error(), "")
		return
	}

	// Remove the credential from the vault.
	if err := s.vault.Remove(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove credential: "+err.Error(), "")
		return
	}

	if err := s.recompileEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "credential removed but engine recompile failed: "+err.Error(), "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Binding handlers ---

// GetApiBindings lists all credential bindings.
func (s *Server) GetApiBindings(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list bindings", "")
		return
	}

	bindings := make([]Binding, len(rows))
	for i, b := range rows {
		bindings[i] = storeBindingToAPI(b)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bindings)
}

// PostApiBindings adds a new credential binding.
func (s *Server) PostApiBindings(w http.ResponseWriter, r *http.Request) {
	var req CreateBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if req.Destination == "" || req.Credential == "" {
		writeError(w, http.StatusBadRequest, "destination and credential are required", "")
		return
	}

	opts := store.BindingOpts{
		Header:   ptrStr(req.Header),
		Template: ptrStr(req.Template),
	}
	if req.Ports != nil {
		opts.Ports = *req.Ports
	}
	if req.Protocols != nil {
		opts.Protocols = *req.Protocols
	}

	id, err := s.store.AddBinding(req.Destination, req.Credential, opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	// Read back the binding.
	rows, err := s.store.ListBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back binding", "")
		return
	}
	for _, b := range rows {
		if b.ID == id {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(storeBindingToAPI(b))
			return
		}
	}

	// Fallback.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(Binding{Id: id, Destination: req.Destination, Credential: req.Credential})
}

// DeleteApiBindingsId removes a credential binding.
func (s *Server) DeleteApiBindingsId(w http.ResponseWriter, r *http.Request, id int64) {
	deleted, err := s.store.RemoveBinding(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove binding", "")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "binding not found", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- MCP upstream handlers ---

// GetApiMcpUpstreams lists all MCP upstreams.
func (s *Server) GetApiMcpUpstreams(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListMCPUpstreams()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list upstreams", "")
		return
	}

	upstreams := make([]MCPUpstream, len(rows))
	for i, u := range rows {
		upstreams[i] = storeMCPUpstreamToAPI(u)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(upstreams)
}

// PostApiMcpUpstreams adds a new MCP upstream.
func (s *Server) PostApiMcpUpstreams(w http.ResponseWriter, r *http.Request) {
	var req CreateMCPUpstreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if req.Name == "" || req.Command == "" {
		writeError(w, http.StatusBadRequest, "name and command are required", "")
		return
	}

	opts := store.MCPUpstreamOpts{}
	if req.Args != nil {
		opts.Args = *req.Args
	}
	if req.Env != nil {
		opts.Env = *req.Env
	}
	if req.TimeoutSec != nil {
		opts.TimeoutSec = *req.TimeoutSec
	}

	id, err := s.store.AddMCPUpstream(req.Name, req.Command, opts)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error(), "")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	// Read back the upstream.
	rows, err := s.store.ListMCPUpstreams()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back upstream", "")
		return
	}
	for _, u := range rows {
		if u.ID == id {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(storeMCPUpstreamToAPI(u))
			return
		}
	}

	// Fallback.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(MCPUpstream{Id: id, Name: req.Name, Command: req.Command})
}

// DeleteApiMcpUpstreamsName removes an MCP upstream by name.
func (s *Server) DeleteApiMcpUpstreamsName(w http.ResponseWriter, r *http.Request, name string) {
	deleted, err := s.store.RemoveMCPUpstream(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove upstream", "")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "upstream not found", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Audit handlers ---

// GetApiAuditRecent returns the last N audit log entries.
func (s *Server) GetApiAuditRecent(w http.ResponseWriter, r *http.Request, params GetApiAuditRecentParams) {
	if s.auditPath == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]AuditEntry{})
		return
	}

	limit := 50
	if params.Limit != nil && *params.Limit > 0 {
		limit = *params.Limit
		if limit > 1000 {
			limit = 1000
		}
	}

	entries, err := readRecentAuditEntries(s.auditPath, limit)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]AuditEntry{})
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read audit log: "+err.Error(), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// GetApiAuditVerify verifies the audit log hash chain.
func (s *Server) GetApiAuditVerify(w http.ResponseWriter, r *http.Request) {
	if s.auditPath == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerifyResult{
			TotalLines:  0,
			ValidLinks:  0,
			BrokenLinks: []BrokenLink{},
			LegacyLines: 0,
		})
		return
	}

	result, err := audit.VerifyChain(s.auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(VerifyResult{
				TotalLines:  0,
				ValidLinks:  0,
				BrokenLinks: []BrokenLink{},
				LegacyLines: 0,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, "verification failed: "+err.Error(), "")
		return
	}

	apiLinks := make([]BrokenLink, len(result.BrokenLinks))
	for i, bl := range result.BrokenLinks {
		apiLinks[i] = BrokenLink{
			LineNumber:   bl.LineNumber,
			ExpectedHash: bl.ExpectedHash,
			ActualHash:   bl.ActualHash,
		}
	}
	if apiLinks == nil {
		apiLinks = []BrokenLink{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(VerifyResult{
		TotalLines:  result.TotalLines,
		ValidLinks:  result.ValidLinks,
		BrokenLinks: apiLinks,
		LegacyLines: result.LegacyLines,
	})
}

// --- Channel handlers ---

// GetApiChannels lists all notification channels.
func (s *Server) GetApiChannels(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListChannels()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list channels", "")
		return
	}

	channels := make([]Channel, len(rows))
	for i, ch := range rows {
		channels[i] = storeChannelToAPI(ch)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(channels)
}

// PatchApiChannelsId updates a notification channel.
func (s *Server) PatchApiChannelsId(w http.ResponseWriter, r *http.Request, id int64) {
	var req ChannelUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	// Check if channel exists.
	ch, err := s.store.GetChannel(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get channel", "")
		return
	}
	if ch == nil {
		writeError(w, http.StatusNotFound, "channel not found", "")
		return
	}

	update := store.ChannelUpdate{
		Enabled:       req.Enabled,
		WebhookURL:    req.WebhookUrl,
		WebhookSecret: req.WebhookSecret,
	}

	if err := s.store.UpdateChannel(id, update); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update channel: "+err.Error(), "")
		return
	}

	// Read back the updated channel.
	ch, err = s.store.GetChannel(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back channel", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(storeChannelToAPI(*ch))
}

// --- Helpers ---

// storeRuleToAPI converts a store.Rule to the API Rule type.
func storeRuleToAPI(r store.Rule) Rule {
	rule := Rule{
		Id:      r.ID,
		Verdict: RuleVerdict(r.Verdict),
	}
	if r.Destination != "" {
		rule.Destination = &r.Destination
	}
	if r.Tool != "" {
		rule.Tool = &r.Tool
	}
	if r.Pattern != "" {
		rule.Pattern = &r.Pattern
	}
	if r.Replacement != "" {
		rule.Replacement = &r.Replacement
	}
	if len(r.Ports) > 0 {
		rule.Ports = &r.Ports
	}
	if len(r.Protocols) > 0 {
		rule.Protocols = &r.Protocols
	}
	if r.Name != "" {
		rule.Name = &r.Name
	}
	if r.Source != "" {
		rule.Source = &r.Source
	}
	if r.CreatedAt != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", r.CreatedAt); err == nil {
			rule.CreatedAt = &t
		}
	}
	return rule
}

// ptrStr returns the value of a string pointer or empty string if nil.
func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := ErrorResponse{Error: msg}
	if code != "" {
		resp.Code = &code
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// storeBindingToAPI converts a store.BindingRow to the API Binding type.
func storeBindingToAPI(b store.BindingRow) Binding {
	binding := Binding{
		Id:          b.ID,
		Destination: b.Destination,
		Credential:  b.Credential,
	}
	if len(b.Ports) > 0 {
		binding.Ports = &b.Ports
	}
	if b.Header != "" {
		binding.Header = &b.Header
	}
	if b.Template != "" {
		binding.Template = &b.Template
	}
	if len(b.Protocols) > 0 {
		binding.Protocols = &b.Protocols
	}
	if b.CreatedAt != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", b.CreatedAt); err == nil {
			binding.CreatedAt = &t
		}
	}
	return binding
}

// storeMCPUpstreamToAPI converts a store.MCPUpstreamRow to the API MCPUpstream type.
func storeMCPUpstreamToAPI(u store.MCPUpstreamRow) MCPUpstream {
	upstream := MCPUpstream{
		Id:      u.ID,
		Name:    u.Name,
		Command: u.Command,
	}
	if len(u.Args) > 0 {
		upstream.Args = &u.Args
	}
	if len(u.Env) > 0 {
		upstream.Env = &u.Env
	}
	if u.TimeoutSec != 0 {
		upstream.TimeoutSec = &u.TimeoutSec
	}
	if u.CreatedAt != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", u.CreatedAt); err == nil {
			upstream.CreatedAt = &t
		}
	}
	return upstream
}

// storeChannelToAPI converts a store.Channel to the API Channel type.
func storeChannelToAPI(ch store.Channel) Channel {
	var chType ChannelType
	switch ch.Type {
	case int(channel.ChannelTelegram):
		chType = ChannelTypeTelegram
	case int(channel.ChannelHTTP):
		chType = ChannelTypeHttp
	}
	apiCh := Channel{
		Id:      ch.ID,
		Type:    chType,
		Enabled: ch.Enabled,
	}
	if ch.WebhookURL != "" {
		apiCh.WebhookUrl = &ch.WebhookURL
	}
	if ch.WebhookSecret != "" {
		apiCh.WebhookSecret = &ch.WebhookSecret
	}
	if ch.CreatedAt != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", ch.CreatedAt); err == nil {
			apiCh.CreatedAt = &t
		}
	}
	return apiCh
}

// readRecentAuditEntries reads the last N entries from the audit log file.
func readRecentAuditEntries(path string, limit int) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read all lines, keep last N.
	var lines [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		lines = append(lines, cp)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Take last N lines.
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	recent := lines[start:]

	entries := make([]AuditEntry, 0, len(recent))
	for _, line := range recent {
		var evt audit.Event
		if err := json.Unmarshal(line, &evt); err != nil {
			continue
		}
		entry := AuditEntry{
			Verdict: evt.Verdict,
		}
		if t, err := time.Parse(time.RFC3339, evt.Timestamp); err == nil {
			entry.Timestamp = t
		}
		if evt.PrevHash != "" {
			entry.PrevHash = &evt.PrevHash
		}
		if evt.Destination != "" {
			entry.Destination = &evt.Destination
		}
		if evt.Port != 0 {
			entry.Port = &evt.Port
		}
		if evt.Reason != "" {
			entry.Reason = &evt.Reason
		}
		if evt.Tool != "" {
			entry.Tool = &evt.Tool
		}
		if evt.Action != "" {
			entry.Action = &evt.Action
		}
		if evt.Credential != "" {
			entry.CredentialUsed = &evt.Credential
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
