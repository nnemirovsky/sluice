package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/container"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// Server implements the generated ServerInterface for the sluice REST API.
type Server struct {
	Unimplemented
	store        *store.Store
	broker       *channel.Broker
	proxySrv     *proxy.Server
	vault        *vault.Store
	auditPath    string
	enginePtr    *atomic.Pointer[policy.Engine]
	reloadMu     *sync.Mutex
	resolverPtr  *atomic.Pointer[vault.BindingResolver]
	containerMgr container.ContainerManager
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

// SetResolverPtr shares the proxy's binding resolver pointer so credential
// mutations can update the live binding snapshot without requiring SIGHUP.
func (s *Server) SetResolverPtr(ptr *atomic.Pointer[vault.BindingResolver]) {
	s.resolverPtr = ptr
}

// SetContainerManager enables env injection and container hot-reload
// on credential changes.
func (s *Server) SetContainerManager(mgr container.ContainerManager) {
	s.containerMgr = mgr
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

// rebuildResolver reads bindings from the store, creates a new BindingResolver,
// and atomically swaps it into the shared pointer. The caller must hold reloadMu.
func (s *Server) rebuildResolver() error {
	if s.resolverPtr == nil || s.store == nil {
		return nil
	}
	rows, err := s.store.ListBindings()
	if err != nil {
		return fmt.Errorf("list bindings: %w", err)
	}
	if len(rows) == 0 {
		s.resolverPtr.Store(nil)
		return nil
	}
	bindings := make([]vault.Binding, len(rows))
	for i, r := range rows {
		bindings[i] = vault.Binding{
			Destination: r.Destination,
			Ports:       r.Ports,
			Credential:  r.Credential,
			Header:      r.Header,
			Template:    r.Template,
			Protocols:   r.Protocols,
		}
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		return fmt.Errorf("compile bindings: %w", err)
	}
	s.resolverPtr.Store(resolver)
	return nil
}

// rebuildOAuthIndex reads credential_meta from the store and updates the
// proxy server's OAuth token URL index. This is called after OAuth credential
// mutations so the MITM response handler picks up new or removed token URLs.
func (s *Server) rebuildOAuthIndex() {
	if s.proxySrv == nil || s.store == nil {
		return
	}
	metas, err := s.store.ListCredentialMeta()
	if err != nil {
		log.Printf("[WARN] list credential meta for OAuth index rebuild: %v", err)
		return
	}
	s.proxySrv.UpdateOAuthIndex(metas)
}

// credMutationComplete reads bindings with env_var set from the store,
// generates phantom tokens, and injects them into the agent container.
// removedEnvVars lists env var names whose bindings were already deleted
// and should be cleared from the agent environment.
func (s *Server) credMutationComplete(removedEnvVars ...string) error {
	if s.containerMgr == nil || s.store == nil {
		return nil
	}

	bindings, err := s.store.ListBindingsWithEnvVar()
	if err != nil {
		return fmt.Errorf("list bindings with env_var: %w", err)
	}

	envMap := make(map[string]string, len(bindings)+len(removedEnvVars))
	for _, b := range bindings {
		envMap[b.EnvVar] = vault.GeneratePhantomToken(b.Credential)
	}
	// Set empty values for removed env vars so they are cleared from the agent.
	for _, ev := range removedEnvVars {
		if _, exists := envMap[ev]; !exists {
			envMap[ev] = ""
		}
	}

	if len(envMap) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return s.containerMgr.InjectEnvVars(ctx, envMap, false)
}

// GetHealthz returns 200 when the proxy is listening.
func (s *Server) GetHealthz(w http.ResponseWriter, _ *http.Request) {
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
func (s *Server) GetApiApprovals(w http.ResponseWriter, _ *http.Request) { //nolint:revive // generated interface name
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
func (s *Server) PostApiApprovalsIdResolve(w http.ResponseWriter, r *http.Request, id string) { //nolint:revive // generated interface name
	var req ResolveRequest
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
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
		if s.broker.WasTimedOut(id) {
			writeError(w, http.StatusConflict, "approval already resolved or timed out", "")
		} else {
			writeError(w, http.StatusNotFound, "approval request not found", "")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ResolveResponse{
		Id:      id,
		Verdict: string(req.Verdict),
	})
}

// GetApiStatus returns proxy status and channel information.
func (s *Server) GetApiStatus(w http.ResponseWriter, _ *http.Request) { //nolint:revive // generated interface name
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

		if subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(token)) != 1 {
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
func (s *Server) GetApiRules(w http.ResponseWriter, r *http.Request, params GetApiRulesParams) { //nolint:revive // generated interface name
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
func (s *Server) PostApiRules(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	var req CreateRuleRequest
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
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
func (s *Server) DeleteApiRulesId(w http.ResponseWriter, r *http.Request, id int64) { //nolint:revive // generated interface name
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
func (s *Server) PostApiRulesImport(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form: "+err.Error(), "")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field", "")
		return
	}
	defer func() { _ = file.Close() }()

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
		RulesInserted:     result.RulesInserted,
		RulesSkipped:      result.RulesSkipped,
		BindingsInserted:  result.BindingsInserted,
		BindingsSkipped:   result.BindingsSkipped,
		UpstreamsInserted: result.UpstreamsInserted,
		UpstreamsSkipped:  result.UpstreamsSkipped,
		ConfigSet:         result.ConfigSet,
	})
}

// GetApiRulesExport exports the current rules as TOML.
func (s *Server) GetApiRulesExport(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
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
		if b.EnvVar != "" {
			fmt.Fprintf(&buf, "env_var = %q\n", b.EnvVar)
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
		if u.Transport != "" && u.Transport != "stdio" {
			fmt.Fprintf(&buf, "transport = %q\n", u.Transport)
		}
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
	_, _ = w.Write(buf.Bytes())
}

// --- Config handlers ---

// GetApiConfig returns the current configuration.
func (s *Server) GetApiConfig(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
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
func (s *Server) PatchApiConfig(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	var req ConfigUpdate
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
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

// GetApiCredentials lists credential names from the vault with type metadata.
func (s *Server) GetApiCredentials(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	names, err := s.vault.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list credentials", "")
		return
	}

	// Build a lookup of credential metadata for type/token_url.
	metas, metaErr := s.store.ListCredentialMeta()
	metaMap := make(map[string]store.CredentialMeta, len(metas))
	if metaErr == nil {
		for _, m := range metas {
			metaMap[m.Name] = m
		}
	}

	creds := make([]Credential, len(names))
	for i, n := range names {
		creds[i] = Credential{Name: n}
		if m, ok := metaMap[n]; ok {
			ct := CredentialType(m.CredType)
			creds[i].Type = &ct
			if m.TokenURL != "" {
				creds[i].TokenUrl = &m.TokenURL
			}
		} else {
			// Default to static for credentials without metadata.
			ct := CredentialTypeStatic
			creds[i].Type = &ct
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

// PostApiCredentials adds a credential to the vault. If destination is
// provided, also creates an allow rule and binding. Supports both static
// and oauth credential types.
func (s *Server) PostApiCredentials(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	var req CreateCredentialRequest
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", "")
		return
	}

	// Determine credential type (default: static).
	credType := "static"
	if req.Type != nil {
		if !req.Type.Valid() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid credential type %q: must be static or oauth", *req.Type), "")
			return
		}
		if *req.Type == CreateCredentialRequestTypeOauth {
			credType = "oauth"
		}
	}

	// Validate type-specific required fields.
	if credType == "static" {
		if req.Value == nil || *req.Value == "" {
			writeError(w, http.StatusBadRequest, "value is required for static credentials", "")
			return
		}
	} else {
		if req.TokenUrl == nil || *req.TokenUrl == "" {
			writeError(w, http.StatusBadRequest, "token_url is required for oauth credentials", "")
			return
		}
		parsed, err := url.Parse(*req.TokenUrl)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			writeError(w, http.StatusBadRequest, "invalid token_url: must include scheme and host", "")
			return
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			writeError(w, http.StatusBadRequest, "invalid token_url: scheme must be http or https", "")
			return
		}
		if req.AccessToken == nil || *req.AccessToken == "" {
			writeError(w, http.StatusBadRequest, "access_token is required for oauth credentials", "")
			return
		}
	}

	// env_var requires a destination (it is stored on the binding).
	if req.EnvVar != nil && *req.EnvVar != "" && (req.Destination == nil || *req.Destination == "") {
		writeError(w, http.StatusBadRequest, "--env-var requires --destination", "")
		return
	}

	// Take the reload mutex BEFORE the existence check so concurrent creates
	// of the same credential name serialize end to end. Without this, two
	// racing requests could both observe that the credential does not exist,
	// both call vault.Add, and then the loser's rollback on AddRuleAndBinding
	// failure would delete the winner's freshly created credential and
	// metadata. Holding reloadMu across existence check, vault.Add,
	// AddCredentialMeta, AddRuleAndBinding, and any rollback guarantees that
	// a rollback only ever touches state that this request just created.
	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
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

	// Back up any pre-existing ciphertext so we can restore it on rollback.
	// reloadMu serializes in-process writers, but another sluice instance or
	// a separate CLI process writing to the same vault directory can still
	// overwrite this credential concurrently. Backup-then-restore keeps a
	// transient DB error from wiping their state.
	prevCiphertext, readErr := s.vault.ReadRawCredential(req.Name)
	if readErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to back up existing credential: "+readErr.Error(), "")
		return
	}

	// Store the credential value in the vault, capturing the ciphertext we
	// just wrote so the rollback path can use compare-and-swap.
	var ourCiphertext []byte
	if credType == "oauth" {
		oauthCred := &vault.OAuthCredential{
			AccessToken: *req.AccessToken,
			TokenURL:    *req.TokenUrl,
		}
		if req.RefreshToken != nil {
			oauthCred.RefreshToken = *req.RefreshToken
		}
		data, err := oauthCred.Marshal()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal oauth credential: "+err.Error(), "")
			return
		}
		ct, addErr := s.vault.Add(req.Name, string(data))
		if addErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to store credential: "+addErr.Error(), "")
			return
		}
		ourCiphertext = ct
	} else {
		ct, addErr := s.vault.Add(req.Name, *req.Value)
		if addErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to store credential: "+addErr.Error(), "")
			return
		}
		ourCiphertext = ct
	}

	// rollbackVault reverts the vault entry using compare-and-swap so a
	// concurrent writer that has since overwritten the credential is not
	// clobbered. See (*vault.Store).RollbackAdd for semantics.
	rollbackVault := func() {
		owned, rbErr := s.vault.RollbackAdd(req.Name, prevCiphertext, ourCiphertext)
		if !owned {
			log.Printf("[WARN] credential %q was modified concurrently; skipping vault rollback", req.Name)
			return
		}
		if rbErr != nil {
			log.Printf("[WARN] failed to roll back vault credential %q: %v", req.Name, rbErr)
		}
	}

	// Store credential metadata in the store.
	tokenURL := ""
	if req.TokenUrl != nil {
		tokenURL = *req.TokenUrl
	}
	if err := s.store.AddCredentialMeta(req.Name, credType, tokenURL); err != nil {
		rollbackVault()
		writeError(w, http.StatusInternalServerError, "failed to store credential metadata: "+err.Error(), "")
		return
	}

	// rollbackCredentialMeta removes the credential_meta row we just
	// inserted using compare-and-swap on (cred_type, token_url). If a
	// concurrent writer has already overwritten the row with different
	// values, leave their state alone and log a warning.
	rollbackCredentialMeta := func() {
		_, noConcurrent, rmErr := s.store.RemoveCredentialMetaCAS(req.Name, credType, tokenURL)
		if rmErr != nil {
			log.Printf("[WARN] failed to remove credential meta %q after rollback: %v", req.Name, rmErr)
			return
		}
		if !noConcurrent {
			log.Printf("[WARN] credential meta %q was modified concurrently; skipping meta rollback", req.Name)
		}
	}

	// If destination is provided, create allow rule + binding.
	if req.Destination != nil && *req.Destination != "" {
		ruleOpts := store.RuleOpts{
			Destination: *req.Destination,
			Name:        "credential: " + req.Name,
			Source:      store.CredAddSourcePrefix + req.Name,
		}
		if req.Ports != nil {
			ruleOpts.Ports = *req.Ports
		}

		bindingOpts := store.BindingOpts{
			Header:   ptrStr(req.Header),
			Template: ptrStr(req.Template),
			EnvVar:   ptrStr(req.EnvVar),
		}
		if req.Ports != nil {
			bindingOpts.Ports = *req.Ports
		}

		if _, _, err := s.store.AddRuleAndBinding("allow", ruleOpts, req.Name, bindingOpts); err != nil {
			// Roll back credential_meta and vault using compare-and-swap
			// to avoid clobbering a concurrent writer.
			rollbackCredentialMeta()
			rollbackVault()
			// Distinguish conflict (duplicate binding for this
			// credential/destination), validation (bad input), and
			// unexpected store failures. Collapsing everything to 400
			// hid real outages and made conflicts indistinguishable
			// from client errors. Mirrors PostApiBindings.
			if errors.Is(err, store.ErrBindingDuplicate) {
				writeError(w, http.StatusConflict, err.Error(), "")
				return
			}
			if errors.Is(err, store.ErrBindingValidation) {
				writeError(w, http.StatusBadRequest, err.Error(), "")
				return
			}
			log.Printf("[ERROR] add rule and binding for credential %q failed: %v", req.Name, err)
			writeError(w, http.StatusInternalServerError, "failed to create rule/binding", "")
			return
		}

		if err := s.recompileEngine(); err != nil {
			writeError(w, http.StatusInternalServerError, "credential stored but engine recompile failed: "+err.Error(), "")
			return
		}

		// Fail loudly if the live resolver cannot be rebuilt after a
		// credential mutation created a binding. Silently logging and
		// returning 201 would leave the live BindingResolver stale while
		// the store already has the new binding: the agent would keep
		// using pre-change resolver state until the next successful reload
		// or a SIGHUP. Mirror PostApiBindings, which already surfaces this
		// as a 500.
		if err := s.rebuildResolver(); err != nil {
			log.Printf("[ERROR] rebuild resolver after cred add failed: %v", err)
			writeError(w, http.StatusInternalServerError,
				"credential stored but resolver rebuild failed, live resolver is stale (send SIGHUP to recover): "+err.Error(), "")
			return
		}
	}

	// For OAuth credentials, update the proxy's OAuth index.
	if credType == "oauth" {
		s.rebuildOAuthIndex()
	}

	if err := s.credMutationComplete(); err != nil {
		log.Printf("[WARN] phantom regen/hot-reload after cred add failed: %v", err)
	}

	respCred := Credential{Name: req.Name}
	ct := CredentialType(credType)
	respCred.Type = &ct
	if tokenURL != "" {
		respCred.TokenUrl = &tokenURL
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(respCred)
}

// PatchApiCredentialsName replaces the value of an existing credential.
// For static credentials, request body must contain `value`. For OAuth
// credentials, the body must contain `access_token` and optionally
// `refresh_token`. The existing token_url is preserved. Bindings, rules,
// and metadata are untouched. Phantom tokens are deterministic and derived
// from the credential name, so they do not need regeneration.
func (s *Server) PatchApiCredentialsName(w http.ResponseWriter, r *http.Request, name string) { //nolint:revive // generated interface name
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	var req CredentialUpdate
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	// Serialize with concurrent POST/DELETE on credentials so the vault
	// write is not racing against a concurrent add/remove of the same name.
	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
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

	// Determine credential type from credential_meta (authoritative source),
	// falling back to payload-shape detection only for legacy bare credentials
	// with no meta row. Using vault.IsOAuth on the stored bytes alone would
	// misclassify a static credential whose value happens to be JSON that
	// matches the OAuth shape (e.g. access_token + token_url fields).
	meta, metaErr := s.store.GetCredentialMeta(name)
	if metaErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to read credential metadata: "+metaErr.Error(), "")
		return
	}

	// Read the existing value. For OAuth we need the token_url so we can
	// rebuild the JSON blob with new tokens. The existing secret bytes are
	// released immediately after use.
	current, err := s.vault.Get(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read existing credential", "")
		return
	}
	var isOAuth bool
	switch {
	case meta != nil:
		isOAuth = meta.CredType == "oauth"
	default:
		// Legacy row with no credential_meta. Fall back to payload shape.
		isOAuth = vault.IsOAuth(current.Bytes())
	}
	var existingTokenURL, existingRefreshToken string
	if isOAuth {
		parsed, parseErr := vault.ParseOAuth(current.Bytes())
		if parseErr != nil {
			current.Release()
			writeError(w, http.StatusInternalServerError, "failed to parse existing oauth credential: "+parseErr.Error(), "")
			return
		}
		existingTokenURL = parsed.TokenURL
		existingRefreshToken = parsed.RefreshToken
	}
	current.Release()

	// Validate body and build new secret bytes.
	var newSecret string
	if isOAuth {
		if req.AccessToken == nil || *req.AccessToken == "" {
			writeError(w, http.StatusBadRequest, "access_token is required for oauth credentials", "")
			return
		}
		// PATCH partial-update semantics: a missing refresh_token field
		// preserves the stored value. An explicitly supplied empty string
		// clears it. This matches the CLI "press Enter to keep current"
		// behavior and prevents a client that only rotates access from
		// silently destroying the refresh token.
		oauthCred := &vault.OAuthCredential{
			AccessToken:  *req.AccessToken,
			RefreshToken: existingRefreshToken,
			TokenURL:     existingTokenURL,
		}
		if req.RefreshToken != nil {
			oauthCred.RefreshToken = *req.RefreshToken
		}
		data, marshalErr := oauthCred.Marshal()
		if marshalErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal oauth credential: "+marshalErr.Error(), "")
			return
		}
		newSecret = string(data)
	} else {
		if req.Value == nil || *req.Value == "" {
			writeError(w, http.StatusBadRequest, "value is required for static credentials", "")
			return
		}
		newSecret = *req.Value
	}

	if _, err := s.vault.Add(name, newSecret); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update credential: "+err.Error(), "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteApiCredentialsName removes a credential and its associated bindings/rules.
func (s *Server) DeleteApiCredentialsName(w http.ResponseWriter, r *http.Request, name string) { //nolint:revive // generated interface name
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault not configured", "")
		return
	}

	// Take the reload mutex FIRST, before the existence check. A concurrent
	// delete + recreate of the same credential name could otherwise observe
	// the credential, lose the race to the other handler, and then either
	// delete the freshly created credential (wrong) or return 500 after
	// partial cleanup (wrong). Holding reloadMu across the existence check
	// and the delete serializes these operations end to end.
	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
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

	// Check if this was an OAuth credential (for index rebuild later).
	wasOAuth := false
	if meta, err := s.store.GetCredentialMeta(name); err == nil && meta != nil {
		wasOAuth = meta.CredType == "oauth"
	}

	// Read env_var values from bindings before removal so we can clear
	// them from the agent container after the bindings are deleted.
	var removedEnvVars []string
	if credBindings, err := s.store.ListBindingsByCredential(name); err == nil {
		for _, b := range credBindings {
			if b.EnvVar != "" {
				removedEnvVars = append(removedEnvVars, b.EnvVar)
			}
		}
	}

	// Remove associated bindings and auto-created rules first. If vault.Remove
	// below fails, bindings/rules are already gone. This is a pre-existing
	// ordering tradeoff: reversing it would orphan bindings when vault succeeds
	// but SQLite fails. A transactional approach would require the vault to
	// participate in the same transaction, which is not currently possible.
	if _, err := s.store.RemoveBindingsByCredential(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove bindings: "+err.Error(), "")
		return
	}
	// Rules may have been created by either "cred add --destination" (tagged
	// cred-add:<name>) or by "binding add" against the same credential
	// (tagged binding-add:<name>). Remove both so cleanup is symmetric with
	// the CLI, otherwise orphan allow rules would persist after the
	// credential is gone.
	for _, src := range []string{
		store.CredAddSourcePrefix + name,
		store.BindingAddSourcePrefix + name,
	} {
		if _, err := s.store.RemoveRulesBySource(src); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to remove associated rules: "+err.Error(), "")
			return
		}
	}

	// Remove the credential from the vault first. If this fails, metadata
	// stays intact so the credential type is not lost.
	if err := s.vault.Remove(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove credential: "+err.Error(), "")
		return
	}

	// Remove credential metadata after vault deletion succeeded.
	if _, err := s.store.RemoveCredentialMeta(name); err != nil {
		log.Printf("[WARN] failed to remove credential meta %q: %v", name, err)
	}

	if err := s.recompileEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "credential removed but engine recompile failed: "+err.Error(), "")
		return
	}

	// Fail loudly if the live resolver cannot be rebuilt after a credential
	// removal deleted bindings. Silently logging and returning 204 would
	// leave the live BindingResolver stale while the store already reflects
	// the deletion: the agent would keep resolving the removed bindings
	// until the next successful reload or a SIGHUP. Mirror the binding
	// handlers which already surface this as a 500.
	if err := s.rebuildResolver(); err != nil {
		log.Printf("[ERROR] rebuild resolver after cred remove failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"credential removed but resolver rebuild failed, live resolver is stale (send SIGHUP to recover): "+err.Error(), "")
		return
	}

	// If this was an OAuth credential, rebuild the OAuth index.
	if wasOAuth {
		s.rebuildOAuthIndex()
	}

	if err := s.credMutationComplete(removedEnvVars...); err != nil {
		log.Printf("[WARN] env injection after cred remove failed: %v", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Binding handlers ---

// GetApiBindings lists all credential bindings.
func (s *Server) GetApiBindings(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
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

// PostApiBindings adds a new credential binding. To match the CLI
// (`sluice binding add`), this also creates a paired auto-allow rule
// tagged "binding-add:<credential>" so the destination becomes reachable
// without a separate policy add. Both inserts run inside one transaction
// via AddRuleAndBinding so a duplicate-binding error rolls back the rule
// and leaves no orphan policy.
func (s *Server) PostApiBindings(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	var req CreateBindingRequest
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	if req.Destination == "" || req.Credential == "" {
		writeError(w, http.StatusBadRequest, "destination and credential are required", "")
		return
	}

	bindingOpts := store.BindingOpts{
		Header:   ptrStr(req.Header),
		Template: ptrStr(req.Template),
		EnvVar:   ptrStr(req.EnvVar),
	}
	if req.Ports != nil {
		bindingOpts.Ports = *req.Ports
	}
	if req.Protocols != nil {
		bindingOpts.Protocols = *req.Protocols
	}
	ruleOpts := store.RuleOpts{
		Destination: req.Destination,
		Ports:       bindingOpts.Ports,
		Protocols:   bindingOpts.Protocols,
		Name:        fmt.Sprintf("auto-created for binding on credential %q", req.Credential),
		Source:      store.BindingAddSourcePrefix + req.Credential,
	}

	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	_, id, err := s.store.AddRuleAndBinding("allow", ruleOpts, req.Credential, bindingOpts)
	if err != nil {
		if errors.Is(err, store.ErrBindingDuplicate) {
			writeError(w, http.StatusConflict, err.Error(), "")
			return
		}
		// Only tagged validation errors map to 400. Anything else
		// (SQL failures, tx begin/commit errors, etc) is a server
		// fault and must surface as 500 so clients do not see DB
		// outages as "bad request".
		if errors.Is(err, store.ErrBindingValidation) {
			writeError(w, http.StatusBadRequest, err.Error(), "")
			return
		}
		log.Printf("[ERROR] add rule and binding failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to add binding", "")
		return
	}

	// Fail loudly if the live engine or resolver cannot be rebuilt after a
	// binding mutation. Silently logging and returning 201 would leave the
	// client believing the binding is enforced while the in-memory policy
	// still reflects the pre-change state, so enforcement would lag behind
	// storage until the next successful reload.
	if err := s.recompileEngine(); err != nil {
		log.Printf("[ERROR] recompile engine after binding add failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"binding stored but engine recompile failed: "+err.Error(), "")
		return
	}
	if err := s.rebuildResolver(); err != nil {
		log.Printf("[ERROR] rebuild resolver after binding add failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"binding stored but resolver rebuild failed: "+err.Error(), "")
		return
	}

	if err := s.credMutationComplete(); err != nil {
		log.Printf("[WARN] credential mutation complete after binding add failed: %v", err)
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

// PatchApiBindingsId updates a credential binding. Only fields present in
// the request body are updated. Not-found returns 404. An empty body
// (no fields set) returns 400, matching the CLI.
//
// When the destination, ports, or protocols change, the paired auto-created
// allow rule (tagged with "binding-add:<credential>" or "cred-add:<credential>")
// is updated in lockstep so the binding's network scope matches the rule
// that authorizes it. If no paired rule exists, the binding still updates
// but no fallback rule is created: an operator may have removed the rule
// on purpose, and silently recreating it would mask that decision.
func (s *Server) PatchApiBindingsId(w http.ResponseWriter, r *http.Request, id int64) { //nolint:revive // generated interface name
	var req BindingUpdate
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	// Reject empty updates to align with the CLI, which fails the same way.
	// An empty body previously ran as a no-op because UpdateBinding treats
	// the all-nil options struct as "verify the row exists and return".
	if req.Destination == nil && req.Ports == nil && req.Header == nil &&
		req.Template == nil && req.Protocols == nil && req.EnvVar == nil {
		writeError(w, http.StatusBadRequest, "no fields to update: provide at least one of destination, ports, header, template, protocols, env_var", "")
		return
	}

	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	opts := store.BindingUpdateOpts{
		Destination: req.Destination,
		Ports:       req.Ports,
		Header:      req.Header,
		Template:    req.Template,
		Protocols:   req.Protocols,
		EnvVar:      req.EnvVar,
	}

	// UpdateBindingWithRuleSync runs the read, binding update, and paired
	// rule update in one transaction to eliminate the TOCTOU window. It
	// returns the (pre-update) current binding so we can diff env_var
	// values for the container injection refresh.
	ruleID, ruleFound, current, err := s.store.UpdateBindingWithRuleSync(id, opts)
	if err != nil {
		if errors.Is(err, store.ErrBindingDuplicate) {
			writeError(w, http.StatusConflict, err.Error(), "")
			return
		}
		if errors.Is(err, store.ErrBindingNotFound) {
			writeError(w, http.StatusNotFound, "binding not found", "")
			return
		}
		// Only tagged validation errors map to 400. SQL failures and
		// other internal faults must not masquerade as client errors.
		if errors.Is(err, store.ErrBindingValidation) {
			writeError(w, http.StatusBadRequest, err.Error(), "")
			return
		}
		log.Printf("[ERROR] update binding %d failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, "failed to update binding", "")
		return
	}

	// Track env_var changes so we can refresh the container injection
	// after the update. Clearing env_var on a binding also needs to be
	// propagated to the agent.
	var clearedEnvVars []string
	if req.EnvVar != nil && current.EnvVar != "" && current.EnvVar != *req.EnvVar {
		clearedEnvVars = append(clearedEnvVars, current.EnvVar)
	}

	destChanged := req.Destination != nil && *req.Destination != current.Destination
	portsChanged := req.Ports != nil
	protocolsChanged := req.Protocols != nil
	if destChanged || portsChanged || protocolsChanged {
		if ruleFound {
			log.Printf("[INFO] updated paired allow rule [%d] for binding %d (dest=%v ports=%v protocols=%v)",
				ruleID, id, destChanged, portsChanged, protocolsChanged)
		} else {
			log.Printf("[WARN] no paired allow rule found for credential %q destination %q; binding updated without a matching rule",
				current.Credential, current.Destination)
		}
	}

	// As with PostApiBindings, a failed recompile or resolver rebuild means
	// the client cannot rely on the new binding being active. Return 500 so
	// the caller knows the live engine is out of sync with the store rather
	// than silently logging and claiming success.
	if err := s.recompileEngine(); err != nil {
		log.Printf("[ERROR] recompile engine after binding update failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"binding updated but engine recompile failed: "+err.Error(), "")
		return
	}
	if err := s.rebuildResolver(); err != nil {
		log.Printf("[ERROR] rebuild resolver after binding update failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"binding updated but resolver rebuild failed: "+err.Error(), "")
		return
	}
	if err := s.credMutationComplete(clearedEnvVars...); err != nil {
		log.Printf("[WARN] credential mutation complete after binding update failed: %v", err)
	}

	// Read back the updated binding.
	rows, err := s.store.ListBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back binding", "")
		return
	}
	for _, b := range rows {
		if b.ID == id {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(storeBindingToAPI(b))
			return
		}
	}

	// Should not happen. Fallback.
	writeError(w, http.StatusInternalServerError, "binding disappeared after update", "")
}

// DeleteApiBindingsId removes a credential binding and the auto-created
// allow rule paired with it. Without the paired-rule cleanup, removing a
// binding would leave an orphaned allow rule that silently keeps the
// destination open.
func (s *Server) DeleteApiBindingsId(w http.ResponseWriter, r *http.Request, id int64) { //nolint:revive // generated interface name
	if s.reloadMu != nil {
		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
	}

	// Atomically read the binding, delete it, and clean up the paired
	// auto-created allow rule in one transaction. RemoveBindingWithRuleCleanup
	// closes the TOCTOU window where a concurrent writer could move the
	// binding to a new destination between snapshot and delete and leave an
	// orphaned rule pointing at the previous destination.
	_, _, _, envVar, found, err := s.store.RemoveBindingWithRuleCleanup(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove binding", "")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "binding not found", "")
		return
	}
	var removedEnvVars []string
	if envVar != "" {
		removedEnvVars = append(removedEnvVars, envVar)
	}

	// As with PostApiBindings and PatchApiBindingsId, silently logging a
	// recompile failure on delete would leave stale allow/binding entries
	// in the live engine even though the store has moved on. Surface a 500
	// so the client can retry or alert.
	if err := s.recompileEngine(); err != nil {
		log.Printf("[ERROR] recompile engine after binding remove failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"binding removed but engine recompile failed: "+err.Error(), "")
		return
	}
	if err := s.rebuildResolver(); err != nil {
		log.Printf("[ERROR] rebuild resolver after binding remove failed: %v", err)
		writeError(w, http.StatusInternalServerError,
			"binding removed but resolver rebuild failed: "+err.Error(), "")
		return
	}

	if err := s.credMutationComplete(removedEnvVars...); err != nil {
		log.Printf("[WARN] credential mutation complete after binding remove failed: %v", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- MCP upstream handlers ---

// GetApiMcpUpstreams lists all MCP upstreams.
func (s *Server) GetApiMcpUpstreams(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
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
func (s *Server) PostApiMcpUpstreams(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
	var req CreateMCPUpstreamRequest
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
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
	if req.Transport != nil {
		opts.Transport = *req.Transport
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
			w.Header().Set("X-Sluice-Warning", "restart the MCP gateway for the new upstream to take effect")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(storeMCPUpstreamToAPI(u))
			return
		}
	}

	// Fallback.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Sluice-Warning", "restart the MCP gateway for the new upstream to take effect")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(MCPUpstream{Id: id, Name: req.Name, Command: req.Command})
}

// DeleteApiMcpUpstreamsName removes an MCP upstream by name.
func (s *Server) DeleteApiMcpUpstreamsName(w http.ResponseWriter, r *http.Request, name string) { //nolint:revive // generated interface name
	deleted, err := s.store.RemoveMCPUpstream(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove upstream", "")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "upstream not found", "")
		return
	}
	w.Header().Set("X-Sluice-Warning", "restart the MCP gateway for the removal to take effect")
	w.WriteHeader(http.StatusNoContent)
}

// --- Audit handlers ---

// GetApiAuditRecent returns the last N audit log entries.
func (s *Server) GetApiAuditRecent(w http.ResponseWriter, r *http.Request, params GetApiAuditRecentParams) { //nolint:revive // generated interface name
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
func (s *Server) GetApiAuditVerify(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
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
func (s *Server) GetApiChannels(w http.ResponseWriter, r *http.Request) { //nolint:revive // generated interface name
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
func (s *Server) PatchApiChannelsId(w http.ResponseWriter, r *http.Request, id int64) { //nolint:revive // generated interface name
	var req ChannelUpdate
	if err := json.NewDecoder(limitedBody(w, r)).Decode(&req); err != nil {
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

	// Prevent disabling the last enabled HTTP channel (would lock out the API).
	if req.Enabled != nil && !*req.Enabled && ch.Type == int(channel.ChannelHTTP) && ch.Enabled {
		channels, err := s.store.ListChannels()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to check channels", "")
			return
		}
		httpEnabled := 0
		for _, c := range channels {
			if c.Type == int(channel.ChannelHTTP) && c.Enabled {
				httpEnabled++
			}
		}
		if httpEnabled <= 1 {
			writeError(w, http.StatusConflict, "cannot disable the last enabled HTTP channel", "")
			return
		}
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

// maxRequestBody is the maximum size of a JSON request body (1 MB).
const maxRequestBody = 1 << 20

// limitedBody wraps r.Body with a size limit to prevent memory exhaustion.
func limitedBody(w http.ResponseWriter, r *http.Request) io.ReadCloser {
	return http.MaxBytesReader(w, r.Body, maxRequestBody)
}

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
	if b.EnvVar != "" {
		binding.EnvVar = &b.EnvVar
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
	if u.Transport != "" {
		upstream.Transport = &u.Transport
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
		masked := "***"
		apiCh.WebhookSecret = &masked
	}
	if ch.CreatedAt != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", ch.CreatedAt); err == nil {
			apiCh.CreatedAt = &t
		}
	}
	return apiCh
}

// readRecentAuditEntries reads the last N entries from the audit log file.
// Uses a circular buffer to avoid loading the entire file into memory.
func readRecentAuditEntries(path string, limit int) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Circular buffer: keep only the last N non-empty lines.
	ring := make([][]byte, limit)
	idx := 0
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		ring[idx%limit] = cp
		idx++
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Extract the last N lines in order.
	n := count
	if n > limit {
		n = limit
	}
	recent := make([][]byte, n)
	startIdx := idx - n
	for i := 0; i < n; i++ {
		recent[i] = ring[(startIdx+i)%limit]
	}

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
