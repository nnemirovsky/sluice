package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/api"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/store"
)

// newTestStore creates an in-memory store for testing.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// enableHTTPChannel inserts an enabled HTTP channel row (type=1) in the store.
func enableHTTPChannel(t *testing.T, st *store.Store) {
	t.Helper()
	if _, err := st.AddChannel(int(channel.ChannelHTTP), true); err != nil {
		t.Fatalf("add http channel: %v", err)
	}
}

// newTestHandler creates a chi handler with auth and channel gate middleware for testing.
// oapi-codegen wraps handlers bottom-up: last middleware in the slice becomes
// outermost. Channel gate goes first (innermost), auth second (outermost),
// so auth rejects before channel gate reveals channel state.
func newTestHandler(t *testing.T, srv *api.Server, st *store.Store) http.Handler {
	t.Helper()
	return api.HandlerWithOptions(srv, api.ChiServerOptions{
		Middlewares: []api.MiddlewareFunc{
			api.ChannelGateMiddleware(st),
			api.BearerAuthMiddleware,
		},
	})
}

// --- Health endpoint tests ---

func TestGetHealthz_ProxyNil(t *testing.T) {
	st := newTestStore(t)
	srv := api.NewServer(st, nil, nil, "")

	// /healthz has no auth requirement, so no middleware needed
	handler := api.Handler(srv)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
	var resp api.HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "not ready" {
		t.Errorf("expected 'not ready', got %q", resp.Status)
	}
}

func TestGetHealthz_NoAuth(t *testing.T) {
	st := newTestStore(t)
	srv := api.NewServer(st, nil, nil, "")

	// /healthz bypasses auth even with middleware
	t.Setenv("SLUICE_API_TOKEN", "test-token")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should work without bearer token
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no proxy), got %d", rec.Code)
	}
}

func TestGetHealthz_BypassesChannelGate(t *testing.T) {
	st := newTestStore(t)
	// No HTTP channel enabled - /healthz should still work
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "test-token")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no proxy), got %d", rec.Code)
	}
}

// --- Auth middleware tests ---

func TestAuth_MissingToken(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "secret")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_WrongToken(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "secret")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_NoEnvVar(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestAuth_ValidToken(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "secret")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAuth_BadTokenBeforeChannelCheck(t *testing.T) {
	// Auth should fail with 401 before channel gate check runs.
	// This ensures bad tokens never reveal whether HTTP channel is enabled.
	st := newTestStore(t)
	// No HTTP channel enabled
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "secret")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should get 401 (auth failure) not 403 (channel disabled)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// --- Channel gate middleware tests ---

func TestChannelGate_Disabled(t *testing.T) {
	st := newTestStore(t)
	// Default store has only Telegram channel (type=0), no HTTP channel
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "secret")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	var resp api.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "HTTP channel is not enabled" {
		t.Errorf("unexpected error: %q", resp.Error)
	}
	if resp.Code == nil || *resp.Code != "channel_disabled" {
		t.Errorf("unexpected code: %v", resp.Code)
	}
}

func TestChannelGate_Enabled(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "secret")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// --- Approval endpoint tests ---

func TestGetApiApprovals_Empty(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	broker := channel.NewBroker(nil)
	srv := api.NewServer(st, broker, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/approvals", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var approvals []api.ApprovalRequest
	if err := json.NewDecoder(rec.Body).Decode(&approvals); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(approvals) != 0 {
		t.Errorf("expected 0 approvals, got %d", len(approvals))
	}
}

func TestGetApiApprovals_NilBroker(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/approvals", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var approvals []api.ApprovalRequest
	if err := json.NewDecoder(rec.Body).Decode(&approvals); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(approvals) != 0 {
		t.Errorf("expected 0 approvals, got %d", len(approvals))
	}
}

func TestGetApiApprovals_WithPending(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	// Create a mock channel that does nothing (just satisfies the interface)
	mockCh := &mockChannel{}
	broker := channel.NewBroker([]channel.Channel{mockCh})
	srv := api.NewServer(st, broker, nil, "")

	// Fire a request in a goroutine (blocks until resolved or timeout)
	go func() {
		_, _ = broker.Request("api.github.com", 443, 30*time.Second)
	}()

	// Wait briefly for the request to register
	time.Sleep(50 * time.Millisecond)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/approvals", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var approvals []api.ApprovalRequest
	if err := json.NewDecoder(rec.Body).Decode(&approvals); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(approvals) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(approvals))
	}
	if approvals[0].Destination != "api.github.com" {
		t.Errorf("expected destination api.github.com, got %q", approvals[0].Destination)
	}
	if approvals[0].Port != 443 {
		t.Errorf("expected port 443, got %d", approvals[0].Port)
	}

	// Clean up: resolve the pending request so the goroutine exits
	broker.Resolve(approvals[0].Id, channel.ResponseDeny)
}

// --- Resolve endpoint tests ---

func TestPostResolve_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	mockCh := &mockChannel{}
	broker := channel.NewBroker([]channel.Channel{mockCh})
	srv := api.NewServer(st, broker, nil, "")

	// Create a pending request
	resultCh := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request("example.com", 443, 30*time.Second)
		resultCh <- resp
	}()
	time.Sleep(50 * time.Millisecond)

	pending := broker.PendingRequests()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "allow_once"}`
	req := httptest.NewRequest("POST", "/api/approvals/"+pending[0].ID+"/resolve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp api.ResolveResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Verdict != "allow_once" {
		t.Errorf("expected allow_once, got %q", resp.Verdict)
	}

	// Verify the broker actually resolved the request
	select {
	case r := <-resultCh:
		if r != channel.ResponseAllowOnce {
			t.Errorf("expected AllowOnce, got %v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resolution")
	}
}

func TestPostResolve_NotFound(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	broker := channel.NewBroker(nil)
	srv := api.NewServer(st, broker, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "deny"}`
	req := httptest.NewRequest("POST", "/api/approvals/nonexistent/resolve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestPostResolve_InvalidVerdict(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	broker := channel.NewBroker(nil)
	srv := api.NewServer(st, broker, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "invalid"}`
	req := httptest.NewRequest("POST", "/api/approvals/req_1/resolve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestPostResolve_NoBroker(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "deny"}`
	req := httptest.NewRequest("POST", "/api/approvals/req_1/resolve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestPostResolve_AlwaysAllow(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	mockCh := &mockChannel{}
	broker := channel.NewBroker([]channel.Channel{mockCh})
	srv := api.NewServer(st, broker, nil, "")

	resultCh := make(chan channel.Response, 1)
	go func() {
		resp, _ := broker.Request("example.com", 443, 30*time.Second)
		resultCh <- resp
	}()
	time.Sleep(50 * time.Millisecond)

	pending := broker.PendingRequests()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "always_allow"}`
	req := httptest.NewRequest("POST", "/api/approvals/"+pending[0].ID+"/resolve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	select {
	case r := <-resultCh:
		if r != channel.ResponseAlwaysAllow {
			t.Errorf("expected AlwaysAllow, got %v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resolution")
	}
}

// --- Status endpoint tests ---

func TestGetStatus_NoBroker(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var status api.StatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status.ProxyListening {
		t.Error("proxy should not be listening (nil)")
	}
	if status.PendingApprovals != 0 {
		t.Errorf("expected 0 pending, got %d", status.PendingApprovals)
	}
	if len(status.Channels) != 0 {
		t.Errorf("expected 0 channels, got %d", len(status.Channels))
	}
}

func TestGetStatus_WithBroker(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	mockCh := &mockChannel{chType: channel.ChannelTelegram}
	broker := channel.NewBroker([]channel.Channel{mockCh})
	srv := api.NewServer(st, broker, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var status api.StatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(status.Channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(status.Channels))
	}
	if status.Channels[0].Type != api.ChannelStatusTypeTelegram {
		t.Errorf("expected telegram, got %q", status.Channels[0].Type)
	}
	if !status.Channels[0].Enabled {
		t.Error("channel should be enabled")
	}
}

// --- mockChannel implements channel.Channel for testing ---

type mockChannel struct {
	chType channel.ChannelType
}

func (m *mockChannel) RequestApproval(_ context.Context, _ channel.ApprovalRequest) error {
	return nil
}
func (m *mockChannel) CancelApproval(_ string) error        { return nil }
func (m *mockChannel) Commands() <-chan channel.Command      { return nil }
func (m *mockChannel) Notify(_ context.Context, _ string) error { return nil }
func (m *mockChannel) Start() error                          { return nil }
func (m *mockChannel) Stop()                                 {}
func (m *mockChannel) Type() channel.ChannelType             { return m.chType }

// --- Rule management handler tests ---

func TestGetApiRules_Empty(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/rules", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var rules []api.Rule
	if err := json.NewDecoder(rec.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestGetApiRules_WithFilter(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	// Add rules of different types.
	if _, err := st.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Name: "test allow"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if _, err := st.AddRule("deny", store.RuleOpts{Destination: "evil.com"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if _, err := st.AddRule("allow", store.RuleOpts{Tool: "github__list_*", Name: "read-only github"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	// Filter by verdict=allow.
	req := httptest.NewRequest("GET", "/api/rules?verdict=allow", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var rules []api.Rule
	if err := json.NewDecoder(rec.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 allow rules, got %d", len(rules))
	}

	// Filter by type=network.
	req = httptest.NewRequest("GET", "/api/rules?type=network", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rules = nil
	if err := json.NewDecoder(rec.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 network rules, got %d", len(rules))
	}

	// Filter by verdict=allow and type=tool.
	req = httptest.NewRequest("GET", "/api/rules?verdict=allow&type=tool", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rules = nil
	if err := json.NewDecoder(rec.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow+tool rule, got %d", len(rules))
	}
	if rules[0].Tool == nil || *rules[0].Tool != "github__list_*" {
		t.Errorf("expected tool github__list_*, got %v", rules[0].Tool)
	}
}

func TestPostApiRules_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "allow", "destination": "api.example.com", "ports": [443], "name": "test rule"}`
	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var rule api.Rule
	if err := json.NewDecoder(rec.Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Verdict != "allow" {
		t.Errorf("expected allow, got %q", rule.Verdict)
	}
	if rule.Destination == nil || *rule.Destination != "api.example.com" {
		t.Errorf("expected api.example.com, got %v", rule.Destination)
	}
	if rule.Ports == nil || len(*rule.Ports) != 1 || (*rule.Ports)[0] != 443 {
		t.Errorf("expected ports [443], got %v", rule.Ports)
	}
	if rule.Source == nil || *rule.Source != "api" {
		t.Errorf("expected source api, got %v", rule.Source)
	}
}

func TestPostApiRules_ToolRule(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "deny", "tool": "exec__*", "name": "block exec"}`
	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var rule api.Rule
	if err := json.NewDecoder(rec.Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Tool == nil || *rule.Tool != "exec__*" {
		t.Errorf("expected tool exec__*, got %v", rule.Tool)
	}
}

func TestPostApiRules_InvalidVerdict(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "nope", "destination": "example.com"}`
	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestPostApiRules_NoTarget(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"verdict": "allow"}`
	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteApiRules_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	id, err := st.AddRule("allow", store.RuleOpts{Destination: "example.com"})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/rules/%d", id), nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify rule is gone.
	rules, err := st.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(rules))
	}
}

func TestDeleteApiRules_NotFound(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", "/api/rules/999", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestPostApiRulesImport(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	tomlData := `[[allow]]
destination = "api.example.com"
ports = [443]
name = "test allow"

[[deny]]
destination = "evil.com"
`

	// Build multipart form.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "config.toml")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte(tomlData)); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	writer.Close()

	req := httptest.NewRequest("POST", "/api/rules/import", &buf)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result api.ImportResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.RulesInserted != 2 {
		t.Errorf("expected 2 rules inserted, got %d", result.RulesInserted)
	}
}

func TestPostApiRulesImport_InvalidTOML(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "bad.toml")
	part.Write([]byte("this is not valid [[[ toml"))
	writer.Close()

	req := httptest.NewRequest("POST", "/api/rules/import", &buf)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetApiRulesExport(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	// Add some rules.
	if _, err := st.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "example"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if _, err := st.AddRule("deny", store.RuleOpts{Tool: "exec__*"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/rules/export", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/toml" {
		t.Errorf("expected Content-Type application/toml, got %q", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `destination = "api.example.com"`) {
		t.Errorf("export missing expected destination, got:\n%s", body)
	}
	if !strings.Contains(body, `tool = "exec__*"`) {
		t.Errorf("export missing expected tool, got:\n%s", body)
	}
	if !strings.Contains(body, "[[allow]]") {
		t.Errorf("export missing [[allow]] section, got:\n%s", body)
	}
	if !strings.Contains(body, "[[deny]]") {
		t.Errorf("export missing [[deny]] section, got:\n%s", body)
	}
}

func TestGetApiRulesExport_Roundtrip(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	// Add rules of various types.
	if _, err := st.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if _, err := st.AddRule("deny", store.RuleOpts{Destination: "evil.com"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	// Export.
	req := httptest.NewRequest("GET", "/api/rules/export", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d", rec.Code)
	}
	exportedTOML := rec.Body.Bytes()

	// Import into a separate store (temp file, not :memory: which is shared).
	tmpDB := filepath.Join(t.TempDir(), "roundtrip.db")
	st2, err := store.New(tmpDB)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer st2.Close()

	result, err := st2.ImportTOML(exportedTOML)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if result.RulesInserted != 2 {
		t.Errorf("expected 2 rules re-imported, got %d (skipped=%d)", result.RulesInserted, result.RulesSkipped)
	}
}

// --- Config handler tests ---

func TestGetApiConfig(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/config", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var cfg api.Config
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Default store has default_verdict="deny" and timeout_sec=120.
	if cfg.DefaultVerdict == nil || string(*cfg.DefaultVerdict) != "deny" {
		t.Errorf("expected default_verdict deny, got %v", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec == nil || *cfg.TimeoutSec != 120 {
		t.Errorf("expected timeout_sec 120, got %v", cfg.TimeoutSec)
	}
}

func TestPatchApiConfig_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"default_verdict": "deny", "timeout_sec": 60}`
	req := httptest.NewRequest("PATCH", "/api/config", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var cfg api.Config
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.DefaultVerdict == nil || string(*cfg.DefaultVerdict) != "deny" {
		t.Errorf("expected deny, got %v", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec == nil || *cfg.TimeoutSec != 60 {
		t.Errorf("expected 60, got %v", cfg.TimeoutSec)
	}
}

func TestPatchApiConfig_InvalidVerdict(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"default_verdict": "invalid"}`
	req := httptest.NewRequest("PATCH", "/api/config", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPatchApiConfig_PartialUpdate(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	// Update only timeout, leave verdict unchanged.
	body := `{"timeout_sec": 30}`
	req := httptest.NewRequest("PATCH", "/api/config", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var cfg api.Config
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Verdict should still be default "deny".
	if cfg.DefaultVerdict == nil || string(*cfg.DefaultVerdict) != "deny" {
		t.Errorf("expected default_verdict deny (unchanged), got %v", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec == nil || *cfg.TimeoutSec != 30 {
		t.Errorf("expected timeout_sec 30, got %v", cfg.TimeoutSec)
	}
}
