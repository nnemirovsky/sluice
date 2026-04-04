package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/api"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
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

	body := `{"default_verdict": "ask", "timeout_sec": 60}`
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
	if cfg.DefaultVerdict == nil || string(*cfg.DefaultVerdict) != "ask" {
		t.Errorf("expected ask, got %v", cfg.DefaultVerdict)
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

// --- Credential handler tests ---

func newTestVault(t *testing.T) *vault.Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	return v
}

func TestGetApiCredentials_Empty(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	v := newTestVault(t)
	srv := api.NewServer(st, nil, nil, "")
	srv.SetVault(v)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/credentials", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var creds []api.Credential
	if err := json.NewDecoder(rec.Body).Decode(&creds); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}

func TestGetApiCredentials_NoVault(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/credentials", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestPostApiCredentials_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	v := newTestVault(t)
	srv := api.NewServer(st, nil, nil, "")
	srv.SetVault(v)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"name": "my_key", "value": "secret-value-123"}`
	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var cred api.Credential
	if err := json.NewDecoder(rec.Body).Decode(&cred); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cred.Name != "my_key" {
		t.Errorf("expected name my_key, got %q", cred.Name)
	}

	// Verify it's in the vault.
	names, err := v.List()
	if err != nil {
		t.Fatalf("list vault: %v", err)
	}
	if len(names) != 1 || names[0] != "my_key" {
		t.Errorf("expected vault to contain my_key, got %v", names)
	}
}

func TestPostApiCredentials_WithDestination(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	v := newTestVault(t)
	srv := api.NewServer(st, nil, nil, "")
	srv.SetVault(v)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"name": "api_key", "value": "secret", "destination": "api.example.com", "ports": [443], "header": "Authorization", "template": "Bearer {value}"}`
	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify rule was created.
	rules, err := st.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.example.com" {
		t.Errorf("expected destination api.example.com, got %q", rules[0].Destination)
	}

	// Verify binding was created.
	bindings, err := st.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Credential != "api_key" {
		t.Errorf("expected credential api_key, got %q", bindings[0].Credential)
	}
}

func TestPostApiCredentials_Duplicate(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	v := newTestVault(t)
	srv := api.NewServer(st, nil, nil, "")
	srv.SetVault(v)

	// Add the credential first.
	if _, err := v.Add("my_key", "value"); err != nil {
		t.Fatalf("add: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"name": "my_key", "value": "new-value"}`
	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteApiCredentials_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	v := newTestVault(t)
	srv := api.NewServer(st, nil, nil, "")
	srv.SetVault(v)

	// Add a credential with a binding.
	if _, err := v.Add("my_key", "value"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := st.AddBinding("api.example.com", "my_key", store.BindingOpts{}); err != nil {
		t.Fatalf("add binding: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", "/api/credentials/my_key", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify credential is gone.
	names, err := v.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected 0 credentials, got %v", names)
	}

	// Verify binding is gone.
	bindings, err := st.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(bindings))
	}
}

func TestDeleteApiCredentials_NotFound(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	v := newTestVault(t)
	srv := api.NewServer(st, nil, nil, "")
	srv.SetVault(v)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", "/api/credentials/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// --- Binding handler tests ---

func TestGetApiBindings_Empty(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/bindings", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var bindings []api.Binding
	if err := json.NewDecoder(rec.Body).Decode(&bindings); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(bindings))
	}
}

func TestPostApiBindings_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"destination": "api.example.com", "credential": "my_key", "ports": [443], "header": "Authorization", "template": "Bearer {value}"}`
	req := httptest.NewRequest("POST", "/api/bindings", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var binding api.Binding
	if err := json.NewDecoder(rec.Body).Decode(&binding); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if binding.Destination != "api.example.com" {
		t.Errorf("expected api.example.com, got %q", binding.Destination)
	}
	if binding.Credential != "my_key" {
		t.Errorf("expected my_key, got %q", binding.Credential)
	}
	if binding.Header == nil || *binding.Header != "Authorization" {
		t.Errorf("expected header Authorization, got %v", binding.Header)
	}
}

func TestPostApiBindings_MissingFields(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"destination": "api.example.com"}`
	req := httptest.NewRequest("POST", "/api/bindings", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteApiBindings_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	id, err := st.AddBinding("api.example.com", "my_key", store.BindingOpts{})
	if err != nil {
		t.Fatalf("add binding: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/bindings/%d", id), nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify it's gone.
	bindings, err := st.ListBindings()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(bindings))
	}
}

func TestDeleteApiBindings_NotFound(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", "/api/bindings/999", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// --- MCP upstream handler tests ---

func TestGetApiMcpUpstreams_Empty(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/mcp/upstreams", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var upstreams []api.MCPUpstream
	if err := json.NewDecoder(rec.Body).Decode(&upstreams); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(upstreams) != 0 {
		t.Errorf("expected 0 upstreams, got %d", len(upstreams))
	}
}

func TestPostApiMcpUpstreams_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"name": "github", "command": "/usr/bin/mcp-server-github", "args": ["--token", "test"], "timeout_sec": 60}`
	req := httptest.NewRequest("POST", "/api/mcp/upstreams", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var upstream api.MCPUpstream
	if err := json.NewDecoder(rec.Body).Decode(&upstream); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if upstream.Name != "github" {
		t.Errorf("expected name github, got %q", upstream.Name)
	}
	if upstream.Command != "/usr/bin/mcp-server-github" {
		t.Errorf("expected command, got %q", upstream.Command)
	}
	if upstream.TimeoutSec == nil || *upstream.TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %v", upstream.TimeoutSec)
	}
}

func TestPostApiMcpUpstreams_Duplicate(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	if _, err := st.AddMCPUpstream("github", "/usr/bin/mcp", store.MCPUpstreamOpts{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"name": "github", "command": "/usr/bin/mcp"}`
	req := httptest.NewRequest("POST", "/api/mcp/upstreams", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteApiMcpUpstreams_Success(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	if _, err := st.AddMCPUpstream("github", "/usr/bin/mcp", store.MCPUpstreamOpts{}); err != nil {
		t.Fatalf("add: %v", err)
	}

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", "/api/mcp/upstreams/github", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify it's gone.
	upstreams, err := st.ListMCPUpstreams()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(upstreams) != 0 {
		t.Errorf("expected 0 upstreams, got %d", len(upstreams))
	}
}

func TestDeleteApiMcpUpstreams_NotFound(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("DELETE", "/api/mcp/upstreams/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// --- Audit handler tests ---

func TestGetApiAuditRecent_NoPath(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/audit/recent", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var entries []api.AuditEntry
	if err := json.NewDecoder(rec.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestGetApiAuditRecent_WithEntries(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	// Create an audit log with some entries.
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := logger.Log(audit.Event{
			Destination: fmt.Sprintf("host%d.com", i),
			Port:        443,
			Verdict:     "allow",
		}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	logger.Close()

	srv := api.NewServer(st, nil, nil, logPath)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	// Request with limit=3.
	req := httptest.NewRequest("GET", "/api/audit/recent?limit=3", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var entries []api.AuditEntry
	if err := json.NewDecoder(rec.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Should be the last 3 entries.
	if entries[0].Destination == nil || *entries[0].Destination != "host2.com" {
		t.Errorf("expected host2.com, got %v", entries[0].Destination)
	}
	if entries[2].Destination == nil || *entries[2].Destination != "host4.com" {
		t.Errorf("expected host4.com, got %v", entries[2].Destination)
	}
}

func TestGetApiAuditRecent_MissingFile(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "/tmp/nonexistent-audit-file.jsonl")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/audit/recent", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (empty array), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetApiAuditVerify_NoPath(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result api.VerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.TotalLines != 0 {
		t.Errorf("expected 0 total lines, got %d", result.TotalLines)
	}
}

func TestGetApiAuditVerify_ValidChain(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.Log(audit.Event{
			Destination: "example.com",
			Verdict:     "allow",
		}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	logger.Close()

	srv := api.NewServer(st, nil, nil, logPath)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result api.VerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.TotalLines != 3 {
		t.Errorf("expected 3 total lines, got %d", result.TotalLines)
	}
	if result.ValidLinks != 3 {
		t.Errorf("expected 3 valid links, got %d", result.ValidLinks)
	}
	if len(result.BrokenLinks) != 0 {
		t.Errorf("expected 0 broken links, got %d", len(result.BrokenLinks))
	}
}

func TestGetApiAuditVerify_BrokenChain(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)

	// Write a log file with a tampered line.
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	if err := logger.Log(audit.Event{Destination: "a.com", Verdict: "allow"}); err != nil {
		t.Fatalf("log: %v", err)
	}
	logger.Close()

	// Append a line with a wrong prev_hash.
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	f.WriteString(`{"timestamp":"2026-01-01T00:00:00Z","prev_hash":"badhash","destination":"b.com","verdict":"deny"}` + "\n")
	f.Close()

	srv := api.NewServer(st, nil, nil, logPath)

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result api.VerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.BrokenLinks) != 1 {
		t.Errorf("expected 1 broken link, got %d", len(result.BrokenLinks))
	}
}

// --- Channel handler tests ---

func TestGetApiChannels(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	req := httptest.NewRequest("GET", "/api/channels", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var channels []api.Channel
	if err := json.NewDecoder(rec.Body).Decode(&channels); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Should have at least the HTTP channel we added.
	found := false
	for _, ch := range channels {
		if ch.Type == api.ChannelTypeHttp && ch.Enabled {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find enabled HTTP channel, got %v", channels)
	}
}

func TestPatchApiChannels_Disable(t *testing.T) {
	st := newTestStore(t)
	chID, err := st.AddChannel(int(channel.ChannelHTTP), true)
	if err != nil {
		t.Fatalf("add channel: %v", err)
	}
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"enabled": false}`
	req := httptest.NewRequest("PATCH", fmt.Sprintf("/api/channels/%d", chID), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var ch api.Channel
	if err := json.NewDecoder(rec.Body).Decode(&ch); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ch.Enabled {
		t.Error("expected channel to be disabled")
	}

	// Verify in store.
	stored, err := st.GetChannel(chID)
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if stored.Enabled {
		t.Error("expected stored channel to be disabled")
	}
}

func TestPatchApiChannels_NotFound(t *testing.T) {
	st := newTestStore(t)
	enableHTTPChannel(t, st)
	srv := api.NewServer(st, nil, nil, "")

	t.Setenv("SLUICE_API_TOKEN", "tok")
	handler := newTestHandler(t, srv, st)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PATCH", "/api/channels/999", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}
