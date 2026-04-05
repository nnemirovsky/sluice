package http

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
)

// newTestBroker creates a broker with the given channel for testing.
func newTestBroker(ch channel.Channel) *channel.Broker {
	return channel.NewBroker([]channel.Channel{ch})
}

func TestNewHTTPChannel_RequiresWebhookURL(t *testing.T) {
	_, err := NewHTTPChannel(Config{})
	if err == nil {
		t.Fatal("expected error for empty webhook URL")
	}
}

func TestNewHTTPChannel_Success(t *testing.T) {
	ch, err := NewHTTPChannel(Config{WebhookURL: "http://example.com/hook"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.Type() != channel.ChannelHTTP {
		t.Errorf("got type %v, want %v", ch.Type(), channel.ChannelHTTP)
	}
}

func TestCommands_ReturnsNil(t *testing.T) {
	ch, _ := NewHTTPChannel(Config{WebhookURL: "http://example.com"})
	if ch.Commands() != nil {
		t.Error("expected Commands() to return nil")
	}
}

func TestStartStop(t *testing.T) {
	ch, _ := NewHTTPChannel(Config{WebhookURL: "http://example.com"})
	if err := ch.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	ch.Stop()
	// Calling Stop again should not panic.
	ch.Stop()
}

func TestRequestApproval_SyncPath(t *testing.T) {
	var received WebhookPayload
	var receivedSig string
	secret := "test-secret-123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Sluice-Signature")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)

		// Verify HMAC signature.
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if receivedSig != expectedSig {
			t.Errorf("signature mismatch: got %s, want %s", receivedSig, expectedSig)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "allow_once"})
	}))
	defer srv.Close()

	ch, err := NewHTTPChannel(Config{
		WebhookURL:    srv.URL,
		WebhookSecret: secret,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	// Request approval in background (broker.Request blocks).
	var resp channel.Response
	var reqErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, reqErr = broker.Request("api.github.com", 443, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sync approval")
	}

	if reqErr != nil {
		t.Fatalf("unexpected error: %v", reqErr)
	}
	if resp != channel.ResponseAllowOnce {
		t.Errorf("got response %v, want %v", resp, channel.ResponseAllowOnce)
	}
	if received.ID == "" {
		t.Error("webhook did not receive a request ID")
	}
	if received.Destination != "api.github.com" {
		t.Errorf("got destination %q, want %q", received.Destination, "api.github.com")
	}
	if received.Port != 443 {
		t.Errorf("got port %d, want 443", received.Port)
	}
	if received.Type != "approval" {
		t.Errorf("got type %q, want %q", received.Type, "approval")
	}
}

func TestRequestApproval_SyncAlwaysAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "always_allow"})
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("example.com", 80, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	if resp != channel.ResponseAlwaysAllow {
		t.Errorf("got %v, want %v", resp, channel.ResponseAlwaysAllow)
	}
}

func TestRequestApproval_SyncDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "deny"})
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("example.com", 80, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	if resp != channel.ResponseDeny {
		t.Errorf("got %v, want %v", resp, channel.ResponseDeny)
	}
}

func TestRequestApproval_AsyncPath(t *testing.T) {
	// Webhook returns 202 (accepted). Resolution happens via broker.Resolve externally.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload WebhookPayload
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusAccepted)

		// Simulate async callback: resolve after a short delay.
		go func() {
			time.Sleep(100 * time.Millisecond)
			// In real usage, an external system would POST to /api/approvals/{id}/resolve.
			// Here we simulate by calling broker.Resolve directly.
		}()
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("api.github.com", 443, 5*time.Second)
	}()

	// Give time for the webhook delivery, then resolve externally.
	time.Sleep(200 * time.Millisecond)
	resolved := broker.Resolve("req_1", channel.ResponseAllowOnce)
	if !resolved {
		t.Fatal("expected resolve to succeed")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for async approval")
	}

	if resp != channel.ResponseAllowOnce {
		t.Errorf("got %v, want %v", resp, channel.ResponseAllowOnce)
	}
}

func TestRequestApproval_RetryOnServerError(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Third attempt succeeds.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "allow_once"})
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	ch.baseBackoff = 10 * time.Millisecond // Speed up test.
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("example.com", 443, 10*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}

	if resp != channel.ResponseAllowOnce {
		t.Errorf("got %v, want %v", resp, channel.ResponseAllowOnce)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestRequestApproval_AllRetriesFail(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only count approval delivery attempts, not cancel notifications.
		body, _ := io.ReadAll(r.Body)
		var payload struct{ Type string }
		_ = json.Unmarshal(body, &payload)
		if payload.Type != "cancel" {
			attempts.Add(1)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	ch.baseBackoff = 10 * time.Millisecond
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("example.com", 443, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	// Single-channel setup: delivery failure triggers deny.
	if resp != channel.ResponseDeny {
		t.Errorf("got %v, want %v", resp, channel.ResponseDeny)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestRequestApproval_NoSignatureWithoutSecret(t *testing.T) {
	var receivedSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Sluice-Signature")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "allow_once"})
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = broker.Request("example.com", 80, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	if receivedSig != "" {
		t.Errorf("expected no signature header, got %q", receivedSig)
	}
}

func TestCancelApproval_SendsCancelNotification(t *testing.T) {
	var received CancelPayload
	var mu sync.Mutex
	called := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		_ = json.Unmarshal(body, &received)
		if received.Type == "cancel" {
			called = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})

	// Simulate a pending request.
	ch.pending.Store("req_42", struct{}{})

	err := ch.CancelApproval("req_42")
	if err != nil {
		t.Fatalf("CancelApproval failed: %v", err)
	}

	// Wait for the async POST.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Error("cancel notification was not sent")
	}
	if received.ID != "req_42" {
		t.Errorf("got id %q, want %q", received.ID, "req_42")
	}
}

func TestCancelApproval_SkipsUnknownID(t *testing.T) {
	ch, _ := NewHTTPChannel(Config{WebhookURL: "http://example.com"})
	// No pending request. Should be a no-op.
	err := ch.CancelApproval("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNotify_SendsNotification(t *testing.T) {
	var received NotifyPayload
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	err := ch.Notify(context.Background(), "proxy restarted")
	if err != nil {
		t.Fatalf("Notify failed: %v", err)
	}

	// Wait for async delivery.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if received.Type != "notification" {
		t.Errorf("got type %q, want %q", received.Type, "notification")
	}
	if received.Message != "proxy restarted" {
		t.Errorf("got message %q, want %q", received.Message, "proxy restarted")
	}
}

func TestRequestApproval_InvalidSyncResponse(t *testing.T) {
	// Webhook returns 200 but invalid JSON. The request should time out.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("example.com", 80, 500*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for timeout")
	}

	if resp != channel.ResponseDeny {
		t.Errorf("got %v, want %v (timeout -> deny)", resp, channel.ResponseDeny)
	}
}

func TestRequestApproval_UnknownVerdictDefaultsToDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "maybe"})
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("example.com", 80, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	if resp != channel.ResponseDeny {
		t.Errorf("got %v, want %v", resp, channel.ResponseDeny)
	}
}

func TestRequestApproval_Timeout(t *testing.T) {
	// Webhook returns 202 (async) but no callback ever comes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	var reqErr error
	go func() {
		defer close(done)
		resp, reqErr = broker.Request("example.com", 80, 300*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for broker timeout")
	}

	if reqErr == nil {
		t.Error("expected timeout error")
	}
	if resp != channel.ResponseDeny {
		t.Errorf("got %v, want %v", resp, channel.ResponseDeny)
	}
}

func TestHMACSignature(t *testing.T) {
	body := []byte(`{"id":"test","type":"approval"}`)
	secret := "my-secret"

	sig := computeHMAC(body, secret)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if sig != expected {
		t.Errorf("got %s, want %s", sig, expected)
	}
}

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		input string
		want  channel.Response
	}{
		{"allow_once", channel.ResponseAllowOnce},
		{"always_allow", channel.ResponseAlwaysAllow},
		{"deny", channel.ResponseDeny},
		{"unknown", channel.ResponseDeny},
		{"", channel.ResponseDeny},
	}
	for _, tt := range tests {
		got := parseVerdict(tt.input)
		if got != tt.want {
			t.Errorf("parseVerdict(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestMultiChannelBroadcastWithHTTP verifies that the HTTP channel works alongside
// another channel in a multi-channel broker setup with first-response-wins.
func TestMultiChannelBroadcastWithHTTP(t *testing.T) {
	// Set up an HTTP webhook that returns 202 (async).
	var webhookCalled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookCalled.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	httpCh, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})

	// Create a mock that auto-resolves quickly to simulate Telegram.
	mockCh := &mockResolveChannel{}
	broker := channel.NewBroker([]channel.Channel{mockCh, httpCh})
	httpCh.SetBroker(broker)
	mockCh.broker = broker

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("api.github.com", 443, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	// The mock channel responds first.
	if resp != channel.ResponseAllowOnce {
		t.Errorf("got %v, want AllowOnce", resp)
	}
	// Both channels should have been notified.
	if webhookCalled.Load() == 0 {
		t.Error("HTTP webhook was not called")
	}
}

// mockResolveChannel auto-resolves approval requests for multi-channel testing.
type mockResolveChannel struct {
	broker *channel.Broker
}

func (m *mockResolveChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	go func() {
		time.Sleep(10 * time.Millisecond)
		if m.broker != nil {
			m.broker.Resolve(req.ID, channel.ResponseAllowOnce)
		}
	}()
	return nil
}

func (m *mockResolveChannel) CancelApproval(string) error          { return nil }
func (m *mockResolveChannel) Commands() <-chan channel.Command     { return nil }
func (m *mockResolveChannel) Notify(context.Context, string) error { return nil }
func (m *mockResolveChannel) Start() error                         { return nil }
func (m *mockResolveChannel) Stop()                                {}
func (m *mockResolveChannel) Type() channel.ChannelType            { return channel.ChannelTelegram }

// TestHTTPChannelFromStoreConfig verifies that an HTTP channel can be created
// from store channel config (the same flow as main.go).
func TestHTTPChannelFromStoreConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WebhookResponse{Verdict: "allow_once"})
	}))
	defer srv.Close()

	// Simulate what main.go does: read from store, create channel.
	webhookURL := srv.URL
	webhookSecret := "store-secret"

	ch, err := NewHTTPChannel(Config{
		WebhookURL:    webhookURL,
		WebhookSecret: webhookSecret,
	})
	if err != nil {
		t.Fatalf("create from store config: %v", err)
	}
	if ch.Type() != channel.ChannelHTTP {
		t.Errorf("type = %v, want HTTP", ch.Type())
	}

	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	var resp channel.Response
	go func() {
		defer close(done)
		resp, _ = broker.Request("test.com", 443, 5*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	if resp != channel.ResponseAllowOnce {
		t.Errorf("got %v, want AllowOnce", resp)
	}
}

func TestRequestApproval_StopDuringRetry(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ch, _ := NewHTTPChannel(Config{WebhookURL: srv.URL})
	ch.baseBackoff = 500 * time.Millisecond // Slow enough to interrupt.
	broker := newTestBroker(ch)
	ch.SetBroker(broker)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = broker.Request("example.com", 443, 10*time.Second)
	}()

	// Give time for first attempt, then stop.
	time.Sleep(100 * time.Millisecond)
	ch.Stop()

	// Also cancel broker so the goroutine can finish.
	broker.CancelAll()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stop")
	}

	// Should have attempted at least once but not completed all retries.
	if attempts.Load() < 1 {
		t.Errorf("expected at least 1 attempt, got %d", attempts.Load())
	}
}
