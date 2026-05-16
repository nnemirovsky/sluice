package channel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// result bundles a Broker.Request return for fan-in over a channel in
// concurrency tests.
type result struct {
	resp Response
	err  error
}

// mockChannel implements Channel for testing.
type mockChannel struct {
	typ         ChannelType
	requests    []ApprovalRequest
	cancelled   []string
	mu          sync.Mutex
	onRequest   func(ApprovalRequest)
	commandsCh  chan Command
	notifyMsgs  []string
	requestErr  error
	cancelErr   error
	startCalled bool
	stopCalled  bool
}

func newMockChannel(typ ChannelType) *mockChannel {
	return &mockChannel{typ: typ}
}

func (m *mockChannel) RequestApproval(_ context.Context, req ApprovalRequest) error {
	m.mu.Lock()
	m.requests = append(m.requests, req)
	cb := m.onRequest
	err := m.requestErr
	m.mu.Unlock()
	if cb != nil {
		cb(req)
	}
	return err
}

func (m *mockChannel) CancelApproval(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelled = append(m.cancelled, id)
	return m.cancelErr
}

func (m *mockChannel) Commands() <-chan Command {
	return m.commandsCh
}

func (m *mockChannel) Notify(_ context.Context, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifyMsgs = append(m.notifyMsgs, msg)
	return nil
}

func (m *mockChannel) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = true
	return nil
}

func (m *mockChannel) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled = true
}

func (m *mockChannel) Type() ChannelType {
	return m.typ
}

func (m *mockChannel) getRequests() []ApprovalRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ApprovalRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *mockChannel) getCancelled() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.cancelled))
	copy(out, m.cancelled)
	return out
}

// --- ChannelType tests ---

func TestChannelTypeString(t *testing.T) {
	tests := []struct {
		ct   ChannelType
		want string
	}{
		{ChannelTelegram, "telegram"},
		{ChannelHTTP, "http"},
		{ChannelType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("ChannelType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

// --- Response tests ---

func TestResponseString(t *testing.T) {
	tests := []struct {
		r    Response
		want string
	}{
		{ResponseAllowOnce, "allow_once"},
		{ResponseAlwaysAllow, "always_allow"},
		{ResponseDeny, "deny"},
		{Response(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("Response(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

// --- Request options tests ---

func TestWithMethodAndPath(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	var broker *Broker
	ch.onRequest = func(req ApprovalRequest) {
		go func() {
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}
	broker = NewBroker([]Channel{ch})

	_, err := broker.Request("api.example.com", 443, "https", 5*time.Second,
		WithMethodAndPath("POST", "/v1/users"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	reqs := ch.getRequests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Method != "POST" {
		t.Errorf("method: got %q, want %q", reqs[0].Method, "POST")
	}
	if reqs[0].Path != "/v1/users" {
		t.Errorf("path: got %q, want %q", reqs[0].Path, "/v1/users")
	}
}

func TestWithMethodAndPathEmpty(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	var broker *Broker
	ch.onRequest = func(req ApprovalRequest) {
		go func() {
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}
	broker = NewBroker([]Channel{ch})

	// Connection-level approval without the option -> method/path should remain empty.
	_, err := broker.Request("api.example.com", 443, "https", 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	reqs := ch.getRequests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Method != "" || reqs[0].Path != "" {
		t.Errorf("expected empty method/path, got method=%q path=%q", reqs[0].Method, reqs[0].Path)
	}
}

// --- Broker broadcast tests ---

func TestBrokerBroadcastToAllChannels(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)

	// Auto-resolve from ch1 when it receives the request.
	var broker *Broker
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}

	broker = NewBroker([]Channel{ch1, ch2})

	resp, err := broker.Request("evil.com", 443, "", 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp != ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}

	// Both channels should have received the request.
	if len(ch1.getRequests()) != 1 {
		t.Errorf("ch1 should have received 1 request, got %d", len(ch1.getRequests()))
	}
	if len(ch2.getRequests()) != 1 {
		t.Errorf("ch2 should have received 1 request, got %d", len(ch2.getRequests()))
	}
}

func TestBrokerFirstResponseWins(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)

	var broker *Broker
	// ch1 responds AllowOnce after 5ms.
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}
	// ch2 responds Deny after 50ms. Should lose the race.
	ch2.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			broker.Resolve(req.ID, ResponseDeny)
		}()
	}

	broker = NewBroker([]Channel{ch1, ch2})

	resp, err := broker.Request("evil.com", 443, "", 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp != ResponseAllowOnce {
		t.Errorf("first response should win: expected AllowOnce, got %v", resp)
	}
}

// --- Cross-channel cancellation tests ---

func TestBrokerCancelOnOtherChannels(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)

	var broker *Broker
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}

	broker = NewBroker([]Channel{ch1, ch2})

	_, err := broker.Request("evil.com", 443, "", 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Give a moment for the cancel to propagate.
	time.Sleep(20 * time.Millisecond)

	// Both channels should get CancelApproval after resolution.
	ch1Cancelled := ch1.getCancelled()
	ch2Cancelled := ch2.getCancelled()
	if len(ch1Cancelled) == 0 {
		t.Error("ch1 should have received CancelApproval")
	}
	if len(ch2Cancelled) == 0 {
		t.Error("ch2 should have received CancelApproval")
	}
}

// --- Race condition: two channels resolve simultaneously ---

func TestBrokerSimultaneousResolve(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)

	var broker *Broker
	var resolveResults [2]bool
	var resolveWg sync.WaitGroup
	resolveWg.Add(2)

	// Both channels try to resolve at the same time.
	ready := make(chan struct{})
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			<-ready
			resolveResults[0] = broker.Resolve(req.ID, ResponseAllowOnce)
			resolveWg.Done()
		}()
	}
	ch2.onRequest = func(req ApprovalRequest) {
		go func() {
			<-ready
			resolveResults[1] = broker.Resolve(req.ID, ResponseDeny)
			resolveWg.Done()
		}()
	}

	broker = NewBroker([]Channel{ch1, ch2})

	done := make(chan struct{})
	var resp Response
	go func() {
		resp, _ = broker.Request("evil.com", 443, "", 5*time.Second)
		close(done)
	}()

	// Wait for request to be registered.
	for broker.PendingCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	// Release both resolvers simultaneously.
	close(ready)
	resolveWg.Wait()
	<-done

	// Exactly one should have won.
	wins := 0
	if resolveResults[0] {
		wins++
	}
	if resolveResults[1] {
		wins++
	}
	if wins != 1 {
		t.Errorf("expected exactly 1 winner, got %d", wins)
	}

	// Response should be from the winner.
	if resp != ResponseAllowOnce && resp != ResponseDeny {
		t.Errorf("unexpected response: %v", resp)
	}
}

// --- Rate limiting tests (moved from telegram.ApprovalBroker) ---

func TestBrokerPendingLimitExceeded(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1}, WithMaxPending(3))

	// Fill up the pending slots by sending requests that won't be resolved.
	// Distinct destinations so each opens its own waiter (same-dest:port
	// requests now coalesce onto a single waiter by design).
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		dest := fmt.Sprintf("example-%d.com", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = broker.Request(dest, 443, "", 2*time.Second)
		}()
	}
	// Wait until all 3 are registered as waiters.
	for broker.PendingCount() < 3 {
		time.Sleep(time.Millisecond)
	}

	// The 4th request should be auto-denied.
	resp, err := broker.Request("example.com", 443, "", time.Second)
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
	if !errors.Is(err, ErrPendingLimitExceeded) {
		t.Errorf("expected ErrPendingLimitExceeded, got %v", err)
	}

	// Resolve pending to unblock goroutines.
	ch1.mu.Lock()
	reqs := make([]ApprovalRequest, len(ch1.requests))
	copy(reqs, ch1.requests)
	ch1.mu.Unlock()
	for _, req := range reqs {
		broker.Resolve(req.ID, ResponseDeny)
	}
	wg.Wait()
}

func TestBrokerPendingLimitZeroMeansUnlimited(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)

	var broker *Broker
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(time.Millisecond)
			broker.Resolve(req.ID, ResponseDeny)
		}()
	}

	broker = NewBroker(
		[]Channel{ch1},
		WithMaxPending(0),
		WithDestinationRateLimit(0, 0),
	)

	// Should accept many requests without hitting any pending limit.
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := broker.Request("example.com", 443, "", 5*time.Second)
			if errors.Is(err, ErrPendingLimitExceeded) {
				t.Error("should not hit pending limit with MaxPending=0")
			}
		}()
	}
	wg.Wait()
}

func TestBrokerDestinationRateLimiting(t *testing.T) {
	fakeNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ch1 := newMockChannel(ChannelTelegram)

	var broker *Broker
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}

	broker = NewBroker(
		[]Channel{ch1},
		WithMaxPending(0),
		WithDestinationRateLimit(3, time.Minute),
	)
	broker.nowFunc = func() time.Time { return fakeNow }

	// First 3 requests to the same destination should succeed.
	for i := 0; i < 3; i++ {
		_, err := broker.Request("api.example.com", 443, "", time.Second)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}

	// 4th request within the same window should be rate limited.
	resp, err := broker.Request("api.example.com", 443, "", time.Second)
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
	if !errors.Is(err, ErrDestinationRateLimited) {
		t.Errorf("expected ErrDestinationRateLimited, got %v", err)
	}

	// A different destination should still work.
	_, err = broker.Request("other.example.com", 443, "", time.Second)
	if err != nil {
		t.Fatalf("different destination should not be rate limited: %v", err)
	}

	// Advance time past the window. The original destination should work again.
	fakeNow = fakeNow.Add(61 * time.Second)
	_, err = broker.Request("api.example.com", 443, "", time.Second)
	if err != nil {
		t.Fatalf("after window expiry, request should succeed: %v", err)
	}
}

func TestBrokerDestinationRateLimitDisabled(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)

	var broker *Broker
	ch1.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}

	broker = NewBroker(
		[]Channel{ch1},
		WithMaxPending(0),
		WithDestinationRateLimit(0, 0),
	)

	// Should accept many requests without rate limiting.
	for i := 0; i < 20; i++ {
		_, err := broker.Request("api.example.com", 443, "", time.Second)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}
}

// --- CancelAll tests ---

func TestBrokerCancelAllDeniesAllPending(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1})

	const n = 5
	type result struct {
		resp Response
		err  error
	}
	results := make(chan result, n)

	// Start n requests that will block waiting for approval. Distinct
	// destinations so each registers its own waiter (same-dest:port
	// requests now coalesce by design).
	for i := 0; i < n; i++ {
		dest := fmt.Sprintf("cancel-test-%d.com", i)
		go func() {
			resp, err := broker.Request(dest, 443, "", 5*time.Second)
			results <- result{resp, err}
		}()
	}

	// Wait for all requests to be registered as waiters.
	for broker.PendingCount() < n {
		time.Sleep(time.Millisecond)
	}

	broker.CancelAll()

	// All requests should complete with Deny and no error.
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("request %d: unexpected error: %v", i, r.err)
		}
		if r.resp != ResponseDeny {
			t.Errorf("request %d: expected Deny, got %v", i, r.resp)
		}
	}

	if broker.PendingCount() != 0 {
		t.Errorf("expected 0 pending after CancelAll, got %d", broker.PendingCount())
	}
}

func TestBrokerCancelAllRejectsNewRequests(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1}, WithMaxPending(0))

	broker.CancelAll()

	start := time.Now()
	resp, err := broker.Request("post-cancel.com", 443, "", 5*time.Second)
	elapsed := time.Since(start)

	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
	if err == nil {
		t.Fatal("expected error from post-CancelAll request")
	}
	// Should return almost immediately, not wait for the 5s timeout.
	if elapsed > 500*time.Millisecond {
		t.Errorf("Request after CancelAll took %v; expected prompt return", elapsed)
	}
}

func TestBrokerCancelAllCallsCancelOnChannels(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)
	broker := NewBroker([]Channel{ch1, ch2})

	// Send a request that blocks.
	go func() {
		_, _ = broker.Request("test.com", 443, "", 5*time.Second)
	}()

	// Wait for it to register.
	for broker.PendingCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	broker.CancelAll()

	// Give cancellations time to propagate.
	time.Sleep(20 * time.Millisecond)

	// Both channels should have received CancelApproval.
	if len(ch1.getCancelled()) == 0 {
		t.Error("ch1 should have received CancelApproval during CancelAll")
	}
	if len(ch2.getCancelled()) == 0 {
		t.Error("ch2 should have received CancelApproval during CancelAll")
	}
}

// --- Timeout test ---

func TestBrokerTimeout(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1})

	resp, err := broker.Request("slow.com", 443, "", 50*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error, got response %v", resp)
	}
	if resp != ResponseDeny {
		t.Errorf("expected ResponseDeny on timeout, got %v", resp)
	}
}

func TestBrokerTimeoutCallsCancelOnChannels(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)
	broker := NewBroker([]Channel{ch1, ch2})

	_, _ = broker.Request("slow.com", 443, "", 50*time.Millisecond)

	// Give cancellations time to propagate.
	time.Sleep(20 * time.Millisecond)

	if len(ch1.getCancelled()) == 0 {
		t.Error("ch1 should have received CancelApproval on timeout")
	}
	if len(ch2.getCancelled()) == 0 {
		t.Error("ch2 should have received CancelApproval on timeout")
	}
}

// --- No channels test ---

func TestBrokerNoChannelsTimesOut(t *testing.T) {
	broker := NewBroker(nil)

	resp, err := broker.Request("no-channels.com", 443, "", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error with no channels")
	}
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
}

// --- HasWaiter / WasTimedOut tests ---

func TestBrokerHasWaiterAndTimedOut(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1})

	var reqID atomic.Value
	ch1.onRequest = func(req ApprovalRequest) {
		reqID.Store(req.ID)
	}

	done := make(chan struct{})
	go func() {
		_, _ = broker.Request("test.com", 443, "", 50*time.Millisecond)
		close(done)
	}()

	// Wait for the request to be registered.
	for broker.PendingCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	id := reqID.Load().(string)
	if !broker.HasWaiter(id) {
		t.Error("expected HasWaiter to return true for pending request")
	}

	<-done // Wait for timeout.

	if broker.HasWaiter(id) {
		t.Error("expected HasWaiter to return false after timeout")
	}
	if !broker.WasTimedOut(id) {
		t.Error("expected WasTimedOut to return true")
	}

	broker.ClearTimedOut(id)
	if broker.WasTimedOut(id) {
		t.Error("expected WasTimedOut to return false after ClearTimedOut")
	}
}

// --- Channels accessor test ---

func TestBrokerChannels(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)
	broker := NewBroker([]Channel{ch1, ch2})

	channels := broker.Channels()
	if len(channels) != 2 {
		t.Errorf("expected 2 channels, got %d", len(channels))
	}
	if channels[0].Type() != ChannelTelegram {
		t.Errorf("expected first channel to be Telegram, got %v", channels[0].Type())
	}
	if channels[1].Type() != ChannelHTTP {
		t.Errorf("expected second channel to be HTTP, got %v", channels[1].Type())
	}
}

// --- Channel error does not block other channels ---

func TestBrokerEmptyChannelSlice(t *testing.T) {
	// Empty slice (not nil) should behave the same as nil channels.
	broker := NewBroker([]Channel{})

	resp, err := broker.Request("empty-slice.com", 443, "", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error with empty channel slice")
	}
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}

	if len(broker.Channels()) != 0 {
		t.Errorf("expected 0 channels, got %d", len(broker.Channels()))
	}
}

// panicChannel is a mock that panics during RequestApproval.
type panicChannel struct {
	mockChannel
}

func (p *panicChannel) RequestApproval(_ context.Context, _ ApprovalRequest) error {
	panic("channel exploded")
}

func TestBrokerChannelPanicRecovery(t *testing.T) {
	panicCh := &panicChannel{mockChannel: mockChannel{typ: ChannelTelegram}}
	goodCh := newMockChannel(ChannelHTTP)

	var broker *Broker
	goodCh.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}

	broker = NewBroker([]Channel{panicCh, goodCh})

	// The panicking channel should not prevent the good channel from resolving.
	resp, err := broker.Request("panic-test.com", 443, "", 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp != ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}

	// The good channel should have received the request.
	if len(goodCh.getRequests()) != 1 {
		t.Errorf("good channel should have received 1 request, got %d", len(goodCh.getRequests()))
	}
}

func TestBrokerAllChannelsPanic(t *testing.T) {
	panicCh1 := &panicChannel{mockChannel: mockChannel{typ: ChannelTelegram}}
	panicCh2 := &panicChannel{mockChannel: mockChannel{typ: ChannelHTTP}}

	broker := NewBroker([]Channel{panicCh1, panicCh2})

	// With all channels panicking, the request should time out.
	resp, err := broker.Request("all-panic.com", 443, "", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error when all channels panic")
	}
	if resp != ResponseDeny {
		t.Errorf("expected Deny on timeout, got %v", resp)
	}
}

func TestBrokerPendingRequests(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1})

	// Start a request that blocks.
	go func() {
		_, _ = broker.Request("pending-test.com", 443, "", 5*time.Second)
	}()

	// Wait for it to register.
	for broker.PendingCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	reqs := broker.PendingRequests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(reqs))
	}
	if reqs[0].Destination != "pending-test.com" {
		t.Errorf("destination = %q, want 'pending-test.com'", reqs[0].Destination)
	}
	if reqs[0].Port != 443 {
		t.Errorf("port = %d, want 443", reqs[0].Port)
	}
	if reqs[0].ID == "" {
		t.Error("request ID should not be empty")
	}

	// Resolve to clean up.
	broker.Resolve(reqs[0].ID, ResponseDeny)
}

func TestBrokerIsClosed(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch1})

	if broker.IsClosed() {
		t.Error("broker should not be closed initially")
	}

	broker.CancelAll()

	if !broker.IsClosed() {
		t.Error("broker should be closed after CancelAll")
	}

	// Double CancelAll should not panic.
	broker.CancelAll()
}

func TestBrokerChannelErrorDoesNotBlockOthers(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch1.requestErr = errors.New("telegram API down")

	ch2 := newMockChannel(ChannelHTTP)

	var broker *Broker
	ch2.onRequest = func(req ApprovalRequest) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			broker.Resolve(req.ID, ResponseAllowOnce)
		}()
	}

	broker = NewBroker([]Channel{ch1, ch2})

	resp, err := broker.Request("test.com", 443, "", 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp != ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}
}

// --- Coalescing tests (broker-level dedup by dest:port) ---

// fireCoalescedBurst starts n concurrent Request calls to the same
// dest:port and waits until the broker reports all n have attached to a
// single primary waiter. It returns the primary request ID and a channel
// that yields each call's (resp, err) result.
func fireCoalescedBurst(t *testing.T, broker *Broker, ch *mockChannel, dest string, n int, timeout time.Duration) (string, <-chan result) {
	t.Helper()
	const port = 443
	type res = result
	out := make(chan res, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := broker.Request(dest, port, "https", timeout)
			out <- res{resp, err}
		}()
	}
	// Wait for the primary prompt to land.
	deadline := time.After(5 * time.Second)
	for {
		reqs := ch.getRequests()
		if len(reqs) >= 1 {
			id := reqs[0].ID
			if broker.CoalescedCount(id) >= n {
				return id, out
			}
		}
		select {
		case <-deadline:
			t.Fatalf("burst did not fully coalesce: got %d requests, count=%v",
				len(ch.getRequests()), func() int {
					if r := ch.getRequests(); len(r) > 0 {
						return broker.CoalescedCount(r[0].ID)
					}
					return 0
				}())
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestBrokerCoalesceOneBroadcastFanToAll(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 8
	primaryID, out := fireCoalescedBurst(t, broker, ch, "cas.example.com", n, 5*time.Second)

	// Exactly one prompt was broadcast for the whole burst.
	if got := len(ch.getRequests()); got != 1 {
		t.Fatalf("expected exactly 1 broadcast, got %d", got)
	}
	if c := broker.CoalescedCount(primaryID); c != n {
		t.Fatalf("expected coalesced count %d, got %d", n, c)
	}
	if pc := broker.PendingCount(); pc != 1 {
		t.Fatalf("expected 1 pending waiter, got %d", pc)
	}

	if !broker.Resolve(primaryID, ResponseAlwaysAllow) {
		t.Fatal("Resolve returned false for primary")
	}

	for i := 0; i < n; i++ {
		r := <-out
		if r.err != nil {
			t.Errorf("request %d: unexpected error %v", i, r.err)
		}
		if r.resp != ResponseAlwaysAllow {
			t.Errorf("request %d: expected AlwaysAllow, got %v", i, r.resp)
		}
	}
	// Final count retained for message-edit paths after the waiter is gone.
	if c := broker.CoalescedCount(primaryID); c != n {
		t.Errorf("expected retained coalesced count %d, got %d", n, c)
	}
}

func TestBrokerCoalesceDenyFanOut(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 5
	primaryID, out := fireCoalescedBurst(t, broker, ch, "deny.example.com", n, 5*time.Second)
	broker.Resolve(primaryID, ResponseDeny)

	for i := 0; i < n; i++ {
		r := <-out
		if r.resp != ResponseDeny {
			t.Errorf("request %d: expected Deny, got %v", i, r.resp)
		}
	}
}

func TestBrokerCoalesceTimeoutFanOut(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 4
	// No resolve: the primary times out and fans the terminal Deny to
	// every subscriber. The primary itself returns the timeout error;
	// subscribers receive Deny via the fan-out (nil err, like any
	// terminal resolution). Every caller must end up denied.
	_, out := fireCoalescedBurst(t, broker, ch, "slowburst.example.com", n, 80*time.Millisecond)

	timeoutErrs := 0
	for i := 0; i < n; i++ {
		r := <-out
		if r.resp != ResponseDeny {
			t.Errorf("request %d: expected Deny on timeout, got %v", i, r.resp)
		}
		if r.err != nil {
			timeoutErrs++
		}
	}
	if timeoutErrs == 0 {
		t.Error("expected at least the primary to report a timeout error")
	}
}

func TestBrokerCoalesceShutdownFanOut(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 6
	_, out := fireCoalescedBurst(t, broker, ch, "shutdown.example.com", n, 5*time.Second)
	broker.CancelAll()

	for i := 0; i < n; i++ {
		r := <-out
		if r.resp != ResponseDeny {
			t.Errorf("request %d: expected Deny on shutdown, got %v", i, r.resp)
		}
	}
}

// TestBrokerCancelAllRetainsCoalescedCount is the Finding 2 regression.
// CancelAll cleared the waiter map without retaining each waiter's final
// coalesced count, so the shutdown CancelApproval edit saw
// CoalescedCount==1 and dropped the "applied to N requests" suffix for a
// burst that was pending at shutdown. The fix records the count under the
// broker lock before the map is cleared, mirroring Resolve.
//
// Pre-fix this test fails: CoalescedCount after CancelAll returns 1.
func TestBrokerCancelAllRetainsCoalescedCount(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 7
	primaryID, out := fireCoalescedBurst(t, broker, ch, "cancelcount.example.com", n, 5*time.Second)

	broker.CancelAll()

	// Drain so the goroutines finish (they all get a terminal Deny).
	for i := 0; i < n; i++ {
		<-out
	}

	if c := broker.CoalescedCount(primaryID); c != n {
		t.Fatalf("after CancelAll, CoalescedCount(%s) = %d, want %d "+
			"(the shutdown cancel edit would render \"applied to %d "+
			"requests\"; pre-fix it renders just 1) — Finding 2",
			primaryID, c, n, c)
	}
}

// TestBrokerDetachedSubNotCounted is the Finding 3 regression. When a
// coalesced subscriber times out and detaches, the waiter's count was NOT
// decremented, so a later Resolve reported a CoalescedCount that still
// included subscribers that had already given up — Telegram said "applied
// to N" for more than were actually resolved by the tap. The fix
// decrements the count on detach, never below 1 (the primary).
//
// Pre-fix this test fails: the retained count stays at the peak (1 + total
// attached) instead of dropping by the number of detached subs.
func TestBrokerDetachedSubNotCounted(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const dest = "detachcount.example.com"
	const port = 443

	// Long-lived primary so it stays pending while subs come and go.
	primaryOut := make(chan result, 1)
	go func() {
		resp, err := broker.Request(dest, port, "https", 5*time.Second)
		primaryOut <- result{resp, err}
	}()
	var primaryID string
	for {
		reqs := ch.getRequests()
		if len(reqs) == 1 {
			primaryID = reqs[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}

	// k subscribers that each attach then time out and detach.
	const k = 3
	subOut := make(chan result, k)
	for i := 0; i < k; i++ {
		go func() {
			resp, err := broker.Request(dest, port, "https", 30*time.Millisecond)
			subOut <- result{resp, err}
		}()
	}
	// Wait until all k have attached (count == 1 + k at the peak).
	for broker.CoalescedCount(primaryID) < 1+k {
		time.Sleep(time.Millisecond)
	}
	// Let every sub time out and detach.
	for i := 0; i < k; i++ {
		sr := <-subOut
		if sr.resp != ResponseDeny || sr.err == nil {
			t.Fatalf("sub %d should have timed out with Deny+err, got %v / %v", i, sr.resp, sr.err)
		}
	}
	// All k detached; the primary alone remains.
	if c := broker.CoalescedCount(primaryID); c != 1 {
		t.Fatalf("after %d subs detached, live CoalescedCount = %d, want 1 "+
			"(detached subs must not inflate the count) — Finding 3", k, c)
	}

	// Resolve the primary; the retained count must reflect only the
	// primary (the k detached subs gave up before the decision).
	if !broker.Resolve(primaryID, ResponseAllowOnce) {
		t.Fatal("Resolve returned false for primary")
	}
	pr := <-primaryOut
	if pr.resp != ResponseAllowOnce {
		t.Fatalf("primary: expected AllowOnce, got %v", pr.resp)
	}
	if c := broker.CoalescedCount(primaryID); c != 1 {
		t.Fatalf("retained CoalescedCount after resolve = %d, want 1 "+
			"(Telegram would say \"applied to %d requests\" when only the "+
			"primary was actually covered) — Finding 3", c, c)
	}
}

func TestBrokerCoalesceSubTimeoutDoesNotBlockFanOut(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	// Primary with a long timeout so it stays pending.
	primaryOut := make(chan result, 1)
	go func() {
		resp, err := broker.Request("subtimeout.example.com", 443, "https", 5*time.Second)
		primaryOut <- result{resp, err}
	}()
	var primaryID string
	for {
		reqs := ch.getRequests()
		if len(reqs) == 1 {
			primaryID = reqs[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}

	// A coalesced sub with a very short timeout: it detaches itself.
	subOut := make(chan result, 1)
	go func() {
		resp, err := broker.Request("subtimeout.example.com", 443, "https", 30*time.Millisecond)
		subOut <- result{resp, err}
	}()
	// Wait for the sub to attach (count == 2) then time out (count back
	// near 1 once it detaches; tolerate the race by just waiting for the
	// sub result).
	for broker.CoalescedCount(primaryID) < 2 {
		time.Sleep(time.Millisecond)
	}
	sr := <-subOut
	if sr.resp != ResponseDeny || sr.err == nil {
		t.Fatalf("sub should have timed out with Deny+err, got %v / %v", sr.resp, sr.err)
	}

	// Resolving the primary must not block on the departed sub.
	done := make(chan bool, 1)
	go func() { done <- broker.Resolve(primaryID, ResponseAllowOnce) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("Resolve returned false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Resolve blocked on a detached sub")
	}
	pr := <-primaryOut
	if pr.resp != ResponseAllowOnce {
		t.Errorf("primary: expected AllowOnce, got %v", pr.resp)
	}
}

func TestBrokerCoalesceLateAttachOpensNewPrompt(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	// First prompt for the target.
	out1 := make(chan result, 1)
	go func() {
		resp, err := broker.Request("late.example.com", 443, "https", 5*time.Second)
		out1 <- result{resp, err}
	}()
	var id1 string
	for {
		reqs := ch.getRequests()
		if len(reqs) == 1 {
			id1 = reqs[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Resolve the first; dedupIndex entry is cleared in the same locked
	// section as the waiter delete.
	broker.Resolve(id1, ResponseAllowOnce)
	if r := <-out1; r.resp != ResponseAllowOnce {
		t.Fatalf("first request: expected AllowOnce, got %v", r.resp)
	}

	// A new request to the same target after resolution must NOT attach to
	// the dead waiter — it must open a fresh prompt with a new ID.
	out2 := make(chan result, 1)
	go func() {
		resp, err := broker.Request("late.example.com", 443, "https", 5*time.Second)
		out2 <- result{resp, err}
	}()
	var id2 string
	for {
		reqs := ch.getRequests()
		if len(reqs) == 2 {
			id2 = reqs[1].ID
			break
		}
		select {
		case <-time.After(2 * time.Second):
			t.Fatal("late request did not open a new prompt (attached to dead waiter)")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if id2 == id1 {
		t.Fatalf("late request reused dead primary id %q", id1)
	}
	broker.Resolve(id2, ResponseDeny)
	if r := <-out2; r.resp != ResponseDeny {
		t.Errorf("second request: expected Deny, got %v", r.resp)
	}
}

func TestBrokerCoalesceConcurrentResolveAndAttach(t *testing.T) {
	// Stress the resolve/attach interleave: no sub may end up attached to
	// a deleted waiter (which would hang forever) and none may be lost.
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const rounds = 40
	for round := 0; round < rounds; round++ {
		dest := fmt.Sprintf("race-%d.example.com", round)
		out := make(chan result, 3)
		for i := 0; i < 3; i++ {
			go func() {
				resp, err := broker.Request(dest, 443, "https", 3*time.Second)
				out <- result{resp, err}
			}()
		}
		// Resolve as soon as the first prompt appears, racing the other
		// two arrivals (some attach as subs, some open fresh prompts).
		var firstID string
		for {
			for _, r := range ch.getRequests() {
				if r.Destination == dest {
					firstID = r.ID
					break
				}
			}
			if firstID != "" {
				break
			}
			time.Sleep(time.Microsecond * 200)
		}
		// Keep resolving every pending prompt for this dest until all
		// three callers return. Any caller that opened its own prompt
		// gets resolved here too.
		got := 0
		timeout := time.After(3 * time.Second)
		for got < 3 {
			for _, r := range broker.PendingRequests() {
				if r.Destination == dest {
					broker.Resolve(r.ID, ResponseAllowOnce)
				}
			}
			select {
			case res := <-out:
				if res.resp != ResponseAllowOnce {
					t.Fatalf("round %d: expected AllowOnce, got %v (err %v)", round, res.resp, res.err)
				}
				got++
			case <-timeout:
				t.Fatalf("round %d: only %d/3 callers returned (deadlock?)", round, got)
			default:
				time.Sleep(time.Microsecond * 200)
			}
		}
	}
}

func TestBrokerDistinctDestNotCoalesced(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	out := make(chan result, 2)
	go func() {
		resp, err := broker.Request("a.example.com", 443, "https", 5*time.Second)
		out <- result{resp, err}
	}()
	go func() {
		resp, err := broker.Request("b.example.com", 443, "https", 5*time.Second)
		out <- result{resp, err}
	}()
	// Two distinct targets -> two waiters, two broadcasts.
	for broker.PendingCount() < 2 {
		time.Sleep(time.Millisecond)
	}
	if got := len(ch.getRequests()); got != 2 {
		t.Fatalf("expected 2 broadcasts for distinct targets, got %d", got)
	}
	for _, r := range broker.PendingRequests() {
		broker.Resolve(r.ID, ResponseAllowOnce)
	}
	<-out
	<-out
}

func TestBrokerSamePortDifferentDestNotCoalesced(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	out := make(chan result, 2)
	// Same host, different port -> different dedup key, not coalesced.
	go func() {
		resp, err := broker.Request("svc.example.com", 443, "https", 5*time.Second)
		out <- result{resp, err}
	}()
	go func() {
		resp, err := broker.Request("svc.example.com", 8443, "https", 5*time.Second)
		out <- result{resp, err}
	}()
	for broker.PendingCount() < 2 {
		time.Sleep(time.Millisecond)
	}
	if got := len(ch.getRequests()); got != 2 {
		t.Fatalf("expected 2 broadcasts for differing ports, got %d", got)
	}
	for _, r := range broker.PendingRequests() {
		broker.Resolve(r.ID, ResponseAllowOnce)
	}
	<-out
	<-out
}

func TestBrokerWithNoCoalesceNeverCoalesces(t *testing.T) {
	ch := newMockChannel(ChannelTelegram)
	broker := NewBroker([]Channel{ch}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 4
	out := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := broker.Request("mcp-tool", 0, "mcp", 5*time.Second, WithNoCoalesce())
			out <- result{resp, err}
		}()
	}
	for broker.PendingCount() < n {
		time.Sleep(time.Millisecond)
	}
	if got := len(ch.getRequests()); got != n {
		t.Fatalf("WithNoCoalesce: expected %d separate prompts, got %d", n, got)
	}
	for _, r := range broker.PendingRequests() {
		broker.Resolve(r.ID, ResponseAllowOnce)
	}
	for i := 0; i < n; i++ {
		<-out
	}
}

func TestBrokerCoalesceCrossChannelFirstWins(t *testing.T) {
	ch1 := newMockChannel(ChannelTelegram)
	ch2 := newMockChannel(ChannelHTTP)
	broker := NewBroker([]Channel{ch1, ch2}, WithMaxPending(0), WithDestinationRateLimit(0, 0))

	const n = 5
	out := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := broker.Request("xchan.example.com", 443, "https", 5*time.Second)
			out <- result{resp, err}
		}()
	}
	var primaryID string
	for {
		reqs := ch1.getRequests()
		if len(reqs) == 1 && broker.CoalescedCount(reqs[0].ID) >= n {
			primaryID = reqs[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	// Both channels saw exactly one prompt (the primary).
	if len(ch1.getRequests()) != 1 || len(ch2.getRequests()) != 1 {
		t.Fatalf("expected 1 prompt per channel, got ch1=%d ch2=%d",
			len(ch1.getRequests()), len(ch2.getRequests()))
	}
	// Two channels race to resolve the same primary; first wins, and the
	// whole coalesced burst gets that winner's response.
	r1 := make(chan bool, 1)
	r2 := make(chan bool, 1)
	go func() { r1 <- broker.Resolve(primaryID, ResponseAlwaysAllow) }()
	go func() { r2 <- broker.Resolve(primaryID, ResponseDeny) }()
	wins := 0
	if <-r1 {
		wins++
	}
	if <-r2 {
		wins++
	}
	if wins != 1 {
		t.Fatalf("expected exactly 1 winning Resolve, got %d", wins)
	}
	first := result{}
	for i := 0; i < n; i++ {
		r := <-out
		if i == 0 {
			first = r
		} else if r.resp != first.resp {
			t.Fatalf("coalesced burst got mixed responses: %v vs %v", first.resp, r.resp)
		}
	}
	if first.resp != ResponseAlwaysAllow && first.resp != ResponseDeny {
		t.Fatalf("unexpected response %v", first.resp)
	}
}
