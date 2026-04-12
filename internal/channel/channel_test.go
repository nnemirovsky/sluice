package channel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = broker.Request("example.com", 443, "", 2*time.Second)
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

	broker = NewBroker([]Channel{ch1},
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

	broker = NewBroker([]Channel{ch1},
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

	broker = NewBroker([]Channel{ch1},
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

	// Start n requests that will block waiting for approval.
	for i := 0; i < n; i++ {
		go func() {
			resp, err := broker.Request("cancel-test.com", 443, "", 5*time.Second)
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
