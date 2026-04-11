package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
)

// fakeChannel implements channel.Channel and resolves approval requests via a
// pre-configured response. The broker is required because CheckAndConsume goes
// through Broker.Request which only returns once a channel resolves.
type fakeChannel struct {
	mu          sync.Mutex
	broker      *channel.Broker
	response    channel.Response
	requests    []channel.ApprovalRequest
	onRequestCh chan struct{}
}

func newFakeChannel(resp channel.Response) *fakeChannel {
	return &fakeChannel{response: resp, onRequestCh: make(chan struct{}, 32)}
}

func (f *fakeChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	resp := f.response
	broker := f.broker
	f.mu.Unlock()
	// Resolve asynchronously so the broker goroutine can register the waiter
	// before we deliver the response.
	go func() {
		broker.Resolve(req.ID, resp)
	}()
	select {
	case f.onRequestCh <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeChannel) CancelApproval(_ string) error        { return nil }
func (f *fakeChannel) Commands() <-chan channel.Command     { return nil }
func (f *fakeChannel) Notify(context.Context, string) error { return nil }
func (f *fakeChannel) Start() error                         { return nil }
func (f *fakeChannel) Stop()                                {}
func (f *fakeChannel) Type() channel.ChannelType            { return channel.ChannelTelegram }

func (f *fakeChannel) setResponse(resp channel.Response) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.response = resp
}

func (f *fakeChannel) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// newTestChecker builds a RequestPolicyChecker wired to a fake channel/broker
// and a policy engine loaded from the given TOML.
func newTestChecker(t *testing.T, toml string, resp channel.Response) (*RequestPolicyChecker, *fakeChannel) {
	t.Helper()
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	// Override timeout so ask-path tests finish fast on a misconfigured test.
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	fc := newFakeChannel(resp)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker
	return NewRequestPolicyChecker(ptr, broker), fc
}

func TestRequestPolicyChecker_ExplicitAllowSkipsBroker(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
`
	checker, fc := newTestChecker(t, toml, channel.ResponseDeny)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("verdict = %v, want Allow", verdict)
	}
	if fc.requestCount() != 0 {
		t.Fatalf("broker request count = %d, want 0 (explicit allow should skip broker)", fc.requestCount())
	}
}

func TestRequestPolicyChecker_ExplicitDenyReturnsImmediately(t *testing.T) {
	toml := `
[policy]
default = "allow"

[[deny]]
destination = "evil.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	verdict, err := checker.CheckAndConsume("evil.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny", verdict)
	}
	if fc.requestCount() != 0 {
		t.Fatalf("broker request count = %d, want 0 (explicit deny should skip broker)", fc.requestCount())
	}
}

func TestRequestPolicyChecker_AllowOnceConsumedAfterOneCall(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("first call verdict = %v, want Allow", verdict)
	}
	if !checker.ConsumedAllowOnce("api.example.com", 443) {
		t.Fatal("expected ConsumedAllowOnce to be true after allow-once approval")
	}
	if fc.requestCount() != 1 {
		t.Fatalf("broker request count = %d, want 1", fc.requestCount())
	}
}

func TestRequestPolicyChecker_SecondCallToConsumedDestReAsksBroker(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	// First request -> allow-once approved.
	if _, err := checker.CheckAndConsume("api.example.com", 443); err != nil {
		t.Fatalf("first CheckAndConsume: %v", err)
	}
	// Second request must trigger a fresh broker call. Switch the response
	// so the second decision differs from the first, proving the broker
	// was actually consulted.
	fc.setResponse(channel.ResponseDeny)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("second CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("second call verdict = %v, want Deny", verdict)
	}
	if fc.requestCount() != 2 {
		t.Fatalf("broker request count = %d, want 2 (each call should ask the broker)", fc.requestCount())
	}
}

func TestRequestPolicyChecker_AlwaysAllowNotConsumed(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAlwaysAllow)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("verdict = %v, want Allow", verdict)
	}
	if checker.ConsumedAllowOnce("api.example.com", 443) {
		t.Fatal("always-allow should not set ConsumedAllowOnce marker")
	}
	if fc.requestCount() != 1 {
		t.Fatalf("broker request count = %d, want 1", fc.requestCount())
	}
}

func TestRequestPolicyChecker_AlwaysDenyBlocks(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, _ := newTestChecker(t, toml, channel.ResponseAlwaysDeny)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny", verdict)
	}
	if checker.ConsumedAllowOnce("api.example.com", 443) {
		t.Fatal("always-deny should not set ConsumedAllowOnce marker")
	}
}

func TestRequestPolicyChecker_DenyResponseFromUser(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseDeny)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny", verdict)
	}
	if fc.requestCount() != 1 {
		t.Fatalf("broker request count = %d, want 1", fc.requestCount())
	}
}

func TestRequestPolicyChecker_NilBrokerTreatsAskAsDeny(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	checker := NewRequestPolicyChecker(ptr, nil)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny (nil broker should treat ask as deny)", verdict)
	}
}

func TestRequestPolicyChecker_NilCheckerAllowsAllRequests(t *testing.T) {
	// A nil checker means per-request checking was disabled (e.g. explicit
	// allow rule matched at connection level). CheckAndConsume should be a
	// no-op that returns Allow.
	var checker *RequestPolicyChecker
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("verdict = %v, want Allow", verdict)
	}
}

func TestRequestPolicyChecker_NilEngineReturnsError(t *testing.T) {
	ptr := new(atomic.Pointer[policy.Engine])
	checker := NewRequestPolicyChecker(ptr, nil)
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err == nil {
		t.Fatal("CheckAndConsume: expected error for nil engine")
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny on nil engine", verdict)
	}
}

func TestRequestPolicyChecker_DefaultDenyReturnsDeny(t *testing.T) {
	toml := `
[policy]
default = "deny"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	verdict, err := checker.CheckAndConsume("unknown.host", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny", verdict)
	}
	if fc.requestCount() != 0 {
		t.Fatalf("broker request count = %d, want 0 (default deny should skip broker)", fc.requestCount())
	}
}

func TestRequestPolicyChecker_ConcurrentAllowOnceSerializesApprovals(t *testing.T) {
	// Multiple HTTP/2 streams on the same connection may invoke
	// CheckAndConsume concurrently. Each call must be independently answered
	// by the broker (no single-shot caching). This test confirms the mutex
	// and broker contract hold up under concurrency.
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	const n = 5
	var wg sync.WaitGroup
	results := make([]policy.Verdict, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := checker.CheckAndConsume("api.example.com", 443)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
			}
			results[i] = v
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent CheckAndConsume did not finish in time")
	}
	for i, v := range results {
		if v != policy.Allow {
			t.Errorf("result[%d] = %v, want Allow", i, v)
		}
	}
	if fc.requestCount() != n {
		t.Errorf("broker request count = %d, want %d (every request should ask)", fc.requestCount(), n)
	}
}
