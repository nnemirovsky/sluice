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

// fakeChannel implements channel.Channel and resolves approval requests via
// a pre-configured response. The broker is required because CheckAndConsume
// goes through Broker.Request which only returns once a channel resolves.
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
	// Resolve asynchronously so the broker goroutine can register the
	// waiter before we deliver the response.
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

// newTestChecker builds a RequestPolicyChecker wired to a fake
// channel/broker and a policy engine loaded from the given TOML.
func newTestChecker(t *testing.T, toml string, resp channel.Response) (*RequestPolicyChecker, *fakeChannel) {
	t.Helper()
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	// Override timeout so ask-path tests finish fast on a misconfigured
	// test.
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

func TestRequestPolicyChecker_AllowOnceAsksBrokerAndAllows(t *testing.T) {
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
	if fc.requestCount() != 1 {
		t.Fatalf("broker request count = %d, want 1", fc.requestCount())
	}
}

func TestRequestPolicyChecker_SecondCallAsksBrokerAgain(t *testing.T) {
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
	// Second request must trigger a fresh broker call. Switch the
	// response so the second decision differs from the first, proving
	// the broker was actually consulted.
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

func TestRequestPolicyChecker_AlwaysAllowPersistsViaCallback(t *testing.T) {
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
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	fc := newFakeChannel(channel.ResponseAlwaysAllow)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	var persistCalls int
	var persistVerdict PersistVerdict
	var persistDest string
	var persistPort int
	persist := func(v PersistVerdict, d string, p int) {
		persistCalls++
		persistVerdict = v
		persistDest = d
		persistPort = p
	}
	checker := NewRequestPolicyChecker(ptr, broker, WithPersist(persist))

	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("verdict = %v, want Allow", verdict)
	}
	if persistCalls != 1 {
		t.Fatalf("persist callback called %d times, want 1", persistCalls)
	}
	if persistVerdict != PersistAllow {
		t.Fatalf("persist verdict = %v, want PersistAllow", persistVerdict)
	}
	if persistDest != "api.example.com" || persistPort != 443 {
		t.Fatalf("persist args = %s:%d, want api.example.com:443", persistDest, persistPort)
	}
}

func TestRequestPolicyChecker_AlwaysDenyPersistsViaCallback(t *testing.T) {
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
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	fc := newFakeChannel(channel.ResponseAlwaysDeny)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	var persistCalls int
	var persistVerdict PersistVerdict
	persist := func(v PersistVerdict, _ string, _ int) {
		persistCalls++
		persistVerdict = v
	}
	checker := NewRequestPolicyChecker(ptr, broker, WithPersist(persist))

	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny", verdict)
	}
	if persistCalls != 1 {
		t.Fatalf("persist callback called %d times, want 1", persistCalls)
	}
	if persistVerdict != PersistDeny {
		t.Fatalf("persist verdict = %v, want PersistDeny", persistVerdict)
	}
}

func TestRequestPolicyChecker_AlwaysAllowWithoutCallbackStillAllows(t *testing.T) {
	// Without a persist callback, always-allow still allows the current
	// request (the warning is logged so operators notice the drift).
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
	if fc.requestCount() != 1 {
		t.Fatalf("broker request count = %d, want 1", fc.requestCount())
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
	eng.TimeoutSec = 1 // short defensive timeout in case the ask path
	// leaks into the broker (nil broker should short-circuit before the
	// broker is consulted, but a regression must not hang the test).
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

func TestRequestPolicyChecker_NilEnginePointerReturnsError(t *testing.T) {
	// A checker constructed with a nil atomic pointer (not just an unloaded
	// engine) must fail closed instead of panicking.
	checker := &RequestPolicyChecker{}
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err == nil {
		t.Fatal("CheckAndConsume: expected error for nil engine pointer")
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny on nil engine pointer", verdict)
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

func TestRequestPolicyChecker_WithRequestInfoPopulatesApprovalRequest(t *testing.T) {
	// CheckAndConsume should forward the HTTP method and path to the broker
	// so channels can render a per-request approval message.
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	if _, err := checker.CheckAndConsume("api.example.com", 443, WithRequestInfo("POST", "/v1/users")); err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	fc.mu.Lock()
	reqs := append([]channel.ApprovalRequest(nil), fc.requests...)
	fc.mu.Unlock()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 broker request, got %d", len(reqs))
	}
	if reqs[0].Method != "POST" {
		t.Errorf("approval method = %q, want %q", reqs[0].Method, "POST")
	}
	if reqs[0].Path != "/v1/users" {
		t.Errorf("approval path = %q, want %q", reqs[0].Path, "/v1/users")
	}
}

func TestRequestPolicyChecker_WithoutRequestInfoLeavesApprovalEmpty(t *testing.T) {
	// Connection-level ask approvals (no WithRequestInfo) should leave the
	// approval request method/path empty so channels render the legacy
	// connection-level message.
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)
	if _, err := checker.CheckAndConsume("api.example.com", 443); err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	fc.mu.Lock()
	reqs := append([]channel.ApprovalRequest(nil), fc.requests...)
	fc.mu.Unlock()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 broker request, got %d", len(reqs))
	}
	if reqs[0].Method != "" || reqs[0].Path != "" {
		t.Errorf("expected empty method/path, got method=%q path=%q", reqs[0].Method, reqs[0].Path)
	}
}

func TestRequestPolicyChecker_WithProtocolMatchesScopedRule(t *testing.T) {
	// A rule scoped to protocols=["grpc"] must match when the caller
	// passes WithProtocol("grpc") even though the destination matches
	// multiple rules. Without WithProtocol, the engine would fall back to
	// port-based detection and the grpc-scoped rule would not apply.
	toml := `
[policy]
default = "deny"

[[deny]]
destination = "api.example.com"
protocols = ["grpc"]

[[allow]]
destination = "api.example.com"
protocols = ["https"]
`
	checker, fc := newTestChecker(t, toml, channel.ResponseAllowOnce)

	// grpc-scoped deny: must return Deny without contacting the broker.
	verdict, err := checker.CheckAndConsume("api.example.com", 443, WithProtocol("grpc"))
	if err != nil {
		t.Fatalf("CheckAndConsume(grpc): %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("grpc verdict = %v, want Deny (protocol-scoped deny rule)", verdict)
	}

	// https-scoped allow: must return Allow without contacting the broker.
	verdict, err = checker.CheckAndConsume("api.example.com", 443, WithProtocol("https"))
	if err != nil {
		t.Fatalf("CheckAndConsume(https): %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("https verdict = %v, want Allow (protocol-scoped allow rule)", verdict)
	}

	if fc.requestCount() != 0 {
		t.Fatalf("broker request count = %d, want 0 (explicit rules should skip broker)", fc.requestCount())
	}
}

// TestRequestPolicyChecker_BypassRateLimitAllowsHighVolume verifies that
// per-request traffic can exceed the broker's 5/min per-destination rate
// limit when the checker attaches WithSkipBrokerRateLimit. Without the
// bypass, the 6th request would silently be denied by the broker's limiter
// even though the user keeps approving. Per-request policy callers use the
// bypass so a keep-alive connection hitting one destination does not hit
// the rate cap sized for connection-level approvals.
func TestRequestPolicyChecker_BypassRateLimitAllowsHighVolume(t *testing.T) {
	// injectCredentials always passes WithSkipBrokerRateLimit so the
	// checker constructed here simulates that path. Use a plain 5/min rate
	// limit.
	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"

[[ask]]
destination = "other.example.com"
`
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	fc := newFakeChannel(channel.ResponseAllowOnce)
	broker := channel.NewBroker([]channel.Channel{fc},
		channel.WithDestinationRateLimit(5, time.Minute))
	fc.broker = broker

	checker := NewRequestPolicyChecker(ptr, broker)

	// Make 10 sequential requests with the bypass. Without the bypass the
	// 6th (and later) request would be rate-limited and return Deny; with
	// the bypass all 10 should be approved.
	for i := 0; i < 10; i++ {
		verdict, err := checker.CheckAndConsume("api.example.com", 443, WithSkipBrokerRateLimit())
		if err != nil {
			t.Fatalf("call %d: CheckAndConsume: %v", i, err)
		}
		if verdict != policy.Allow {
			t.Fatalf("call %d: verdict = %v, want Allow (rate limit bypass failed)", i, verdict)
		}
	}
	if fc.requestCount() != 10 {
		t.Fatalf("broker request count = %d, want 10 (bypass should not drop any requests)", fc.requestCount())
	}

	// Sanity check the opposite direction on a DIFFERENT destination so
	// the 10 bypass entries above do not pollute its rate-limit window.
	// Without the bypass, the 6th call hits the rate limit. The broker
	// returns (ResponseDeny, ErrDestinationRateLimited) which the checker
	// surfaces as (Deny, err).
	for i := 0; i < 5; i++ {
		verdict, err := checker.CheckAndConsume("other.example.com", 443)
		if err != nil {
			t.Fatalf("non-bypass call %d: unexpected error %v", i, err)
		}
		if verdict != policy.Allow {
			t.Fatalf("non-bypass call %d verdict = %v, want Allow", i, verdict)
		}
	}
	verdict, err := checker.CheckAndConsume("other.example.com", 443)
	if err == nil {
		t.Fatalf("6th non-bypass call: expected rate-limit error, verdict=%v", verdict)
	}
	if verdict != policy.Deny {
		t.Fatalf("6th non-bypass call verdict = %v, want Deny", verdict)
	}
}

// TestRequestPolicyChecker_SeedCreditConsumedOnFirstCall verifies the new
// seed-credit pattern used to avoid double-prompting when the SOCKS5 or
// SNI layer already obtained an ask approval for the CONNECT tunnel.
func TestRequestPolicyChecker_SeedCreditConsumedOnFirstCall(t *testing.T) {
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
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	fc := newFakeChannel(channel.ResponseDeny)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	// Seed with 1 credit. The first CheckAndConsume should return Allow
	// without contacting the broker even though the default verdict for
	// api.example.com is Ask and the broker would return Deny.
	checker := NewRequestPolicyChecker(ptr, broker, WithSeedCredits(1))
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("first CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("first verdict = %v, want Allow (seeded credit)", verdict)
	}
	if fc.requestCount() != 0 {
		t.Fatalf("broker count after seeded call = %d, want 0", fc.requestCount())
	}

	// Second call: seed exhausted. The broker returns Deny, so the
	// verdict must be Deny and broker count must be 1.
	verdict, err = checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("second CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("second verdict = %v, want Deny (seed exhausted, broker returned Deny)", verdict)
	}
	if fc.requestCount() != 1 {
		t.Fatalf("broker count after exhausted seed = %d, want 1", fc.requestCount())
	}
}

// TestRequestPolicyChecker_SeedCreditDoesNotOverrideExplicitDeny verifies
// that an explicit deny rule always wins over a prepaid seed credit. This
// protects against the case where a destination was allow-once'd at
// CONNECT time but subsequently added to a deny list via another approval
// or SIGHUP.
func TestRequestPolicyChecker_SeedCreditDoesNotOverrideExplicitDeny(t *testing.T) {
	toml := `
[policy]
default = "deny"

[[deny]]
destination = "api.example.com"
`
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	checker := NewRequestPolicyChecker(ptr, nil, WithSeedCredits(5))
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("verdict = %v, want Deny (explicit deny must beat seed)", verdict)
	}
}

func TestRequestPolicyChecker_ConcurrentAllowOnceSerializesApprovals(t *testing.T) {
	// Multiple HTTP/2 streams on the same connection may invoke
	// CheckAndConsume concurrently. Each call must be independently
	// answered by the broker (no single-shot caching). This test
	// confirms the contract holds up under concurrency.
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
