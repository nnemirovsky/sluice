package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// newTestRuleSet builds a policyRuleSet wired to an engine compiled from the
// given TOML snippet. Optional broker is used for ask-path tests.
func newTestRuleSet(t *testing.T, toml string, broker *channel.Broker) *policyRuleSet {
	t.Helper()
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	return &policyRuleSet{
		engine:   ptr,
		reloadMu: new(sync.Mutex),
		broker:   broker,
	}
}

// mkConnectRequest produces a minimal CONNECT request targeting host:port.
func mkConnectRequest(host string, port int) *socks5.Request {
	return &socks5.Request{
		Request: statute.Request{
			Command: statute.CommandConnect,
		},
		DestAddr: &statute.AddrSpec{
			FQDN: host,
			Port: port,
		},
	}
}

func TestAllowSetsSkipPerRequestOnExplicitAllowRule(t *testing.T) {
	rules := newTestRuleSet(t, `
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
`, nil)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com", 443))
	if !ok {
		t.Fatal("Allow returned false for explicit allow rule")
	}
	skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool)
	if !skip {
		t.Fatal("ctxKeySkipPerRequest should be true for explicit allow rule")
	}
	if _, present := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker); present {
		t.Fatal("ctxKeyPerRequestPolicy should NOT be set when skip flag is true")
	}
	if c := perRequestCheckerFromContext(ctx); c != nil {
		t.Fatal("perRequestCheckerFromContext should return nil for explicit allow")
	}
}

func TestAllowAttachesCheckerOnDefaultAllowWithBroker(t *testing.T) {
	fc := newFakeChannel(channel.ResponseAllowOnce)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	rules := newTestRuleSet(t, `
[policy]
default = "allow"
`, broker)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("anything.example.com", 443))
	if !ok {
		t.Fatal("Allow returned false for default allow")
	}
	if skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool); skip {
		t.Fatal("ctxKeySkipPerRequest should NOT be set for default-verdict allow when a broker is wired")
	}
	checker, ok := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker)
	if !ok || checker == nil {
		t.Fatal("ctxKeyPerRequestPolicy should be a non-nil *RequestPolicyChecker")
	}
	if perRequestCheckerFromContext(ctx) != checker {
		t.Fatal("perRequestCheckerFromContext should return the attached checker")
	}
}

func TestAllowSkipsCheckerOnDefaultAllowWithoutBroker(t *testing.T) {
	// Without a broker, per-request checks can only allow or deny via the
	// engine, so attaching a checker adds overhead without benefit. The
	// fast path should kick in here too.
	rules := newTestRuleSet(t, `
[policy]
default = "allow"
`, nil)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("anything.example.com", 443))
	if !ok {
		t.Fatal("Allow returned false for default allow")
	}
	if skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool); !skip {
		t.Fatal("ctxKeySkipPerRequest should be true when no broker is configured")
	}
	if _, present := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker); present {
		t.Fatal("ctxKeyPerRequestPolicy should NOT be set when skip flag is true")
	}
}

func TestAllowAttachesCheckerOnAskApproval(t *testing.T) {
	fc := newFakeChannel(channel.ResponseAllowOnce)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	rules := newTestRuleSet(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, broker)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com", 443))
	if !ok {
		t.Fatal("Allow returned false after ask->allow-once approval")
	}
	if skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool); skip {
		t.Fatal("ctxKeySkipPerRequest should NOT be set for ask-approved connection")
	}
	checker, _ := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker)
	if checker == nil {
		t.Fatal("ask-approved connection must attach a RequestPolicyChecker so subsequent HTTP requests re-trigger the ask flow")
	}

	// Sanity check: Allow() must have consulted the broker exactly once for
	// the CONNECT-level ask.
	if got := fc.requestCount(); got != 1 {
		t.Fatalf("broker count after Allow = %d, want 1 (CONNECT ask)", got)
	}

	// The first HTTP request must NOT re-ask the broker (double-prompt
	// regression guard). The checker was seeded with one prepaid allow
	// credit from the CONNECT approval, so CheckAndConsume on the first
	// request is satisfied from the seed without contacting the broker.
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("first CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("first HTTP request verdict = %v, want Allow (seeded credit)", verdict)
	}
	if got := fc.requestCount(); got != 1 {
		t.Fatalf("broker count after first HTTP request = %d, want 1 (seed must consume without re-asking broker)", got)
	}

	// The second HTTP request must re-ask the broker (seed is exhausted).
	// Flip the response so the second verdict differs from the first,
	// proving the broker was actually consulted again.
	fc.setResponse(channel.ResponseDeny)
	verdict, err = checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("second CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("second HTTP request verdict = %v, want Deny", verdict)
	}
	if got := fc.requestCount(); got != 2 {
		t.Fatalf("broker count after second HTTP request = %d, want 2 (each subsequent request re-asks)", got)
	}
}

func TestAllowSetsSkipAfterAlwaysAllow(t *testing.T) {
	// When a connection-level ask resolves to Always Allow and the rule
	// is persisted, the connection should take the fast path because the
	// new rule will match every subsequent HTTP request via the engine.
	// This mirrors the SNI path which sets ctxKeySkipPerRequest after
	// sniSaveRule succeeds. Uses a store-backed rule set because the
	// persist path now requires a store (there is no in-memory fallback).
	fc := newFakeChannel(channel.ResponseAlwaysAllow)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	rules, _ := newTestRuleSetWithStore(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, broker)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com", 443))
	if !ok {
		t.Fatal("Allow returned false after ask->always-allow approval")
	}
	skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool)
	if !skip {
		t.Fatal("ctxKeySkipPerRequest should be true after always-allow so per-request checks are skipped")
	}
	if _, present := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker); present {
		t.Fatal("ctxKeyPerRequestPolicy should NOT be set when skip flag is true")
	}
}

func TestAllowAttachesNoCheckerOnDeny(t *testing.T) {
	rules := newTestRuleSet(t, `
[policy]
default = "deny"
`, nil)

	_, ok := rules.Allow(context.Background(), mkConnectRequest("blocked.example.com", 443))
	if ok {
		t.Fatal("Allow returned true for default deny")
	}
}

func TestPerRequestCheckerFromContextSkipOverridesChecker(t *testing.T) {
	// Even if a checker is mistakenly attached alongside a skip flag, the
	// skip flag wins so explicit allow rules never pay the per-request cost.
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(&policy.Engine{Default: policy.Allow})
	checker := NewRequestPolicyChecker(ptr, nil)

	ctx := context.Background()
	ctx = context.WithValue(ctx, ctxKeyPerRequestPolicy, checker)
	ctx = context.WithValue(ctx, ctxKeySkipPerRequest, true)

	if got := perRequestCheckerFromContext(ctx); got != nil {
		t.Fatalf("perRequestCheckerFromContext = %v, want nil when skip flag is set", got)
	}
}

func TestPerRequestCheckerFromContextEmptyContextReturnsNil(t *testing.T) {
	if got := perRequestCheckerFromContext(context.Background()); got != nil {
		t.Fatalf("empty context returned checker %v, want nil", got)
	}
}

func TestInjectorPinCheckerRoundTrip(t *testing.T) {
	inj := &Injector{}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(&policy.Engine{Default: policy.Allow})
	checker := NewRequestPolicyChecker(ptr, nil)

	inj.PinChecker("pin-abc", checker)
	if got := inj.lookupChecker("pin-abc"); got != checker {
		t.Fatalf("lookupChecker returned %v, want %v", got, checker)
	}

	// UnpinIPs should also evict the checker so connection teardown cleans
	// both maps. Otherwise long-lived proxies accumulate stale checkers.
	inj.UnpinIPs("pin-abc")
	if got := inj.lookupChecker("pin-abc"); got != nil {
		t.Fatalf("lookupChecker after UnpinIPs = %v, want nil", got)
	}
}

func TestInjectorPinCheckerNilNoop(t *testing.T) {
	inj := &Injector{}
	inj.PinChecker("pin-xyz", nil)
	if got := inj.lookupChecker("pin-xyz"); got != nil {
		t.Fatalf("storing nil checker leaked entry: %v", got)
	}
}

func TestProxyConnStateUserDataShape(t *testing.T) {
	// Guard against a regression where UserData falls back to a bare string.
	// The HandleConnect callback is expected to install a proxyConnState so
	// pin ID, checker, and CONNECT target are available to inner request handlers.
	state := proxyConnState{pinID: "pin-123", connectHost: "api.example.com", connectPort: 443}
	if state.pinID != "pin-123" {
		t.Fatalf("pinID = %q, want pin-123", state.pinID)
	}
	if state.checker != nil {
		t.Fatal("default proxyConnState.checker should be nil")
	}
	if state.connectHost != "api.example.com" {
		t.Fatalf("connectHost = %q, want api.example.com", state.connectHost)
	}
	if state.connectPort != 443 {
		t.Fatalf("connectPort = %d, want 443", state.connectPort)
	}
}

// newTestRuleSetWithStore builds a policyRuleSet backed by an in-memory
// SQLite store seeded from the given TOML snippet. Used for tests that
// exercise buildPersistFunc and the persistAlways* helpers against a real
// store + engine rather than a closure double.
func newTestRuleSetWithStore(t *testing.T, toml string, broker *channel.Broker) (*policyRuleSet, *store.Store) {
	t.Helper()
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if toml != "" {
		if _, importErr := s.ImportTOML([]byte(toml)); importErr != nil {
			t.Fatalf("store.ImportTOML: %v", importErr)
		}
	}
	eng, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatalf("policy.LoadFromStore: %v", err)
	}
	eng.TimeoutSec = 2

	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)

	return &policyRuleSet{
		engine:   ptr,
		reloadMu: new(sync.Mutex),
		broker:   broker,
		store:    s,
	}, s
}

// TestPolicyRuleSetBuildPersistFuncWritesAllowRule verifies that the
// closure returned by buildPersistFunc actually (a) writes a rule to the
// backing store and (b) swaps a recompiled engine in that matches the
// destination as Allow on the next Evaluate.
func TestPolicyRuleSetBuildPersistFuncWritesAllowRule(t *testing.T) {
	rules, s := newTestRuleSetWithStore(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, nil)

	persist := rules.buildPersistFunc()
	if persist == nil {
		t.Fatal("buildPersistFunc returned nil for a store-backed rule set")
	}
	persist(PersistAllow, "api.example.com", 443)

	// Verify the rule landed in the store.
	persisted, err := s.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	found := false
	for _, r := range persisted {
		if r.Destination == "api.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("buildPersistFunc did not write the allow rule to the store")
	}

	// Verify the engine was recompiled and now matches the destination.
	got, src := rules.engine.Load().EvaluateDetailed("api.example.com", 443)
	if got != policy.Allow || src != policy.RuleMatch {
		t.Fatalf("engine after persist: verdict=%v source=%v, want (Allow, RuleMatch)", got, src)
	}
}

// TestPolicyRuleSetBuildPersistFuncWritesDenyRule mirrors the allow test
// for the deny persist path.
func TestPolicyRuleSetBuildPersistFuncWritesDenyRule(t *testing.T) {
	rules, s := newTestRuleSetWithStore(t, `
[policy]
default = "allow"

[[ask]]
destination = "blocked.example.com"
`, nil)

	persist := rules.buildPersistFunc()
	if persist == nil {
		t.Fatal("buildPersistFunc returned nil for a store-backed rule set")
	}
	persist(PersistDeny, "blocked.example.com", 443)

	persisted, err := s.ListRules(store.RuleFilter{Verdict: "deny"})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	found := false
	for _, r := range persisted {
		if r.Destination == "blocked.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("buildPersistFunc did not write the deny rule to the store")
	}

	got, src := rules.engine.Load().EvaluateDetailed("blocked.example.com", 443)
	if got != policy.Deny || src != policy.RuleMatch {
		t.Fatalf("engine after persist: verdict=%v source=%v, want (Deny, RuleMatch)", got, src)
	}
}

// TestPolicyRuleSetBuildPersistFuncNilWithoutStore verifies the helper
// returns nil when there is no store wired up, so the checker can safely
// fall back to log-only behavior.
func TestPolicyRuleSetBuildPersistFuncNilWithoutStore(t *testing.T) {
	rules := newTestRuleSet(t, `[policy]
default = "deny"`, nil)
	if persist := rules.buildPersistFunc(); persist != nil {
		t.Fatal("buildPersistFunc should return nil when the rule set has no store")
	}
}

// TestAllowAlwaysAllowPersistFailureAttachesChecker verifies that when the
// ask->AlwaysAllow persistence path fails (store closed), Allow() does
// NOT set ctxKeySkipPerRequest and instead attaches a per-request checker
// as a safety net. This is the critical iteration-2 blind spot: a broken
// string match ("reason == user approved always") would have set the
// skip flag regardless of success.
func TestAllowAlwaysAllowPersistFailureAttachesChecker(t *testing.T) {
	fc := newFakeChannel(channel.ResponseAlwaysAllow)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	rules, s := newTestRuleSetWithStore(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, broker)
	// Close the store BEFORE the Allow() call so AddRule fails. The
	// in-memory engine snapshot still matches the destination as Ask, so
	// the checker path must re-evaluate every request and ask the user
	// again.
	_ = s.Close()

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com", 443))
	if !ok {
		t.Fatal("Allow returned false after ask->always-allow")
	}
	// The skip flag must NOT be set because persistence failed.
	if skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool); skip {
		t.Fatal("ctxKeySkipPerRequest must NOT be set when always-allow persistence fails")
	}
	checker, _ := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker)
	if checker == nil {
		t.Fatal("expected a per-request checker as safety net when always-allow persistence fails")
	}
}
