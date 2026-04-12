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

// mkConnectRequest produces a minimal CONNECT request targeting host:443.
func mkConnectRequest(host string) *socks5.Request {
	return &socks5.Request{
		Request: statute.Request{
			Command: statute.CommandConnect,
		},
		DestAddr: &statute.AddrSpec{
			FQDN: host,
			Port: 443,
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

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com"))
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

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("anything.example.com"))
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

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("anything.example.com"))
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

func TestAllowDefersAskToPerRequest(t *testing.T) {
	// When a broker is configured and the destination matches an ask rule,
	// Allow() auto-allows the SOCKS5 CONNECT without consulting the broker.
	// A checker with no seed credit is attached so every HTTP request
	// triggers its own per-request approval with method/path visible.
	fc := newFakeChannel(channel.ResponseAllowOnce)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	rules := newTestRuleSet(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, broker)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com"))
	if !ok {
		t.Fatal("Allow returned false for ask destination with broker")
	}
	if skip, _ := ctx.Value(ctxKeySkipPerRequest).(bool); skip {
		t.Fatal("ctxKeySkipPerRequest should NOT be set for ask-deferred connection")
	}
	checker, _ := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker)
	if checker == nil {
		t.Fatal("ask-deferred connection must attach a RequestPolicyChecker")
	}

	// Allow() must NOT have consulted the broker (deferred to per-request).
	if got := fc.requestCount(); got != 0 {
		t.Fatalf("broker count after Allow = %d, want 0 (deferred)", got)
	}

	// First HTTP request asks the broker (no seed credit).
	verdict, err := checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("first CheckAndConsume: %v", err)
	}
	if verdict != policy.Allow {
		t.Fatalf("first HTTP request verdict = %v, want Allow", verdict)
	}
	if got := fc.requestCount(); got != 1 {
		t.Fatalf("broker count after first request = %d, want 1", got)
	}

	// Second HTTP request also asks the broker.
	fc.setResponse(channel.ResponseDeny)
	verdict, err = checker.CheckAndConsume("api.example.com", 443)
	if err != nil {
		t.Fatalf("second CheckAndConsume: %v", err)
	}
	if verdict != policy.Deny {
		t.Fatalf("second HTTP request verdict = %v, want Deny", verdict)
	}
	if got := fc.requestCount(); got != 2 {
		t.Fatalf("broker count after second request = %d, want 2", got)
	}
}

func TestAllowDefersAskWithBrokerDoesNotPrompt(t *testing.T) {
	// With a broker, ask destinations are auto-allowed at CONNECT time.
	// The broker is NOT consulted. The checker has no seed credit.
	// Verify that Always Allow responses are handled per-request (the
	// checker's persist callback handles rule persistence).
	fc := newFakeChannel(channel.ResponseAlwaysAllow)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker

	rules, _ := newTestRuleSetWithStore(t, `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
`, broker)

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com"))
	if !ok {
		t.Fatal("Allow returned false for ask destination with broker")
	}
	// Broker was NOT consulted at connection level.
	if got := fc.requestCount(); got != 0 {
		t.Fatalf("broker count = %d, want 0 (deferred)", got)
	}
	// Checker is attached (not skip).
	checker, _ := ctx.Value(ctxKeyPerRequestPolicy).(*RequestPolicyChecker)
	if checker == nil {
		t.Fatal("checker should be attached for ask-deferred connection")
	}
}

func TestAllowAttachesNoCheckerOnDeny(t *testing.T) {
	rules := newTestRuleSet(t, `
[policy]
default = "deny"
`, nil)

	_, ok := rules.Allow(context.Background(), mkConnectRequest("blocked.example.com"))
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

func TestAddonPendingCheckerRoundTrip(t *testing.T) {
	addon := NewSluiceAddon()
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(&policy.Engine{Default: policy.Allow})
	checker := NewRequestPolicyChecker(ptr, nil)

	addon.PendingChecker("api.example.com:443", checker, false)
	pc := addon.consumePendingChecker("api.example.com:443")
	if pc == nil {
		t.Fatal("consumePendingChecker returned nil")
	}
	if pc.checker != checker {
		t.Fatalf("consumePendingChecker returned %v, want %v", pc.checker, checker)
	}

	// Second consume should return nil (consumed).
	if got := addon.consumePendingChecker("api.example.com:443"); got != nil {
		t.Fatalf("second consumePendingChecker returned %v, want nil", got)
	}
}

func TestAddonPendingCheckerSkip(t *testing.T) {
	addon := NewSluiceAddon()
	addon.PendingChecker("api.example.com:443", nil, true)
	pc := addon.consumePendingChecker("api.example.com:443")
	if pc == nil {
		t.Fatal("consumePendingChecker returned nil")
	}
	if !pc.skip {
		t.Fatal("expected skip=true")
	}
	if pc.checker != nil {
		t.Fatal("expected nil checker when skip=true")
	}
}

func TestConnStateShape(t *testing.T) {
	// Guard against a regression where connState shape changes break the
	// SOCKS5 -> addon handoff.
	state := connState{connectHost: "api.example.com", connectPort: 443}
	if state.checker != nil {
		t.Fatal("default connState.checker should be nil")
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

	ctx, ok := rules.Allow(context.Background(), mkConnectRequest("api.example.com"))
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
