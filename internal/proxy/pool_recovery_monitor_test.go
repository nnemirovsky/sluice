package proxy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// newMonitorTestServer builds a minimal Server (policy-only, no provider) for
// exercising the A2 recovery monitor in isolation. The monitor goroutine is
// already running (started in New); the test stores a pool resolver and drives
// the monitor via markPoolExhausted. recoveryMinReschedule is shortened so a
// just-expired-but-unhealthy reschedule does not slow the test.
func newMonitorTestServer(t *testing.T) *Server {
	t.Helper()
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatalf("policy load: %v", err)
	}
	srv, err := New(Config{ListenAddr: "127.0.0.1:0", Policy: eng})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.recoveryMinReschedule = time.Millisecond
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// twoMemberPool builds a 2-member failover pool resolver and stores it on the
// server. Returns the live resolver.
func twoMemberPool(t *testing.T, srv *Server, a, b string) *vault.PoolResolver {
	t.Helper()
	pool := store.Pool{Name: "p", Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: a, Position: 0},
		{Credential: b, Position: 1},
	}
	pr := vault.NewPoolResolver([]store.Pool{pool}, nil)
	srv.poolResolver.Store(pr)
	return pr
}

// waitFor polls cond up to timeout, returning whether it became true. Avoids a
// fixed Sleep so the monitor tests stay fast and deterministic.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// TestMarkPoolExhaustedEdge asserts the healthy->exhausted edge fires exactly
// once: the first call returns true, subsequent calls (the agent's retry storm)
// return false until the pool recovers.
func TestMarkPoolExhaustedEdge(t *testing.T) {
	srv := newMonitorTestServer(t)
	// No resolver / no recovery: a removed-but-marked pool would be cleaned up,
	// but here we only test the edge bookkeeping, so use a pool that stays
	// exhausted (no resolver -> scanRecovery clears it). Store a resolver whose
	// members are all cooling so it stays exhausted.
	pr := twoMemberPool(t, srv, "a", "b")
	far := time.Now().Add(time.Hour)
	pr.MarkCooldown("a", far, "429")
	pr.MarkCooldown("b", far, "429")

	if !srv.markPoolExhausted("p") {
		t.Fatal("first markPoolExhausted = false, want true (healthy->exhausted edge)")
	}
	for i := 0; i < 5; i++ {
		if srv.markPoolExhausted("p") {
			t.Fatalf("markPoolExhausted call %d = true, want false (already exhausted, no new edge)", i+2)
		}
	}
}

// TestExhaustedNoticeEdgeAcrossManyResponses asserts handlePoolFailover emits
// exactly one "exhausted" notice across many failing responses once the
// Server's edge gate is wired (A2: the edge, not the 30s window, is
// authoritative).
func TestExhaustedNoticeEdgeAcrossManyResponses(t *testing.T) {
	srv := newMonitorTestServer(t)
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
	// Wire the addon's exhaustion edge into the server (mirrors setupInjection).
	addon.SetOnPoolExhausted(srv.markPoolExhausted)
	// Share the same resolver between the addon and the server so the monitor
	// observes the cooldowns the failover path applies.
	srv.poolResolver.Store(prPtr.Load())
	srv.addon = addon
	client := setupAddonConn(addon, "auth.example.com:443")

	// Both members already failure-cooled for a long window: every response is
	// pool-exhausting.
	prPtr.Load().MarkCooldown("memA", time.Now().Add(time.Hour), "429")
	prPtr.Load().MarkCooldown("memB", time.Now().Add(time.Hour), "401")

	// New contract: the durable callback fires once per qualifying response
	// (decoupled from the notice dedup), but exactly one event carries
	// Notify=true — the healthy->exhausted edge. The operator notice is gated on
	// Notify, so this still proves "one exhausted notice across many responses"
	// (edge-gated, not per-response) while the durable store write runs on every
	// call.
	var calls, notices int32
	done := make(chan struct{}, 16)
	addon.SetOnFailover(func(ev FailoverEvent) {
		if !ev.Exhausted {
			t.Errorf("FailoverEvent.Exhausted = false, want true")
		}
		atomic.AddInt32(&calls, 1)
		if ev.Notify {
			atomic.AddInt32(&notices, 1)
		}
		done <- struct{}{}
	})

	// Ten back-to-back failing responses (the agent retry storm).
	for i := 0; i < 10; i++ {
		f := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
		addon.flowInjected.Tag(f.Id, "memA")
		addon.Response(f)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onFailover not invoked for the exhausted edge")
	}
	// Let any erroneous extra notice surface.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&notices); got != 1 {
		t.Fatalf("exhausted notices (Notify=true) = %d, want exactly 1 (edge-gated, not per-response)", got)
	}
	// The durable callback itself ran for every qualifying response.
	if got := atomic.LoadInt32(&calls); got != 10 {
		t.Fatalf("onFailover calls = %d, want 10 (durable callback fires per response, decoupled from the notice gate)", got)
	}
}

// TestRecoveryMonitorEdgeNoticeAndCallback asserts that on the
// exhausted->recovered edge the monitor fires exactly one recovered notice AND
// exactly one onPoolRecovered call.
func TestRecoveryMonitorEdgeNoticeAndCallback(t *testing.T) {
	srv := newMonitorTestServer(t)
	pr := twoMemberPool(t, srv, "a", "b")

	var notices, resets int32
	var mu sync.Mutex
	var recoveredNotice, recoveredCb string
	srv.SetOnPoolRecoveredNotice(func(pool string) {
		mu.Lock()
		recoveredNotice = pool
		mu.Unlock()
		atomic.AddInt32(&notices, 1)
	})
	srv.SetOnPoolRecovered(func(pool string) {
		mu.Lock()
		recoveredCb = pool
		mu.Unlock()
		atomic.AddInt32(&resets, 1)
	})

	// Both members cooling briefly: the pool is exhausted, then recovers.
	until := time.Now().Add(40 * time.Millisecond)
	pr.MarkCooldown("a", until, "429")
	pr.MarkCooldown("b", until, "429")

	if !srv.markPoolExhausted("p") {
		t.Fatal("markPoolExhausted = false, want true (edge)")
	}

	if !waitFor(2*time.Second, func() bool { return atomic.LoadInt32(&notices) == 1 }) {
		t.Fatalf("recovered notices = %d, want 1", atomic.LoadInt32(&notices))
	}
	// Let a wrongful second notice surface.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&notices); got != 1 {
		t.Fatalf("recovered notices = %d, want exactly 1", got)
	}
	if got := atomic.LoadInt32(&resets); got != 1 {
		t.Fatalf("onPoolRecovered calls = %d, want exactly 1", got)
	}
	mu.Lock()
	gotNotice, gotCb := recoveredNotice, recoveredCb
	mu.Unlock()
	if gotNotice != "p" || gotCb != "p" {
		t.Fatalf("recovered pool = notice:%q cb:%q, want p/p", gotNotice, gotCb)
	}
	// State cleared after recovery: a fresh edge can re-fire.
	if !srv.markPoolExhausted("p") {
		t.Fatal("post-recovery markPoolExhausted = false, want true (state was cleared)")
	}
}

// TestRecoveryMonitorUnequalCooldowns is the B1-shaped case: memA cools for a
// short window, memB for a far longer one. The monitor must wake at the SOONEST
// cooldown (~memA) and recover once when memA becomes healthy, even though memB
// is still cooling. Uses short injected durations (no 60s sleep).
func TestRecoveryMonitorUnequalCooldowns(t *testing.T) {
	srv := newMonitorTestServer(t)
	pr := twoMemberPool(t, srv, "memA", "memB")

	var notices int32
	srv.SetOnPoolRecoveredNotice(func(string) { atomic.AddInt32(&notices, 1) })

	// memA: short (recovers soon). memB: 6h (still cooling at recovery).
	pr.MarkCooldown("memA", time.Now().Add(40*time.Millisecond), "429")
	pr.MarkCooldown("memB", time.Now().Add(6*time.Hour), "429")

	if !srv.markPoolExhausted("p") {
		t.Fatal("markPoolExhausted = false, want true")
	}

	if !waitFor(2*time.Second, func() bool { return atomic.LoadInt32(&notices) == 1 }) {
		t.Fatalf("recovered notices = %d, want 1 (wake at soonest cooldown, recover on memA)", atomic.LoadInt32(&notices))
	}
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&notices); got != 1 {
		t.Fatalf("recovered notices = %d, want exactly 1 (memB still cooling must not re-fire)", got)
	}
	// memB must still be cooling (the recovery was driven solely by memA).
	if _, cooling := pr.CooldownUntil("memB"); !cooling {
		t.Fatal("memB no longer cooling, expected its 6h cooldown to persist through memA's recovery")
	}
}

// TestRecoveryMonitorPoolRemovedFiresNoNotice asserts a pool removed while
// exhausted has its state dropped and fires no recovered notice.
func TestRecoveryMonitorPoolRemovedFiresNoNotice(t *testing.T) {
	srv := newMonitorTestServer(t)
	pr := twoMemberPool(t, srv, "a", "b")
	pr.MarkCooldown("a", time.Now().Add(time.Hour), "429")
	pr.MarkCooldown("b", time.Now().Add(time.Hour), "429")

	var notices, resets int32
	srv.SetOnPoolRecoveredNotice(func(string) { atomic.AddInt32(&notices, 1) })
	srv.SetOnPoolRecovered(func(string) { atomic.AddInt32(&resets, 1) })

	if !srv.markPoolExhausted("p") {
		t.Fatal("markPoolExhausted = false, want true")
	}

	// Remove the pool from the resolver (membership change rebuilds the
	// resolver with no pools).
	srv.poolResolver.Store(vault.NewPoolResolver(nil, nil))
	// Wake the monitor so it observes the removal.
	srv.markPoolExhausted("p") // already-exhausted -> false, but harmless
	select {
	case srv.recoveryWake <- struct{}{}:
	default:
	}

	// The state entry must be dropped without any recovered notice/reset.
	if !waitFor(2*time.Second, func() bool {
		srv.poolExhaustMu.Lock()
		_, present := srv.poolExhausted["p"]
		srv.poolExhaustMu.Unlock()
		return !present
	}) {
		t.Fatal("exhaustion state for removed pool was not dropped")
	}
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&notices); got != 0 {
		t.Fatalf("recovered notices = %d, want 0 (removed pool fires no notice)", got)
	}
	if got := atomic.LoadInt32(&resets); got != 0 {
		t.Fatalf("onPoolRecovered calls = %d, want 0 (removed pool triggers no reset)", got)
	}
}

// TestRecoveryMonitorStopsCleanly asserts the monitor stops on shutdown and that
// stopping twice (Close after GracefulShutdown, or vice versa) does not panic.
func TestRecoveryMonitorStopsCleanly(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte("[policy]\ndefault = \"deny\"\n"))
	if err != nil {
		t.Fatalf("policy load: %v", err)
	}
	srv, err := New(Config{ListenAddr: "127.0.0.1:0", Policy: eng})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Double-stop must be idempotent (monitorStopOnce). Calling both shutdown
	// paths must not panic on a double close of monitorStop. (The second close
	// of the already-closed listener returns a benign "use of closed network
	// connection" error, which is unrelated to the monitor and ignored here.)
	if err := srv.GracefulShutdown(time.Second); err != nil {
		t.Fatalf("GracefulShutdown: %v", err)
	}
	_ = srv.Close() // must not panic on the monitorStop double-close
	// stopMonitors directly a third time also must not panic.
	srv.stopMonitors()

	// The monitor goroutine must have returned: a markPoolExhausted edge after
	// stop must not be serviced (no recovered notice ever fires).
	var notices int32
	srv.SetOnPoolRecoveredNotice(func(string) { atomic.AddInt32(&notices, 1) })
	pr := twoMemberPool(t, srv, "a", "b")
	pr.MarkCooldown("a", time.Now().Add(20*time.Millisecond), "429")
	pr.MarkCooldown("b", time.Now().Add(20*time.Millisecond), "429")
	srv.markPoolExhausted("p")
	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&notices); got != 0 {
		t.Fatalf("recovered notices = %d, want 0 (monitor stopped, must not service wakes)", got)
	}
}
