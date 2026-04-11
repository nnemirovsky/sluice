package proxy

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
)

// PersistVerdict tells the PersistRuleFunc which side of a
// ResponseAlways* approval to persist into the policy store.
type PersistVerdict int

const (
	// PersistAllow persists an allow rule for the destination.
	PersistAllow PersistVerdict = iota
	// PersistDeny persists a deny rule for the destination.
	PersistDeny
)

// PersistRuleFunc persists a new allow/deny rule for dest:port to the
// backing store and atomically swaps in a fresh compiled policy engine so
// subsequent requests match via the engine fast path instead of re-entering
// the checker. Called by RequestPolicyChecker when a per-request approval
// resolves to ResponseAlwaysAllow or ResponseAlwaysDeny.
//
// Implementations must be safe to call from arbitrary goroutines and must
// handle internal failures (store write, engine recompile) without
// panicking. Errors are logged, not returned, because the per-request
// approval already resolved and the current request must proceed.
type PersistRuleFunc func(verdict PersistVerdict, dest string, port int)

// RequestPolicyChecker performs per-HTTP-request policy evaluation within a
// single SOCKS5 connection. Unlike the connection-level check in
// policyRuleSet.Allow(), this checker re-evaluates policy for every HTTP
// request so that keep-alive connections cannot silently funnel multiple
// requests through a single "Allow Once" approval.
//
// Lifecycle: one RequestPolicyChecker per SOCKS5 TCP connection. It is
// created by the SOCKS5 rule set (or the SNI-deferred handler) and threaded
// through to the HTTP MITM handler via ProxyCtx.UserData.
//
// Seeded credits: when the SOCKS5 or SNI layer has already obtained an
// ask->ResponseAllowOnce approval for the CONNECT tunnel, the checker is
// created with one or more prepaid allow credits. CheckAndConsume consumes
// a credit on the first call without contacting the broker so the first
// HTTP request does not double-prompt the user. Subsequent calls re-enter
// the broker normally.
//
// Thread-safety: HTTP/2 (gRPC) streams may invoke CheckAndConsume
// concurrently on the same connection. The seed counter is guarded by a
// mutex so exactly one concurrent caller consumes a given credit. The rest
// of the checker holds no mutable state.
type RequestPolicyChecker struct {
	enginePtr *atomic.Pointer[policy.Engine]
	broker    *channel.Broker
	// persist writes a new rule to the store and swaps in a fresh
	// compiled engine when a per-request ask approval resolves to
	// ResponseAlwaysAllow or ResponseAlwaysDeny. Nil when the checker has
	// no store access (tests, standalone runs); in that case the current
	// request still gets the correct verdict but the next request on this
	// connection re-enters the approval flow.
	persist PersistRuleFunc

	// seedMu guards seedCredits so concurrent HTTP/2 streams consume the
	// prepaid allow credits safely.
	seedMu sync.Mutex
	// seedCredits is the number of prepaid allow credits left from the
	// connection-level ask approval. Each credit allows one CheckAndConsume
	// call to return policy.Allow without contacting the broker. Starts at
	// 1 when the SOCKS5 CONNECT resolved to ResponseAllowOnce, 0 otherwise.
	seedCredits int
}

// CheckerOption configures an optional field on a RequestPolicyChecker at
// construction time. Use WithPersist and WithSeedCredits to enable the
// persistence callback and prepaid allow credits respectively.
type CheckerOption func(*RequestPolicyChecker)

// WithPersist attaches a persistence callback that is invoked when a per-
// request approval resolves to ResponseAlwaysAllow or ResponseAlwaysDeny.
// The callback is responsible for writing the rule to the store and
// swapping in a recompiled engine. A nil persist is equivalent to omitting
// this option (the checker logs a warning when it would have persisted).
func WithPersist(persist PersistRuleFunc) CheckerOption {
	return func(c *RequestPolicyChecker) {
		c.persist = persist
	}
}

// WithSeedCredits sets the number of prepaid allow credits. Each credit is
// consumed by the next CheckAndConsume call (regardless of destination),
// returning policy.Allow without contacting the broker. This is how
// connection-level ask approvals (ResponseAllowOnce from SOCKS5 CONNECT or
// SNI) avoid double-prompting the user when the first HTTP request re-
// enters policy evaluation. Negative values are clamped to 0.
func WithSeedCredits(seed int) CheckerOption {
	return func(c *RequestPolicyChecker) {
		if seed < 0 {
			seed = 0
		}
		c.seedCredits = seed
	}
}

// NewRequestPolicyChecker creates a checker bound to a policy engine
// pointer and optional approval broker. The engine pointer allows each
// request to evaluate against the latest policy snapshot (e.g. after a
// SIGHUP). A nil broker treats ask verdicts as deny.
//
// Options:
//   - WithPersist: attach a persistence callback for ResponseAlways* approvals.
//   - WithSeedCredits: prepay N allow credits consumed before the broker is
//     contacted (used to avoid double-prompting after a connection-level
//     ask->AllowOnce approval).
func NewRequestPolicyChecker(enginePtr *atomic.Pointer[policy.Engine], broker *channel.Broker, opts ...CheckerOption) *RequestPolicyChecker {
	c := &RequestPolicyChecker{
		enginePtr: enginePtr,
		broker:    broker,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// consumeSeed returns true and decrements the credit counter when a prepaid
// allow credit is available. Returns false otherwise. Thread-safe.
func (c *RequestPolicyChecker) consumeSeed() bool {
	c.seedMu.Lock()
	defer c.seedMu.Unlock()
	if c.seedCredits <= 0 {
		return false
	}
	c.seedCredits--
	return true
}

// CheckAndConsume evaluates policy for a single HTTP request targeting
// dest:port and returns the final verdict for that request.
//
// Semantics:
//   - Prepaid seed credit: if the checker was constructed with a seed via
//     WithSeedCredits, the first N calls consume one credit each and return
//     policy.Allow without contacting the broker. This is how connection-
//     level ask approvals avoid double-prompting the user when the first
//     HTTP request re-enters policy evaluation.
//   - Deny rule or default deny: returns Deny immediately.
//   - Explicit allow rule: returns Allow without triggering the broker.
//   - Ask rule or default ask: triggers the approval broker. On
//     ResponseAllowOnce the current request is permitted and the next
//     CheckAndConsume re-triggers the ask flow so "Allow Once" truly
//     means one HTTP request.
//   - ResponseAlwaysAllow / ResponseAlwaysDeny: the current request gets
//     the corresponding verdict AND the checker invokes its persistence
//     callback to write the rule to the store and recompile the engine.
//     Subsequent requests (on this connection or any new connection)
//     match the freshly persisted rule via the engine fast path.
func (c *RequestPolicyChecker) CheckAndConsume(dest string, port int, opts ...CheckOption) (policy.Verdict, error) {
	if c == nil {
		return policy.Allow, nil
	}
	if c.enginePtr == nil {
		return policy.Deny, fmt.Errorf("policy engine pointer not set")
	}
	eng := c.enginePtr.Load()
	if eng == nil {
		return policy.Deny, fmt.Errorf("policy engine not loaded")
	}
	checkCtx := checkContext{}
	for _, opt := range opts {
		opt(&checkCtx)
	}
	// Evaluate against the engine first so explicit deny rules always win
	// over the prepaid seed credit. A destination that was allow-once'd at
	// CONNECT time but subsequently added to a deny list (via another
	// approval or SIGHUP) must still be blocked by the engine.
	var verdict policy.Verdict
	if checkCtx.protocol != "" {
		verdict, _ = eng.EvaluateDetailedWithProtocol(dest, port, checkCtx.protocol)
	} else {
		verdict, _ = eng.EvaluateDetailed(dest, port)
	}
	switch verdict {
	case policy.Deny:
		return policy.Deny, nil
	case policy.Allow:
		return policy.Allow, nil
	case policy.Ask:
		// The engine still returns Ask. Prefer the prepaid seed credit so
		// the first post-CONNECT request flows through without a second
		// approval prompt. Subsequent calls (seed exhausted) fall back to
		// the broker as usual.
		if c.consumeSeed() {
			log.Printf("[REQ-SEED-ALLOW] %s:%d (seeded allow-once credit consumed)", dest, port)
			return policy.Allow, nil
		}
		return c.resolveAsk(dest, port, eng, checkCtx)
	default:
		// Redact is not a network verdict. Treat unknown as deny.
		return policy.Deny, nil
	}
}

// checkContext carries optional metadata about the HTTP request being
// checked. It lets callers attach request-scoped context (method, path,
// protocol) that the broker forwards to channels for per-request approval
// rendering and that the engine uses for protocol-scoped rule matching.
type checkContext struct {
	method          string
	path            string
	protocol        string
	bypassRateLimit bool
}

// CheckOption configures optional metadata on a CheckAndConsume call.
type CheckOption func(*checkContext)

// WithRequestInfo attaches the HTTP method and path of the request being
// checked. Channels use this to render per-request approval messages such
// as "GET https://example.com/users". Empty strings are ignored so callers
// can pass partial information without overwriting previously set fields.
func WithRequestInfo(method, path string) CheckOption {
	return func(c *checkContext) {
		if method != "" {
			c.method = method
		}
		if path != "" {
			c.path = path
		}
	}
}

// WithProtocol pins the protocol name used for engine evaluation so
// protocol-scoped rules (e.g. protocols=["grpc"], ["ws"]) can match on a
// per-request basis. Pass the refined protocol from
// DetectProtocolFromHeaders here. An empty string falls back to port-based
// protocol detection (same as calling without this option).
func WithProtocol(proto string) CheckOption {
	return func(c *checkContext) {
		c.protocol = proto
	}
}

// WithSkipBrokerRateLimit signals that the broker should skip its per-
// destination rate limiter for this approval request. Use this for
// per-request policy callers so that a keep-alive connection to a single
// destination can trigger more than 5 approvals per minute without
// silently 403ing once the broker's rate limit kicks in. Connection-level
// approvals still go through the rate limiter.
//
// Distinct from channel.WithBypassRateLimit (which is the broker-side
// option this option ultimately forwards to) so package-qualified and
// unqualified call sites are unambiguous in a mixed-import file.
func WithSkipBrokerRateLimit() CheckOption {
	return func(c *checkContext) {
		c.bypassRateLimit = true
	}
}

// resolveAsk triggers the approval broker for an ask verdict and, on
// ResponseAlwaysAllow / ResponseAlwaysDeny, persists the new rule via the
// checker's persistence callback (if configured).
func (c *RequestPolicyChecker) resolveAsk(dest string, port int, eng *policy.Engine, ctx checkContext) (policy.Verdict, error) {
	if c.broker == nil {
		log.Printf("[REQ-ASK->DENY] %s:%d (no approval broker)", dest, port)
		return policy.Deny, nil
	}

	timeout := time.Duration(eng.TimeoutSec) * time.Second
	proto := ctx.protocol
	if proto == "" {
		proto = DetectProtocol(port).String()
	}
	log.Printf("[REQ-ASK] %s:%d (per-request approval)", dest, port)
	var reqOpts []channel.RequestOption
	if ctx.method != "" || ctx.path != "" {
		reqOpts = append(reqOpts, channel.WithMethodAndPath(ctx.method, ctx.path))
	}
	if ctx.bypassRateLimit {
		reqOpts = append(reqOpts, channel.WithBypassRateLimit())
	}
	resp, err := c.broker.Request(dest, port, proto, timeout, reqOpts...)
	if err != nil {
		log.Printf("[REQ-ASK->DENY] %s:%d (approval error: %v)", dest, port, err)
		return policy.Deny, err
	}
	switch resp {
	case channel.ResponseAllowOnce:
		log.Printf("[REQ-ASK->ALLOW] %s:%d (user approved once, per-request)", dest, port)
		return policy.Allow, nil
	case channel.ResponseAlwaysAllow:
		log.Printf("[REQ-ASK->ALLOW+SAVE] %s:%d (user approved always, per-request)", dest, port)
		if c.persist != nil {
			c.persist(PersistAllow, dest, port)
		} else {
			log.Printf("[WARN] per-request always-allow for %s:%d not persisted (no store callback)", dest, port)
		}
		return policy.Allow, nil
	case channel.ResponseAlwaysDeny:
		log.Printf("[REQ-ASK->DENY+SAVE] %s:%d (user denied always, per-request)", dest, port)
		if c.persist != nil {
			c.persist(PersistDeny, dest, port)
		} else {
			log.Printf("[WARN] per-request always-deny for %s:%d not persisted (no store callback)", dest, port)
		}
		return policy.Deny, nil
	default:
		log.Printf("[REQ-ASK->DENY] %s:%d (user denied, per-request)", dest, port)
		return policy.Deny, nil
	}
}
