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

// RequestPolicyChecker performs per-HTTP-request policy evaluation within a
// single SOCKS5 connection. Unlike the connection-level check in
// policyRuleSet.Allow(), this checker re-evaluates policy for every HTTP
// request so that keep-alive connections cannot silently funnel multiple
// requests through a single "Allow Once" approval.
//
// Lifecycle: one RequestPolicyChecker per SOCKS5 TCP connection. It is created
// by the SOCKS5 rule set (or the SNI-deferred handler) and threaded through
// to the HTTP MITM handler via ProxyCtx.UserData.
//
// Thread-safety: HTTP/2 (gRPC) streams may invoke CheckAndConsume concurrently
// on the same connection, so all state mutations are guarded by a mutex.
type RequestPolicyChecker struct {
	enginePtr *atomic.Pointer[policy.Engine]
	broker    *channel.Broker

	mu          sync.Mutex
	allowedOnce map[string]bool // dest:port -> previous allow-once was consumed
}

// NewRequestPolicyChecker creates a checker bound to a policy engine pointer
// and optional approval broker. The engine pointer allows each request to
// evaluate against the latest policy snapshot (e.g. after a SIGHUP). A nil
// broker treats ask verdicts as deny.
func NewRequestPolicyChecker(enginePtr *atomic.Pointer[policy.Engine], broker *channel.Broker) *RequestPolicyChecker {
	return &RequestPolicyChecker{
		enginePtr:   enginePtr,
		broker:      broker,
		allowedOnce: make(map[string]bool),
	}
}

// CheckAndConsume evaluates policy for a single HTTP request targeting
// dest:port and returns the final verdict for that request.
//
// Semantics:
//   - Deny rule or default deny: returns Deny immediately.
//   - Explicit allow rule: returns Allow without triggering the broker.
//   - Ask rule or default ask: triggers the approval broker. On
//     ResponseAllowOnce the current request is permitted and the destination
//     is marked as having consumed an allow-once slot. The next
//     CheckAndConsume for the same dest:port re-triggers the ask flow so
//     "Allow Once" truly means one HTTP request.
//   - ResponseAlwaysAllow / ResponseAlwaysDeny: returns Allow or Deny without
//     tracking. The SOCKS5 layer (not the checker) is responsible for
//     persisting the new rule to the store, so subsequent requests bypass the
//     checker via an explicit rule match.
func (c *RequestPolicyChecker) CheckAndConsume(dest string, port int) (policy.Verdict, error) {
	if c == nil {
		return policy.Allow, nil
	}
	eng := c.enginePtr.Load()
	if eng == nil {
		return policy.Deny, fmt.Errorf("policy engine not loaded")
	}
	verdict, _ := eng.EvaluateDetailed(dest, port)
	switch verdict {
	case policy.Deny:
		return policy.Deny, nil
	case policy.Allow:
		return policy.Allow, nil
	case policy.Ask:
		return c.resolveAsk(dest, port, eng)
	default:
		// Redact is not a network verdict. Treat unknown as deny.
		return policy.Deny, nil
	}
}

// resolveAsk triggers the approval broker for an ask verdict and tracks
// consumed allow-once slots so subsequent requests re-ask.
func (c *RequestPolicyChecker) resolveAsk(dest string, port int, eng *policy.Engine) (policy.Verdict, error) {
	key := requestKey(dest, port)

	if c.broker == nil {
		log.Printf("[REQ-ASK->DENY] %s:%d (no approval broker)", dest, port)
		return policy.Deny, nil
	}

	timeout := time.Duration(eng.TimeoutSec) * time.Second
	proto := DetectProtocol(port)
	log.Printf("[REQ-ASK] %s:%d (per-request approval)", dest, port)
	resp, err := c.broker.Request(dest, port, proto.String(), timeout)
	if err != nil {
		log.Printf("[REQ-ASK->DENY] %s:%d (approval error: %v)", dest, port, err)
		return policy.Deny, err
	}
	switch resp {
	case channel.ResponseAllowOnce:
		log.Printf("[REQ-ASK->ALLOW] %s:%d (user approved once, per-request)", dest, port)
		// Mark the destination as having consumed one allow-once slot. The
		// next CheckAndConsume will see the marker and re-trigger the ask
		// flow (by calling the broker again). The marker itself is kept so
		// that operators can inspect checker state and so tests can assert
		// that an allow-once was previously consumed on this connection.
		c.mu.Lock()
		c.allowedOnce[key] = true
		c.mu.Unlock()
		return policy.Allow, nil
	case channel.ResponseAlwaysAllow:
		// Engine persistence happens at the SOCKS5 layer. Return Allow so the
		// current request proceeds; once the new allow rule is live, future
		// requests match an explicit rule and skip the broker entirely.
		log.Printf("[REQ-ASK->ALLOW] %s:%d (user approved always, per-request)", dest, port)
		return policy.Allow, nil
	case channel.ResponseAlwaysDeny:
		log.Printf("[REQ-ASK->DENY] %s:%d (user denied always, per-request)", dest, port)
		return policy.Deny, nil
	default:
		log.Printf("[REQ-ASK->DENY] %s:%d (user denied, per-request)", dest, port)
		return policy.Deny, nil
	}
}

// ConsumedAllowOnce reports whether a previous CheckAndConsume call for
// dest:port recorded an allow-once approval. Used by tests to assert internal
// state and by diagnostic tooling.
func (c *RequestPolicyChecker) ConsumedAllowOnce(dest string, port int) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allowedOnce[requestKey(dest, port)]
}

func requestKey(dest string, port int) string {
	return fmt.Sprintf("%s:%d", dest, port)
}
