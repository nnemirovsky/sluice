package proxy

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"time"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/vault"
)

// failoverClass is the result of classifying an upstream response for a
// pooled destination.
type failoverClass int

const (
	// failoverNone means the response is not a failover trigger (2xx, 5xx,
	// or any 4xx that is not an exhaustion/auth signal). Phase 2 deliberately
	// does NOT fail over on 5xx: a server-side error is not evidence that the
	// active member's account is exhausted or revoked, and rolling onto the
	// next member would just spread a transient upstream outage across every
	// account in the pool. 5xx and everything else is a documented no-op.
	failoverNone failoverClass = iota
	// failoverRateLimited: the active member is quota-exhausted / throttled
	// (HTTP 429, or HTTP 403 whose body names quota exhaustion). Short cooldown
	// (RateLimitCooldown) because rate limits roll off within the provider's
	// window.
	failoverRateLimited
	// failoverAuthFailure: the active member's token is rejected (HTTP 401, or
	// a token-endpoint body of invalid_grant / invalid_token). Long cooldown
	// (AuthFailCooldown) because a revoked/expired refresh token will not
	// self-heal quickly and retrying it thrashes a broken account.
	failoverAuthFailure
)

// reasonTag returns the short tag embedded in the audit Reason
// ("<pool>:<from>-><to>:<tag>") and the Telegram notice.
func failoverReasonTag(class failoverClass, statusCode int, bodyTag string) string {
	switch class {
	case failoverRateLimited:
		if statusCode == 403 {
			return "403"
		}
		return "429"
	case failoverAuthFailure:
		if statusCode == 401 {
			return "401"
		}
		if bodyTag != "" {
			return bodyTag
		}
		return "invalid_grant"
	default:
		return ""
	}
}

// classifyFailover inspects a response for a pooled destination and decides
// whether it is a failover trigger.
//
// Classification rules (status code is the primary signal; the body is only
// consulted for the documented 403/token-endpoint cases):
//
//   - HTTP 429                                      -> rate-limited
//   - HTTP 403 with body insufficient_quota / quota -> rate-limited
//   - HTTP 401                                      -> auth-failure
//   - token-endpoint body invalid_grant/invalid_token -> auth-failure
//   - 2xx, 5xx, and everything else                 -> no-op (documented)
//
// isTokenEndpoint is true when the request URL matched the OAuth token-URL
// index (so a body classification is only trusted on an actual token
// endpoint, not on an arbitrary API 4xx that happens to echo the string
// "invalid_grant" in unrelated prose). bodyTag returns the matched body
// token (for the audit reason) when the decision came from the body.
func classifyFailover(statusCode int, body []byte, isTokenEndpoint bool) (class failoverClass, bodyTag string) {
	switch {
	case statusCode == 429:
		return failoverRateLimited, ""
	case statusCode == 401:
		return failoverAuthFailure, ""
	case statusCode == 403:
		if bodyContainsAny(body, "insufficient_quota", "quota_exceeded", "quota exhausted", "rate_limit_exceeded") {
			return failoverRateLimited, ""
		}
		return failoverNone, ""
	}
	// Non-4xx-status path. Only a real token-endpoint body may be classified
	// (invalid_grant/invalid_token), and only when the status is not a 2xx
	// success. A 2xx token response is a healthy refresh, never a failover.
	if isTokenEndpoint && (statusCode < 200 || statusCode > 299) {
		if bodyContainsAny(body, "invalid_grant") {
			return failoverAuthFailure, "invalid_grant"
		}
		if bodyContainsAny(body, "invalid_token") {
			return failoverAuthFailure, "invalid_token"
		}
	}
	return failoverNone, ""
}

// bodyContainsAny reports whether body contains any of the substrings,
// case-insensitively. Bodies are bounded by maxProxyBody upstream so an
// in-memory scan is safe.
func bodyContainsAny(body []byte, subs ...string) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	for _, s := range subs {
		if bytes.Contains(lower, []byte(strings.ToLower(s))) {
			return true
		}
	}
	return false
}

// FailoverEvent describes a completed pool failover. It is handed to the
// optional onFailover callback (store durability write + Telegram notice)
// configured via SetOnFailover.
type FailoverEvent struct {
	Pool   string
	From   string
	To     string
	Reason string // short tag: 429 | 403 | 401 | invalid_grant | invalid_token
	Class  failoverClass
	Until  time.Time // member cooldown expiry just applied
}

// poolForResponse maps a response's CONNECT destination back to a pooled
// binding and returns the pool name + the member that was active for this
// request. Returns ok=false when the destination is not bound to a pool.
func (a *SluiceAddon) poolForResponse(f *mitmproxy.Flow) (pool, activeMember string, pr *vault.PoolResolver, ok bool) {
	if a.poolResolver == nil || a.resolver == nil {
		return "", "", nil, false
	}
	pr = a.poolResolver.Load()
	if pr == nil {
		return "", "", nil, false
	}
	res := a.resolver.Load()
	if res == nil {
		return "", "", nil, false
	}
	host, port := connectTargetForFlow(a, f)
	if host == "" {
		return "", "", nil, false
	}
	// The Response addon path is HTTP/HTTPS/HTTP2 (gRPC). Bindings without
	// an explicit protocol list match any protocol; pass "https" so a
	// protocol-scoped binding still resolves on the common case.
	for _, boundName := range res.CredentialsForDestination(host, port, "https") {
		if !pr.IsPool(boundName) {
			continue
		}
		member, mok := pr.ResolveActive(boundName)
		if !mok || member == "" {
			continue
		}
		return boundName, member, pr, true
	}
	return "", "", nil, false
}

// handlePoolFailover is the Phase 2 entry point invoked from Response for
// every response. It is a cheap no-op for the overwhelming common case
// (destination is not pooled, or the response is a success / 5xx). When the
// response classifies as a failover trigger for the active pool member it:
//
//  1. Synchronously marks the active member in cooldown in the in-memory
//     PoolResolver BEFORE this function returns, so the very next request
//     resolves to the next member. This is the I1 fix: the active-member
//     switch must NOT wait on the 2s data-version watcher. The store write
//     below only reconciles for durability across restarts.
//  2. Computes the next active member (post-cooldown) for the audit/notice.
//  3. Hands a FailoverEvent to the onFailover callback (async, best-effort):
//     the callback persists SetCredentialHealth to the store and fires the
//     Telegram notice. The callback MUST NOT block the response path.
//
// No in-flight retry: the triggering request still returns its own upstream
// error to the agent unmodified. The agent (or its SDK) retries on its own
// schedule, and that retry resolves to the freshly-activated next member.
// Transparent in-flight retry is intentionally out of scope (see the plan's
// "Out of scope" section) — buffering and replaying an arbitrary upstream
// request body/headers safely is a separate, larger change.
func (a *SluiceAddon) handlePoolFailover(f *mitmproxy.Flow) {
	if f == nil || f.Response == nil || f.Request == nil {
		return
	}
	pool, from, pr, ok := a.poolForResponse(f)
	if !ok {
		return
	}

	isTokenEndpoint := false
	if idx := a.oauthIndex.Load(); idx != nil {
		_, isTokenEndpoint = idx.Match(f.Request.URL)
	}

	class, bodyTag := classifyFailover(f.Response.StatusCode, f.Response.Body, isTokenEndpoint)
	if class == failoverNone {
		return
	}

	ttl := vault.RateLimitCooldown
	if class == failoverAuthFailure {
		ttl = vault.AuthFailCooldown
	}
	until := time.Now().Add(ttl)
	tag := failoverReasonTag(class, f.Response.StatusCode, bodyTag)

	// (1) Synchronous in-memory health update BEFORE returning (Risk I1).
	// MarkCooldown takes the resolver's write lock; ResolveActive takes the
	// read lock, so the next request observes the new active member with no
	// dependency on the store-reconcile watcher.
	pr.MarkCooldown(from, until, tag)

	// (2) Recompute the active member now that `from` is cooling down. If
	// every member is in cooldown ResolveActive degrades to the
	// soonest-recovering one (possibly `from` itself); the notice still
	// records the attempted transition honestly.
	to := from
	if next, nok := pr.ResolveActive(pool); nok && next != "" {
		to = next
	}

	log.Printf("[POOL-FAILOVER] pool %q: %s -> %s (%s); member %q cooling down until %s",
		pool, from, to, tag, from, until.Format(time.RFC3339))

	// Audit: emit a cred_failover action with the documented Reason shape
	// "<pool>:<from>-><to>:<tag>". Safe to call with a nil auditLog. The
	// blake3 hash chain is appended synchronously by FileLogger.Log; the
	// write is local and fast (mirrors logDLPAudit on the same path), so it
	// does not warrant detaching like the store/Telegram side effects.
	if a.auditLog != nil {
		host, port := connectTargetForFlow(a, f)
		evt := audit.Event{
			Destination: host,
			Port:        port,
			Protocol:    "https",
			Verdict:     "failover",
			Action:      "cred_failover",
			Reason:      fmt.Sprintf("%s:%s->%s:%s", pool, from, to, tag),
			Credential:  from,
		}
		if err := a.auditLog.Log(evt); err != nil {
			log.Printf("[POOL-FAILOVER] audit log error: %v", err)
		}
	}

	// (3) Durability + Telegram via the callback. The callback is
	// responsible for being non-blocking (it runs the store write and the
	// Telegram send in its own goroutine); we still guard with a nil check.
	if a.onFailover != nil {
		a.onFailover(FailoverEvent{
			Pool:   pool,
			From:   from,
			To:     to,
			Reason: tag,
			Class:  class,
			Until:  until,
		})
	}
}
