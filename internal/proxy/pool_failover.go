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
	uuid "github.com/satori/go.uuid"
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
	switch statusCode {
	case 429:
		return failoverRateLimited, ""
	case 401:
		return failoverAuthFailure, ""
	case 403:
		if bodyContainsAny(body, "insufficient_quota", "quota_exceeded", "quota exhausted", "rate_limit_exceeded") {
			return failoverRateLimited, ""
		}
		// NOT a quota signal: do not early-return. A 403 is still a non-2xx
		// status, so a real token-endpoint body of invalid_grant/invalid_token
		// must classify as auth-failure (consistent with the 400/401 path).
		// The shared non-2xx token-endpoint check below handles it; a 403 from
		// a non-token-endpoint with an unrelated body still resolves to
		// failoverNone there (the body is only trusted on a real token URL).
	}
	// Non-2xx-status path. Only a real token-endpoint body may be classified
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
//
// proto is the protocol detected for THIS request (the same value used for
// the protocol-scoped binding lookup). The caller threads it into the
// cred_failover audit event so the audit records the real protocol of the
// pooled binding (grpc / http2 / etc.) instead of a hardcoded "https".
func (a *SluiceAddon) poolForResponse(f *mitmproxy.Flow) (pool, activeMember, proto string, pr *vault.PoolResolver, ok bool) {
	if a.poolResolver == nil || a.resolver == nil {
		return "", "", "", nil, false
	}
	pr = a.poolResolver.Load()
	if pr == nil {
		return "", "", "", nil, false
	}
	res := a.resolver.Load()
	if res == nil {
		return "", "", "", nil, false
	}
	host, port := connectTargetForFlow(a, f)
	if host == "" {
		return "", "", "", nil, false
	}
	// Finding 3: the failover binding lookup MUST use the same protocol the
	// request-side injection (injectHeaders / buildPhantomPairs) used, not a
	// hardcoded "https". A protocol-scoped pooled binding (grpc / http2 /
	// any meta protocol) is invisible to a "https" lookup even though the
	// credential WAS injected for it, so its 429/401 would never fail over.
	// detectRequestProtocol mirrors the injection path exactly (URL scheme
	// then header refinement); for the common unscoped-binding case the
	// result is still https-equivalent so behavior is unchanged.
	proto = a.detectRequestProtocol(f, port).String()
	for _, boundName := range res.CredentialsForDestination(host, port, proto) {
		if !pr.IsPool(boundName) {
			continue
		}
		// Attribute the failover to the member that backed THIS request
		// when it was SENT, recovered by flow ID from the injection-time
		// tag. ResolveActive at response time is unsafe under concurrency:
		// a sibling request's 429 may have already switched the active
		// member, so attributing by response-time active would cool an
		// innocent member and park both accounts (Finding 1). Fall back to
		// ResolveActive only when no per-flow tag exists (e.g. the request
		// never went through the pooled injection path).
		if f != nil && f.Id != uuid.Nil {
			if injected, ok := a.flowInjected.Recover(f.Id); ok && injected != "" {
				// Only honor the tag if the injected member is still a
				// member of this pool (a membership change could have
				// raced); otherwise fall through to ResolveActive.
				if pr.PoolForMember(injected) == boundName {
					return boundName, injected, proto, pr, true
				}
			}
		}
		member, mok := pr.ResolveActive(boundName)
		if !mok || member == "" {
			continue
		}
		return boundName, member, proto, pr, true
	}

	// Token-endpoint path. An OAuth refresh hits the credential's token-URL
	// host (e.g. auth.openai.com), which has no pool binding — the pool
	// binding lives on the API host (e.g. api.openai.com). Without this the
	// token-endpoint 401 / invalid_grant classification is dead code for the
	// primary Codex deployment (only the 429/403 API-host path would ever
	// fire).
	//
	// CRITICAL-2: OAuthIndex.Match is 1:1 token_url->credential and returns
	// the FIRST matching index entry. For the documented primary deployment
	// (two Codex OAuth accounts in ONE pool sharing the SAME token URL
	// auth.openai.com) every member's index entry has an identical token
	// URL, so idx.Match ALWAYS returns the first entry regardless of which
	// member's refresh token is actually in the request body. Attributing
	// the failure by idx.Match alone cools the wrong member whenever the
	// failing member is not the first index entry (e.g. memA cooled by an
	// API 429, memB now active, memB's refresh invalid_grants -> idx.Match
	// returns memA -> innocent memA re-cooled, dead memB stays active ->
	// the pool thrashes the broken account forever).
	//
	// The correct join key is the per-member-UNIQUE real refresh token that
	// pass-2 injected into this exact request body — the SAME mechanism the
	// 2xx persist path (resolveOAuthResponseAttribution) uses. We Peek (not
	// Recover) the refresh-attribution map so the single-use tag survives
	// for the persist path; a token-endpoint FAILURE does not rotate the
	// refresh token and processOAuthResponseIfMatching is 2xx-only, so the
	// tag is still live here.
	//
	// Finding 2: idx.Match returns only the FIRST index entry, and
	// credential_meta is name-ordered. If a plain OAuth credential sorts
	// before the pool members and shares the token URL, idx.Match returns
	// the plain credential, pr.PoolForMember(matched) is "", the whole
	// block is skipped, and a pooled token-host 401 / invalid_grant never
	// fails over (no cooldown -> the broken member stays active forever).
	// Use MatchAll and find ANY pool sharing this token URL so the gate is
	// independent of which credential sorts first; the true owning member
	// is still recovered from the per-member-unique injected refresh token.
	if idx := a.oauthIndex.Load(); idx != nil && f.Request != nil {
		matches := idx.MatchAll(f.Request.URL)
		pool := ""
		matched := ""
		for _, c := range matches {
			if matched == "" {
				matched = c // preserve the deterministic-first as last resort
			}
			if p := pr.PoolForMember(c); p != "" {
				pool = p
				break
			}
		}
		if pool != "" {
			// Recover the TRUE owning member from the injected real
			// refresh token in the buffered request body.
			reqCT := ""
			if f.Request.Header != nil {
				reqCT = f.Request.Header.Get("Content-Type")
			}
			realRefresh := extractRequestRefreshToken(f.Request.Body, reqCT)
			if owner, ok := a.refreshAttr.Peek(realRefresh); ok && owner != "" {
				if ownerPool := pr.PoolForMember(owner); ownerPool != "" {
					return ownerPool, owner, proto, pr, true
				}
				// owner is no longer in any pool (membership change
				// raced the failure); fall through to the active-member
				// fallback below for a still-meaningful attribution.
			}
			// Fallback ONLY when the real refresh token cannot be
			// extracted / attributed: cool the ACTIVE member rather
			// than blindly the first index entry. The active member is
			// the one whose token was most likely just injected, so it
			// is strictly better than idx.Match's deterministic-first.
			if active, aok := pr.ResolveActive(pool); aok && active != "" {
				log.Printf("[POOL-FAILOVER] pool %q: could not attribute "+
					"token-endpoint failure via injected refresh token; "+
					"falling back to active member %q", pool, active)
				return pool, active, proto, pr, true
			}
			// Last resort: a pooled index match if any (preserves prior
			// behavior when even ResolveActive cannot decide; better than
			// no attribution at all).
			for _, c := range matches {
				if pr.PoolForMember(c) != "" {
					return pool, c, proto, pr, true
				}
			}
			return pool, matched, proto, pr, true
		}
	}
	return "", "", "", nil, false
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
	pool, from, proto, pr, ok := a.poolForResponse(f)
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
			// Same protocol used for the protocol-scoped binding lookup in
			// poolForResponse, NOT a hardcoded "https". For a grpc/http2
			// scoped pooled binding the audit must record the real protocol.
			Protocol:   proto,
			Verdict:    "failover",
			Action:     "cred_failover",
			Reason:     fmt.Sprintf("%s:%s->%s:%s", pool, from, to, tag),
			Credential: from,
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
