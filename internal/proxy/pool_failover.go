package proxy

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
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
	// 4xx-client-error token-endpoint path. Only a real token-endpoint body
	// may be classified (invalid_grant/invalid_token), and only on a 4xx
	// CLIENT error. A 2xx token response is a healthy refresh, never a
	// failover; a 5xx is a server-side error and is a documented NO-OP (a
	// transient upstream outage is not evidence the member's account is
	// exhausted or revoked — failing over would just spread the outage
	// across every account in the pool, see README + the failoverNone doc).
	// Restricting to [400,500) keeps every existing correct path (400/403
	// invalid_grant -> auth-failure) while excluding 5xx whose body happens
	// to echo "invalid_grant"/"invalid_token".
	if isTokenEndpoint && statusCode >= 400 && statusCode < 500 {
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

// minFloorForClass returns the lower clamp bound for a derived cooldown. A
// rate-limited member may be honored down to MinRateLimitFloor (a short real
// recovery window must be respected — the whole point of B1). An auth failure
// must never be retried in seconds: a revoked/expired token will not self-heal
// quickly, so the floor stays at AuthFailCooldown regardless of any hint.
func minFloorForClass(class failoverClass) time.Duration {
	if class == failoverAuthFailure {
		return vault.AuthFailCooldown
	}
	return vault.MinRateLimitFloor
}

// classDefaultCooldown is the flat fallback applied when the upstream sends no
// usable recovery hint header.
func classDefaultCooldown(class failoverClass) time.Duration {
	if class == failoverAuthFailure {
		return vault.AuthFailCooldown
	}
	return vault.RateLimitCooldown
}

// recoveryHintHeaders are the response headers, in precedence order, from
// which cooldownFromResponse derives the real recovery window. Retry-After is
// the standard signal; the x-ratelimit-reset* family is provider-specific
// (OpenAI emits per-resource reset hints). Each value is parsed as either a
// delta-seconds count, an HTTP-date (Retry-After only), or — for the reset
// family — a unix epoch.
var recoveryHintHeaders = []string{
	"Retry-After",
	"x-ratelimit-reset",
	"x-ratelimit-reset-requests",
	"x-ratelimit-reset-tokens",
}

// cooldownFromResponse derives the cooldown duration for a failed pool member
// from the upstream's recovery hint headers, clamped to the class bounds.
//
// Precedence: Retry-After (delta-seconds or HTTP-date), then the
// x-ratelimit-reset* family (delta-seconds or unix epoch). The first header
// that yields a positive duration wins. With NO usable hint the flat class
// default is returned (RateLimitCooldown / AuthFailCooldown), so behavior is
// unchanged from before B1 on responses that carry no hint.
//
// The parsed window is clamped to [minFloorForClass(class), MaxCooldown]: a
// rate-limit hint may shrink the cooldown down to MinRateLimitFloor (honoring
// a short real window), an auth failure stays floored at AuthFailCooldown, and
// any absurd/hostile value is capped at MaxCooldown so a member is never
// parked indefinitely.
//
// No body parsing in v1 (deferred until a real Codex 429 is captured — see the
// plan's Post-Completion note); only headers are consulted.
//
// Takes the response header directly (not *http.Response) so it works
// uniformly against the go-mitmproxy Flow's Response.Header at the call site
// and a plain http.Header in tests.
func cooldownFromResponse(class failoverClass, header http.Header) time.Duration {
	if header == nil {
		return classDefaultCooldown(class)
	}
	now := time.Now()
	for _, h := range recoveryHintHeaders {
		raw := strings.TrimSpace(header.Get(h))
		if raw == "" {
			continue
		}
		d, ok := parseRecoveryHint(h, raw, now)
		if !ok || d <= 0 {
			continue
		}
		return clampCooldown(class, d)
	}
	return classDefaultCooldown(class)
}

// parseRecoveryHint parses a single recovery-hint header value into a positive
// duration relative to now. It tries, in order:
//
//   - delta-seconds: a bare integer/decimal count of seconds from now (all
//     headers).
//   - HTTP-date: an absolute time (Retry-After only, per RFC 9110); the
//     duration is its distance from now.
//   - unix epoch: a large integer treated as seconds-since-epoch (the
//     x-ratelimit-reset* family commonly emits an absolute epoch).
//
// Returns ok=false when the value parses to nothing usable (negative,
// zero-after-now, unparseable). A delta value carrying a unit suffix (OpenAI's
// "1.5s" / "60ms" form) is handled via time.ParseDuration as a fallback.
//
// Non-finite (NaN, +Inf, -Inf) and out-of-range bare-numeric values are
// rejected up front: strconv.ParseFloat accepts all of them, NaN<0 and Inf<0
// are both false so the old `secs < 0` guard let them through, and the
// subsequent float->int64 conversion (delta `time.Duration(secs*1e9)` and
// epoch `int64(secs)`) is implementation-defined for those inputs and can wrap
// to a wrong (even negative) duration before clampCooldown runs. Any finite
// magnitude above maxRecoveryHintSeconds is also rejected — it is far larger
// than any real Retry-After / reset / epoch and would overflow int64 once
// multiplied into nanoseconds.
// maxRecoveryHintSeconds is the upper bound for a bare-numeric recovery hint
// (~31,000 years). Any larger value is not a real Retry-After / reset / unix
// epoch and is rejected: it is comfortably above a present-day epoch (~1.7e9)
// yet small enough that int64(secs) cannot overflow on the epoch branch.
const maxRecoveryHintSeconds = 1e12

func parseRecoveryHint(header, raw string, now time.Time) (time.Duration, bool) {
	// Bare numeric: delta-seconds for Retry-After; for the reset family it may
	// be either delta-seconds OR a unix epoch. Disambiguate by magnitude — a
	// value large enough to be a plausible epoch (>= ~ year 2001) is treated
	// as absolute, otherwise as a delta.
	if secs, err := strconv.ParseFloat(raw, 64); err == nil {
		// Reject negative, non-finite (NaN/±Inf), and absurdly large
		// magnitudes before any float->int64 conversion. maxRecoveryHintSeconds
		// (~31,000 years) comfortably exceeds any real epoch (~1.7e9 today) or
		// recovery delta, while staying well within int64 for the epoch
		// branch's int64(secs); the delta branch additionally caps in float
		// space (below) so secs*1e9 can never overflow int64 (~9.2e18).
		if secs < 0 || math.IsNaN(secs) || math.IsInf(secs, 0) || secs > maxRecoveryHintSeconds {
			return 0, false
		}
		const epochThreshold = 1_000_000_000 // ~2001-09; below this, treat as delta-seconds
		if header != "Retry-After" && secs >= epochThreshold {
			until := time.Unix(int64(secs), 0)
			if d := until.Sub(now); d > 0 {
				return d, true
			}
			return 0, false
		}
		// Delta path: cap in float space before the *float64(time.Second)
		// multiply so the int64(time.Duration) conversion can never overflow.
		// clampCooldown applies the real ceiling (MaxCooldown) afterward; this
		// only prevents the conversion itself from wrapping.
		deltaSec := secs
		if maxSec := vault.MaxCooldown.Seconds(); deltaSec > maxSec {
			deltaSec = maxSec
		}
		return time.Duration(deltaSec * float64(time.Second)), true
	}
	// HTTP-date (Retry-After absolute form, per RFC 9110). Only Retry-After is
	// permitted to carry an absolute HTTP-date; the x-ratelimit-reset* family is
	// numeric (delta-seconds / unix epoch / unit-suffixed duration) and must not
	// be coerced through HTTP-date parsing.
	if header == "Retry-After" {
		if t, err := http.ParseTime(raw); err == nil {
			if d := t.Sub(now); d > 0 {
				return d, true
			}
			return 0, false
		}
	}
	// Unit-suffixed duration (e.g. OpenAI "1.5s", "60ms").
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d, true
	}
	return 0, false
}

// clampCooldown bounds a derived cooldown to [minFloorForClass(class),
// MaxCooldown].
func clampCooldown(class failoverClass, d time.Duration) time.Duration {
	floor := minFloorForClass(class)
	if d < floor {
		return floor
	}
	if d > vault.MaxCooldown {
		return vault.MaxCooldown
	}
	return d
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
	// Exhausted is true when there was NO distinct member to fail over to
	// (every member is cooling and the soonest-recovering one is the member
	// that just failed). The cooldown is still applied to From for
	// durability, but this is a pool-exhaustion signal, not a real
	// transition: the operator notice and audit action say so, and it is
	// deduplicated so an agent's retry storm produces one line, not N.
	Exhausted bool
	// Epoch is the From member's membership epoch in the resolver
	// generation that produced this failover. The durable guarded write
	// commits only if (From, Pool, Epoch) is still a live membership row,
	// so a late callback firing after a remove/re-add cannot persist this
	// cooldown onto the re-created same-name successor (Cluster A #2).
	Epoch int64
	// Notify is true only when the operator notice/audit for this event
	// passed the dedup gate (a real transition's 30s window, or the
	// healthy->exhausted edge). The durable store write runs regardless of
	// Notify; only the Telegram notice is gated by it, so cooldown
	// persistence stays monotonic even when notices are suppressed.
	Notify bool
}

// humanizeFailoverReason maps a short reason tag (the same tag embedded in the
// audit Reason) to operator-friendly words, keeping the raw tag in parentheses
// so the technical detail is still visible. Unknown tags degrade gracefully:
// the raw tag is shown as "unknown reason (<tag>)" so the surrounding
// "... after %s." / "... to (%s)." clauses still read naturally instead of the
// redundant "failed over ... after failover (<tag>)".
//
// The empty-tag case is handled by FormatFailoverNotice (its sole caller),
// which short-circuits an empty reason and drops the reason clause entirely
// before ever calling here — so this function never needs an explicit ""
// branch (single source of truth for empty-reason wording lives there).
func humanizeFailoverReason(tag string) string {
	switch tag {
	case "429":
		return "rate limit (429)"
	case "403":
		return "quota exhausted (403)"
	case "401":
		return "auth failure (401)"
	case "invalid_grant":
		return "auth failure (invalid_grant)"
	case "invalid_token":
		return "auth failure (invalid_token)"
	default:
		return "unknown reason (" + tag + ")"
	}
}

// FormatFailoverNotice builds the plain-text, single-line operator notice for a
// completed pool failover. It is the human-facing Telegram/notice string only;
// it deliberately does NOT touch the audit Reason format. Kept as a pure
// function (no I/O, no server state) so it is directly unit-testable.
//
// Plain text only: the notice path (TelegramChannel.Notify) sends with no
// parse mode, so markdown/HTML would render literally — keep it sentence-style
// like sluice's other notices.
func FormatFailoverNotice(ev FailoverEvent) string {
	// An empty reason tag yields humanizeFailoverReason("") == "unknown
	// reason", which reads awkwardly inline ("... to fail over to (unknown
	// reason)." / "... after unknown reason."). When the tag is empty, drop
	// the reason clause entirely instead (Finding 5). The audit Reason format
	// is untouched - this only shapes the human-facing notice.
	if ev.Reason == "" {
		if ev.Exhausted {
			return fmt.Sprintf("Pool %q exhausted: all members are cooling down, no healthy account to fail over to.",
				ev.Pool)
		}
		return fmt.Sprintf("Pool %q failed over from %q to %q.",
			ev.Pool, ev.From, ev.To)
	}
	reason := humanizeFailoverReason(ev.Reason)
	if ev.Exhausted {
		return fmt.Sprintf("Pool %q exhausted: all members are cooling down, no healthy account to fail over to (%s).",
			ev.Pool, reason)
	}
	return fmt.Sprintf("Pool %q failed over from %q to %q after %s.",
		ev.Pool, ev.From, ev.To, reason)
}

// FormatPoolRecoveredNotice builds the plain-text, single-line operator notice
// emitted on the exhausted->recovered edge by the recovery monitor. Kept next
// to FormatFailoverNotice as a pure, directly-testable function. Plain text /
// sentence style for the same reason (the notice path sends with no parse
// mode, so markdown/HTML would render literally).
func FormatPoolRecoveredNotice(pool string) string {
	return fmt.Sprintf("Pool %q recovered: a healthy account is available again.", pool)
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

	// Round-12: recover the per-flow injected member ONCE, with a
	// NON-consuming Peek, before iterating the matching credentials.
	// CredentialsForDestination(dest:port) can return MULTIPLE matching
	// pools for one destination, but the request-side header injection used
	// exactly ONE binding (the first match). Two concrete bugs the old
	// per-pool consuming Recover had:
	//
	//  1. flowInjected.Recover is single-use. Calling it inside the loop let
	//     the FIRST matching pool consume the tag even when the tag belonged
	//     to a LATER pool; the earlier pool then hit the blind ResolveActive
	//     fallback (cooling an unrelated pool) and the later — correct —
	//     pool could no longer see its own tag.
	//  2. With no per-flow tag at all (a plain binding was used, or the
	//     request never went through pooled injection), the old code blindly
	//     cooled ResolveActive(boundName) for ANY matching pool even though
	//     this request never used that pool.
	//
	// Mirror how the token-endpoint path was hardened: a single
	// non-consuming Peek, and attribute a pool ONLY when the injected member
	// PROVES this request used THAT specific pool. No blind ResolveActive
	// fallback — without proof, skip the pool (no cooldown).
	injected := ""
	if f != nil && f.Id != uuid.Nil {
		if m, ok := a.flowInjected.Peek(f.Id); ok {
			injected = m
		}
	}
	for _, boundName := range res.CredentialsForDestination(host, port, proto) {
		if !pr.IsPool(boundName) {
			continue
		}
		// Attribute the failover to the member that backed THIS request
		// when it was SENT, recovered by flow ID from the injection-time
		// tag. ResolveActive at response time is unsafe under concurrency
		// (a sibling request's 429 may have already switched the active
		// member; cooling response-time-active would park an innocent
		// member, Finding 1) AND unsound without proof of pool usage
		// (cooling the active member of a merely dest-matching pool the
		// request never used, round-12). Only attribute when the per-flow
		// injected member resolves to THIS pool; otherwise skip it (no
		// cooldown). If the injected member left this pool (membership
		// raced), there is no longer a sound member to attribute to, so
		// likewise skip rather than blind-fall-back.
		if injected != "" && pr.PoolForMember(injected) == boundName {
			return boundName, injected, proto, pr, true
		}
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
		for _, c := range matches {
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
				// owner is not in any pool. Two cases now collapse here
				// because the refresh-attr map is no longer pool-only:
				//
				//  (1) Round-19 Finding 1: the PLAIN-credential injection
				//      path tags realRefresh -> <plain name> too (so the
				//      2xx persist path can attribute a plain refresh on a
				//      shared token URL 1:1). A plain refresh must NEVER
				//      cool a pool member.
				//  (2) A genuine pooled member whose membership raced the
				//      failure (it left the pool between inject and
				//      response).
				//
				// The refresh-attr tag alone can no longer tell them
				// apart, so it is NOT sufficient evidence for the
				// active-member fallback. Require the independent
				// pool-usage proof (flowInjected, set post-swap ONLY when
				// a pool phantom was actually present in this request):
				// case (2) still has it; case (1) never does. Without it,
				// fall through to the no-evidence path below, which
				// returns ok=false and cools nothing.
				injected, injOK := "", false
				if f.Id != uuid.Nil {
					injected, injOK = a.flowInjected.Peek(f.Id)
				}
				if !injOK || injected == "" {
					log.Printf("[POOL-FAILOVER] pool %q: token-endpoint failure "+
						"owner %q is not a pool member and no flow-injection "+
						"pool-usage tag exists; treating as a plain credential "+
						"sharing this token URL (not cooling any member)", pool, owner)
					// Plain credential (round-19 Finding 1): do not cool.
					// Fall through to the no-evidence return below.
				} else if active, aok := pr.ResolveActive(pool); aok && active != "" {
					log.Printf("[POOL-FAILOVER] pool %q: token-endpoint failure "+
						"owner %q left the pool (membership raced, flow-injection "+
						"tag confirms pooled usage); falling back to active "+
						"member %q", pool, owner, active)
					return pool, active, proto, pr, true
				}
			}
			// Finding 3: the refresh-attr tag could not attribute this
			// failure. A blind ResolveActive / first-index fallback here
			// over-applies the cooldown: a PLAIN (non-pool) OAuth
			// credential that merely SHARES this token URL with a pool
			// would, on its own 401 / invalid_grant, cool an unrelated
			// active pool member even though the failing request never
			// used the pool. The active-member fallback is only sound
			// when there is independent evidence THIS request actually
			// went through the pooled injection path. The injection-time
			// flow tag (set by buildPooledMemberPairs' sibling
			// flowInjected.Tag) is exactly that evidence and is keyed by
			// flow ID, so it survives a missing/expired refresh-attr tag
			// for a genuinely pooled refresh.
			if f.Id != uuid.Nil {
				if injected, iok := a.flowInjected.Recover(f.Id); iok && injected != "" {
					if injPool := pr.PoolForMember(injected); injPool != "" {
						return injPool, injected, proto, pr, true
					}
					// The injected member left the pool but the flow tag
					// still proves this request used the pool: cool the
					// pool's current active member.
					if active, aok := pr.ResolveActive(pool); aok && active != "" {
						log.Printf("[POOL-FAILOVER] pool %q: token-endpoint failure "+
							"injected member %q left the pool; falling back to "+
							"active member %q", pool, injected, active)
						return pool, active, proto, pr, true
					}
				}
			}
			// No refresh-attr tag AND no flow-injection tag: there is no
			// evidence this request used the pool. It is most likely a
			// plain OAuth credential that only happens to share the token
			// URL. Return ok=false so NO pool member is cooled (a blind
			// fallback here would park an innocent active member).
			log.Printf("[POOL-FAILOVER] pool %q: token-endpoint failure on a "+
				"shared token URL with no pooled-usage evidence (no refresh-attr "+
				"or flow-injection tag); not cooling any member (likely a plain "+
				"OAuth credential sharing this token URL)", pool)
			return "", "", "", nil, false
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
//     the callback persists SetCredentialHealth to the store (ALWAYS) and
//     fires the Telegram notice (only when ev.Notify is true). The callback is
//     invoked unconditionally — even for a notice-suppressed (deduped) event —
//     so the durable store write is decoupled from the notice gate and the
//     persisted cooldown stays monotonic through a sustained exhaustion. The
//     callback MUST NOT block the response path. Only the spam-prone log line
//     and audit row stay gated on the dedup decision (ev.Notify).
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

	// B1: derive the cooldown window from the upstream's recovery hints
	// (Retry-After / x-ratelimit-reset*) instead of the flat class TTL, so a
	// quota-exhausted member is parked for the REAL window rather than being
	// re-probed every RateLimitCooldown (60s). cooldownFromResponse clamps to
	// the class bounds and falls back to the flat default when no hint header
	// is present.
	ttl := cooldownFromResponse(class, f.Response.Header)
	until := time.Now().Add(ttl)
	tag := failoverReasonTag(class, f.Response.StatusCode, bodyTag)

	// (1) Synchronous in-memory health update BEFORE returning (Risk I1).
	// MarkCooldown takes the resolver's write lock; ResolveActive takes the
	// read lock, so the next request observes the new active member with no
	// dependency on the store-reconcile watcher.
	//
	// Cluster A: capture the FROM member's pool+epoch identity from THIS
	// resolver generation and thread it through MarkCooldown and the
	// FailoverEvent. If the membership was removed and `from` re-added under
	// the same name (a strictly greater epoch, or a different pool) before
	// this stale write lands, the identity no longer matches and the
	// re-created successor does NOT inherit this old response's cooldown.
	idPool, idEpoch, idOK := pr.IdentityForMember(from)
	if !idOK {
		// `from` is no longer a member of any pool in the current
		// generation (raced removal). There is no sound member to
		// attribute this cooldown to; skip it entirely rather than write
		// an unscoped cooldown a same-name re-add could inherit.
		return
	}
	pr.MarkCooldownScoped(from, idPool, idEpoch, until, tag)

	// (2) Recompute the active member now that `from` is cooling down. If
	// every member is in cooldown ResolveActive degrades to the
	// soonest-recovering one (possibly `from` itself); the notice still
	// records the attempted transition honestly.
	to := from
	if next, nok := pr.ResolveActive(pool); nok && next != "" {
		to = next
	}

	// A1: the pool is exhausted when NO member is healthy, not merely when
	// ResolveActive degraded back to `from` (to == from). The old `to == from`
	// test missed the flap case where the soonest-recovering degrade target is
	// a DIFFERENT still-cooling member: that produced a meaningless
	// "<from> -> <other>" cred_failover plus one Telegram notice per agent
	// retry even though there was no healthy account to serve. HasHealthyMember
	// mirrors ResolveActive's cooling()/lazy-expiry exactly, so it agrees with
	// the degrade decision made just above. `to` is still computed for the
	// real-transition notice/audit (the not-exhausted branch).
	exhausted := !pr.HasHealthyMember(pool)

	// Deduplicate identical signals within a short window. Concurrent
	// in-flight requests (pipelined agents) and retries that race the
	// synchronous MarkCooldown above would otherwise each emit one audit
	// row + one operator notice.
	//
	// A2: the "exhausted" notice is gated on the healthy->exhausted EDGE, not
	// the 30s window. onPoolExhausted (set by the Server) flips the per-pool
	// exhaustion state on the long-lived Server and returns true only on the
	// false->true edge, so a retry storm against an already-exhausted pool
	// emits exactly one notice and the edge also wakes the recovery monitor.
	// When the hook is unset (addon-only unit tests) fall back to the A1
	// collapsed 30s-window key so those tests keep their existing behavior.
	//
	// A real from->to transition is unchanged: it keeps its (pool, from, to,
	// tag) 30s-window key. The cooldown itself was already applied
	// unconditionally above, so suppressing the notice loses nothing.
	emit := false
	if exhausted {
		if a.onPoolExhausted != nil {
			emit = a.onPoolExhausted(pool)
		} else {
			emit = a.shouldEmitPoolNotice(pool, "*", "*", "exhausted")
		}
	} else {
		emit = a.shouldEmitPoolNotice(pool, from, to, tag)
	}

	// (3) Durability + Telegram via the callback. The callback is responsible
	// for being non-blocking (it runs the store write and the Telegram send in
	// its own goroutine); we still guard with a nil check. Fired
	// UNCONDITIONALLY — even when the notice is deduped (emit == false) — so the
	// durable cooldown write is decoupled from the notice gate: the store stays
	// monotonically up to date through a sustained exhaustion/retry storm where
	// every notice after the first edge is suppressed. Only the operator-facing
	// Telegram notice is gated, via Notify=emit; the callback itself runs the
	// durable store write regardless of Notify. The member did fail in every
	// case (the in-memory cooldown above already reflects that), exhausted just
	// changes the operator-facing wording.
	if a.onFailover != nil {
		a.onFailover(FailoverEvent{
			Pool:      pool,
			From:      from,
			To:        to,
			Reason:    tag,
			Class:     class,
			Until:     until,
			Exhausted: exhausted,
			Epoch:     idEpoch,
			Notify:    emit,
		})
	}

	// The log line + audit row below stay gated on the dedup decision: they are
	// the spam-prone surfaces a retry storm would flood, so a suppressed notice
	// (deduped window, or an already-exhausted pool whose edge already fired)
	// must not append a fresh log/audit entry. The durable store write already
	// ran above via the unconditional callback.
	if !emit {
		return
	}

	if exhausted {
		log.Printf("[POOL-FAILOVER] pool %q exhausted: all members cooling (%s); no failover target, serving least-bad %q",
			pool, tag, from)
	} else {
		log.Printf("[POOL-FAILOVER] pool %q: %s -> %s (%s); member %q cooling down until %s",
			pool, from, to, tag, from, until.Format(time.RFC3339))
	}

	// Audit: a real failover emits cred_failover with the documented Reason
	// shape "<pool>:<from>-><to>:<tag>"; pool exhaustion emits the distinct
	// pool_exhausted action so operators can alert on it separately and are
	// not misled by a self-referential transition. Safe with a nil auditLog.
	// The blake3 hash chain is appended synchronously by FileLogger.Log; the
	// write is local and fast (mirrors logDLPAudit on the same path), so it
	// does not warrant detaching like the store/Telegram side effects.
	if a.auditLog != nil {
		host, port := connectTargetForFlow(a, f)
		action := "cred_failover"
		reason := fmt.Sprintf("%s:%s->%s:%s", pool, from, to, tag)
		if exhausted {
			action = "pool_exhausted"
			reason = fmt.Sprintf("%s:exhausted:%s", pool, tag)
		}
		evt := audit.Event{
			Destination: host,
			Port:        port,
			// Same protocol used for the protocol-scoped binding lookup in
			// poolForResponse, NOT a hardcoded "https". For a grpc/http2
			// scoped pooled binding the audit must record the real protocol.
			Protocol:   proto,
			Verdict:    "failover",
			Action:     action,
			Reason:     reason,
			Credential: from,
		}
		if err := a.auditLog.Log(evt); err != nil {
			log.Printf("[POOL-FAILOVER] audit log error: %v", err)
		}
	}
}

// poolNoticeDedupWindow bounds how often an identical pool failover /
// exhaustion signal (same pool, from, to, tag) produces an audit row +
// operator notice. The synchronous in-memory MarkCooldown already switched
// the active member before this fires, so a burst of agent retries within
// the window is genuinely the same event, not new information.
const poolNoticeDedupWindow = 30 * time.Second

// shouldEmitPoolNotice returns true at most once per poolNoticeDedupWindow
// for a given (pool,from,to,tag). It is mutex-guarded (not a sync.Map
// LoadOrStore) so a concurrent burst cannot have two goroutines both miss
// and both emit. The map is keyed by a NUL-joined tuple; key cardinality is
// bounded by pool x member x member x tag, so it does not grow unbounded in
// practice.
func (a *SluiceAddon) shouldEmitPoolNotice(pool, from, to, tag string) bool {
	key := pool + "\x00" + from + "\x00" + to + "\x00" + tag
	now := time.Now()
	a.poolNoticeMu.Lock()
	defer a.poolNoticeMu.Unlock()
	if a.poolNoticeAt == nil {
		a.poolNoticeAt = make(map[string]time.Time)
	}
	if last, ok := a.poolNoticeAt[key]; ok && now.Sub(last) < poolNoticeDedupWindow {
		return false
	}
	a.poolNoticeAt[key] = now
	return true
}
