package proxy

import (
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
)

// flowAttrTTL bounds how long a flow-id -> injected-member tag is retained.
// An HTTP request/response round-trip completes in well under a second in
// practice; a generous TTL absorbs slow upstreams while still bounding the
// map so a flow whose response never arrives cannot leak the tag forever.
// The tag is also deleted on first successful lookup (single-use per flow).
const flowAttrTTL = 5 * time.Minute

// flowInjectedMember maps a go-mitmproxy Flow ID to the pool member whose
// credential was injected into THAT request at injection time (pass-1 header
// inject / pass-2 phantom swap in Requestheaders/Request).
//
// This is the join key for the API-host failover attribution bug (Finding
// 1). A pooled API-host failover (HTTP 429 / 403-quota) must be attributed
// to the member that was ACTIVE WHEN THE REQUEST WAS SENT, not the member
// that happens to be active when the response is processed. With concurrent
// in-flight requests both backed by member A, request1's 429 cools A and the
// pool switches to B; if request2's 429 is then attributed via a
// response-time ResolveActive it would wrongly cool B (now active) and park
// both accounts. The flow ID is stable across Requestheaders -> Request ->
// Response for one HTTP request (or HTTP/2 stream), so recording the
// resolved member per flow at injection time and reading it on the matching
// response pins attribution to the request's own injected member.
type flowInjectedMember struct {
	mu      sync.Mutex
	entries map[uuid.UUID]flowAttrEntry
}

type flowAttrEntry struct {
	member  string
	expires time.Time
}

func newFlowInjectedMember() *flowInjectedMember {
	return &flowInjectedMember{entries: make(map[uuid.UUID]flowAttrEntry)}
}

// Tag records that the given pool member's credential was injected for the
// request identified by flowID. Idempotent: pass-1 (injectHeaders) and
// pass-2 (buildPhantomPairs) both resolve the same member for one flow, so
// recording twice is harmless. A best-effort opportunistic sweep of expired
// entries keeps the map bounded without a background goroutine.
func (m *flowInjectedMember) Tag(flowID uuid.UUID, member string) {
	if member == "" || flowID == uuid.Nil {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) > 0 {
		for k, e := range m.entries {
			if now.After(e.expires) {
				delete(m.entries, k)
			}
		}
	}
	m.entries[flowID] = flowAttrEntry{member: member, expires: now.Add(flowAttrTTL)}
}

// Recover returns the member tagged for the given flow ID and removes the
// entry (single-use: a flow's response is processed exactly once). Returns
// ("", false) when no live tag exists — the caller falls back to
// response-time ResolveActive.
func (m *flowInjectedMember) Recover(flowID uuid.UUID) (string, bool) {
	if flowID == uuid.Nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[flowID]
	if !ok {
		return "", false
	}
	delete(m.entries, flowID)
	if time.Now().After(e.expires) {
		return "", false
	}
	return e.member, true
}

// Peek returns the member tagged for the given flow ID WITHOUT removing the
// entry. Returns ("", false) when no live tag exists.
//
// Peek exists for poolForResponse's API-host failover path. That path
// iterates CredentialsForDestination(dest:port), which can return MULTIPLE
// matching pools for one destination. A consuming Recover inside that loop
// would let the FIRST matching pool consume the tag even when the tag
// actually belongs to a LATER pool, starving the true owner and forcing a
// blind ResolveActive on an unrelated pool (the round-12 bug). A single
// non-consuming Peek before/independent of the loop serves the whole
// iteration so attribution is decided once, by membership, against the one
// pool the injected member actually belongs to.
//
// poolForResponse is invoked exactly once per response (one flow ->
// one Response callback -> one poolForResponse call), so not deleting the
// entry here does not re-attribute across responses; the entry is bounded
// by flowAttrTTL and the opportunistic sweep in Tag. The consuming Recover
// is retained for any caller that requires exactly-once semantics.
func (m *flowInjectedMember) Peek(flowID uuid.UUID) (string, bool) {
	if flowID == uuid.Nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[flowID]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expires) {
		return "", false
	}
	return e.member, true
}

// refreshAttrTTL is how long a real-refresh-token -> member tag is retained.
// An OAuth refresh round-trip (agent POSTs refresh_token, upstream answers
// with rotated tokens) completes in well under a second in practice; a
// generous TTL absorbs slow upstreams and clock skew while still bounding
// the map so a member that never sees its response cannot leak the tag
// forever. The tag is also deleted on first successful lookup.
const refreshAttrTTL = 5 * time.Minute

// refreshAttribution maps the REAL refresh token sluice injected into an
// outbound OAuth refresh-grant request to the pool member that owns it.
//
// This is the join key for Risk R1: two pool members share one token URL,
// so OAuthIndex.Match is 1:1 and cannot tell which member a token-endpoint
// response belongs to. The injected real refresh token, by contrast, is
// unique per member and is present verbatim in the RFC-6749 refresh-grant
// request body (`refresh_token=<value>`). Recording member-by-injected-
// refresh-token at pass-2 swap time and recovering it on the matching
// response is the only attribution that cannot misfile B's rotated tokens
// under A. The access token is NOT a valid key (it is not echoed in the
// refresh-grant request body), and the client connection is NOT a valid key
// (one HTTP/2 connection multiplexes both members' streams).
type refreshAttribution struct {
	mu      sync.Mutex
	entries map[string]refreshAttrEntry
}

type refreshAttrEntry struct {
	member  string
	expires time.Time
}

func newRefreshAttribution() *refreshAttribution {
	return &refreshAttribution{entries: make(map[string]refreshAttrEntry)}
}

// Tag records that the given real refresh token was injected for member.
// Called from the pass-2 phantom swap when the phantom being replaced is a
// pooled credential's `.refresh` phantom. A best-effort opportunistic sweep
// of expired entries keeps the map bounded without a background goroutine.
func (r *refreshAttribution) Tag(realRefreshToken, member string) {
	if realRefreshToken == "" || member == "" {
		return
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) > 0 {
		for k, e := range r.entries {
			if now.After(e.expires) {
				delete(r.entries, k)
			}
		}
	}
	r.entries[realRefreshToken] = refreshAttrEntry{
		member:  member,
		expires: now.Add(refreshAttrTTL),
	}
}

// Recover returns the member tagged for the given real refresh token and
// removes the entry (single-use: a rotated refresh token will never be
// presented again). Returns ("", false) when no live tag exists — the
// caller MUST fail closed (skip the vault write, never guess) per R1.
//
// Recover is used exclusively by the 2xx persist path
// (resolveOAuthResponseAttribution): a successful refresh rotates the
// refresh token, so the tag is dead after one use and must be deleted to
// bound the map.
func (r *refreshAttribution) Recover(realRefreshToken string) (string, bool) {
	if realRefreshToken == "" {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[realRefreshToken]
	if !ok {
		return "", false
	}
	delete(r.entries, realRefreshToken)
	if time.Now().After(e.expires) {
		return "", false
	}
	return e.member, true
}

// Peek returns the member tagged for the given real refresh token WITHOUT
// removing the entry. Returns ("", false) when no live tag exists.
//
// This is the CRITICAL-2 join key for the FAILOVER path
// (poolForResponse). Two pool members share one token URL, so
// OAuthIndex.Match is 1:1 and always returns the first index entry
// regardless of which member's refresh token is actually in the request
// body. Attributing a token-endpoint failure by idx.Match therefore cools
// the WRONG member whenever the failing member is not the first index
// entry. The injected real refresh token, by contrast, is unique per
// member and present verbatim in the refresh-grant request body, so it
// recovers the true owning member.
//
// Peek does NOT delete the entry because, unlike Recover (2xx success
// rotates the token, making the tag dead), a token-endpoint FAILURE
// (401 / invalid_grant) does NOT rotate the refresh token: the agent's
// SDK will retry the same refresh token and the tag must still resolve.
// processOAuthResponseIfMatching (the Recover caller) is 2xx-only, so on
// a 4xx the tag has not been consumed and is still live for this Peek.
// The entry is allowed to expire naturally via refreshAttrTTL / the
// opportunistic sweep in Tag.
func (r *refreshAttribution) Peek(realRefreshToken string) (string, bool) {
	if realRefreshToken == "" {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[realRefreshToken]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expires) {
		return "", false
	}
	return e.member, true
}
