package proxy

import (
	"sync"
	"time"
)

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
