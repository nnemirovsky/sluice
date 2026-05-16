package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	uuid "github.com/satori/go.uuid"
)

func timeFuture() time.Time { return time.Now().Add(5 * time.Minute) }

// TestPoolStablePhantomAccessNameInjectionSafe is the Finding 4 regression.
// The pool name was interpolated directly into the JWT payload JSON string,
// so a name containing '"', '\', or control characters produced an invalid
// or claim-injected JWT, breaking the agent-facing phantom. The fix marshals
// the payload through encoding/json (fixed-field struct, deterministic).
//
// Pre-fix this test fails: base64-decoding the payload of the produced
// phantom yields invalid JSON (the embedded '"' / '\' / control byte breaks
// the hand-rolled string), so json.Unmarshal errors and the sub claim does
// not round-trip the exact pool name.
func TestPoolStablePhantomAccessNameInjectionSafe(t *testing.T) {
	hostile := []string{
		`a"b`,                       // double quote — closes the JSON string early
		`a\b`,                       // backslash — invalid JSON escape
		"a\x01b",                    // control character — invalid in a JSON string
		`","admin":true,"x":"`,      // claim-injection attempt
		`pool"}` + "\n" + `garbage`, // quote + newline + trailing junk
		"normal_pool",               // sanity: the common case still works
	}

	for _, name := range hostile {
		name := name
		t.Run(name, func(t *testing.T) {
			tok := poolStablePhantomAccess(name)

			// Determinism / byte-stability for a given pool name.
			if tok2 := poolStablePhantomAccess(name); tok != tok2 {
				t.Fatalf("phantom not deterministic for %q: %q != %q", name, tok, tok2)
			}

			parts := strings.Split(tok, ".")
			if len(parts) != 3 {
				t.Fatalf("phantom not a 3-part JWT for %q: %q", name, tok)
			}

			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("payload not valid base64url for %q: %v", name, err)
			}

			var claims struct {
				Sub string `json:"sub"`
				Iss string `json:"iss"`
				Exp int64  `json:"exp"`
			}
			if err := json.Unmarshal(payloadBytes, &claims); err != nil {
				t.Fatalf("payload not valid JSON for pool name %q: %v (raw: %s) — Finding 4",
					name, err, payloadBytes)
			}

			// The exact pool name must round-trip — no truncation at the
			// first quote, no injected claims.
			if claims.Sub != "sluice-pool:"+name {
				t.Fatalf("sub claim = %q, want %q (pool name must round-trip exactly) — Finding 4",
					claims.Sub, "sluice-pool:"+name)
			}
			if claims.Iss != "sluice-phantom" || claims.Exp != 4102444800 {
				t.Fatalf("fixed claims corrupted for %q: iss=%q exp=%d", name, claims.Iss, claims.Exp)
			}

			// No extra top-level keys (claim injection would add e.g.
			// "admin"). Decode into a generic map and assert exactly 3.
			var generic map[string]interface{}
			if err := json.Unmarshal(payloadBytes, &generic); err != nil {
				t.Fatalf("payload re-decode failed for %q: %v", name, err)
			}
			if len(generic) != 3 {
				t.Fatalf("payload has %d keys for %q, want exactly 3 (claim injection) — Finding 4: %v",
					len(generic), name, generic)
			}
		})
	}
}

// poolMemberCred builds an OAuth credential envelope for a pool member.
func poolMemberCred(t *testing.T, access, refresh string) string {
	t.Helper()
	c := &vault.OAuthCredential{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenURL:     testOAuthTokenURL,
	}
	data, err := c.Marshal()
	if err != nil {
		t.Fatalf("marshal oauth cred: %v", err)
	}
	return string(data)
}

// setupPoolAddon wires a SluiceAddon with a two-member pool bound to
// auth.example.com. Both members share testOAuthTokenURL (the Risk R1
// collision shape: two Codex accounts behind one OpenAI token endpoint).
func setupPoolAddon(t *testing.T, memberA, memberB string) (*SluiceAddon, *addonWritableProvider, *atomic.Pointer[vault.PoolResolver]) {
	t.Helper()
	const poolName = "codex_pool"

	provider := &addonWritableProvider{
		creds: map[string]string{
			memberA: poolMemberCred(t, "A-access-old", "A-refresh-old"),
			memberB: poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}

	// The agent's binding points at the POOL name, not a member.
	bindings := []vault.Binding{{
		Destination: "auth.example.com",
		Ports:       []int{443},
		Credential:  poolName,
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)

	// Both members are registered in credential_meta (real OAuth creds)
	// with the SAME token URL. The pool name is NOT in credential_meta.
	metas := []store.CredentialMeta{
		{Name: memberA, CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: memberB, CredType: "oauth", TokenURL: testOAuthTokenURL},
	}
	addon.UpdateOAuthIndex(metas)

	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: memberA, Position: 0},
		{Credential: memberB, Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)

	return addon, provider, &prPtr
}

// refreshGrantBody is an RFC-6749 form-encoded refresh grant carrying the
// pool-scoped refresh phantom. Pass-2 swaps the phantom for the active
// member's real refresh token before the request leaves sluice.
// poolName is parameterized on purpose: this is a general RFC-6749
// refresh-grant body builder reused across pool tests, and a multi-pool
// test legitimately passes a different name. unparam only sees the current
// callers all using "codex_pool".
//
//nolint:unparam
func refreshGrantBody(poolName string) []byte {
	return []byte("grant_type=refresh_token&refresh_token=SLUICE_PHANTOM:" + poolName + ".refresh")
}

func newPoolReqRespFlow(client *mitmproxy.ClientConn, reqBody []byte, respBody []byte) *mitmproxy.Flow {
	u, _ := url.Parse(testOAuthTokenURL)
	reqHdr := make(http.Header)
	reqHdr.Set("Content-Type", "application/x-www-form-urlencoded")
	respHdr := make(http.Header)
	respHdr.Set("Content-Type", "application/json")
	return &mitmproxy.Flow{
		Id:          uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{ClientConn: client},
		Request: &mitmproxy.Request{
			Method: "POST",
			URL:    u,
			Header: reqHdr,
			Body:   reqBody,
		},
		Response: &mitmproxy.Response{
			StatusCode: 200,
			Header:     respHdr,
			Body:       respBody,
		},
	}
}

// TestR3PoolPhantomByteIdenticalAcrossMemberSwitch asserts the agent-facing
// phantom access token is byte-identical before and after a member switch
// (Risk R3). resignJWT is per-real-token; the pool-stable synthetic JWT must
// not depend on which member is active.
func TestR3PoolPhantomByteIdenticalAcrossMemberSwitch(t *testing.T) {
	// Direct determinism check on the synthetic-JWT builder.
	p1 := poolStablePhantomAccess("codex_pool")
	p2 := poolStablePhantomAccess("codex_pool")
	if p1 != p2 {
		t.Fatalf("poolStablePhantomAccess not deterministic: %q != %q", p1, p2)
	}
	if parts := strings.Split(p1, "."); len(parts) != 3 {
		t.Fatalf("phantom not a 3-part JWT: %q", p1)
	}
	if poolStablePhantomAccess("other_pool") == p1 {
		t.Fatal("phantom not keyed on pool name (collision across pools)")
	}

	// End-to-end: the access phantom the agent receives in a token-endpoint
	// response must be identical when member A is active and after failover
	// to member B (members have DIFFERENT real access tokens).
	addon, _, prPtr := setupPoolAddon(t, "codexA", "codexB")
	client := setupAddonConn(addon, "auth.example.com:443")

	// Member A active. Request body carries A's real refresh token (as if
	// pass-2 already swapped it), upstream returns A's rotated tokens.
	reqA := []byte("grant_type=refresh_token&refresh_token=A-refresh-old")
	addon.refreshAttr.Tag("A-refresh-old", "codexA")
	respA := mustJSON(t, map[string]interface{}{
		"access_token":  "A-real-access-NEW-aaaaaaaa",
		"refresh_token": "A-real-refresh-NEW-aaaaaaaa",
		"expires_in":    3600,
	})
	fA := newPoolReqRespFlow(client, reqA, respA)
	addon.Response(fA)
	waitAddonPersist(t, addon)
	bodyA := string(fA.Response.Body)
	phantomA := poolStablePhantomAccess("codex_pool")
	if !strings.Contains(bodyA, phantomA) {
		t.Fatalf("member-A response missing pool-stable phantom\n got: %q\nwant substring: %q", bodyA, phantomA)
	}
	if strings.Contains(bodyA, "A-real-access-NEW-aaaaaaaa") {
		t.Fatal("real access token leaked in member-A response")
	}

	// Fail member A over: B is now active.
	prPtr.Load().MarkCooldown("codexA", timeFuture(), "429")
	if got, _ := prPtr.Load().ResolveActive("codex_pool"); got != "codexB" {
		t.Fatalf("after cooldown active = %q, want codexB", got)
	}

	reqB := []byte("grant_type=refresh_token&refresh_token=B-refresh-old")
	addon.refreshAttr.Tag("B-refresh-old", "codexB")
	respB := mustJSON(t, map[string]interface{}{
		"access_token":  "B-real-access-NEW-bbbbbbbbbbbb",
		"refresh_token": "B-real-refresh-NEW-bbbbbbbbbbbb",
		"expires_in":    3600,
	})
	fB := newPoolReqRespFlow(client, reqB, respB)
	addon.Response(fB)
	waitAddonPersist(t, addon)
	bodyB := string(fB.Response.Body)
	phantomB := poolStablePhantomAccess("codex_pool")

	if phantomA != phantomB {
		t.Fatalf("R3 violated: phantom changed across member switch\n A: %q\n B: %q", phantomA, phantomB)
	}
	if !strings.Contains(bodyB, phantomB) {
		t.Fatalf("member-B response missing pool-stable phantom\n got: %q", bodyB)
	}
	if strings.Contains(bodyB, "B-real-access-NEW-bbbbbbbbbbbb") {
		t.Fatal("real access token leaked in member-B response")
	}
}

// TestPooledAccessPhantomSwappedInQueryAndPath is the round-18 #5
// regression. A pooled OAuth credential's access phantom is the R3
// pool-stable SYNTHETIC JWT (poolStablePhantomAccess) — it has NO
// "SLUICE_PHANTOM" prefix. The request-side URL query/path swap was gated
// SOLELY on bytesContainsAnyPhantomPrefix, which only knows the literal
// "SLUICE_PHANTOM" prefix. So when an SDK puts the access token in a query
// parameter or a path segment, the gate returned false, the swap was
// skipped, and the pool-stable JWT phantom was forwarded UPSTREAM verbatim
// (request fails / phantom leaks). The fix also gates on
// pairsPhantomPresentIn so the scoped pooled JWT triggers the existing
// swap.
//
// Fail-before: the phantom JWT survives in RawQuery/Path. Pass-after: it is
// replaced with the active member's real access token in BOTH. Header
// placement still works, the SLUICE_PHANTOM-prefixed (refresh) phantom path
// is unaffected, and the R3 byte-identical-across-member-switch guarantee
// holds (the synthetic-JWT shape is untouched; we only added a detection
// path that triggers the existing swapPhantomBytes).
func TestPooledAccessPhantomSwappedInQueryAndPath(t *testing.T) {
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")

	poolAccessPhantom := poolStablePhantomAccess("codex_pool")
	// Sanity: the pooled access phantom is a prefix-less synthetic JWT, so
	// the old prefix-only gate genuinely could not see it.
	if strings.HasPrefix(poolAccessPhantom, "SLUICE_PHANTOM") {
		t.Fatalf("pooled access phantom unexpectedly carries the SLUICE_PHANTOM prefix: %q", poolAccessPhantom)
	}
	if bytesContainsAnyPhantomPrefix([]byte(poolAccessPhantom)) {
		t.Fatal("pooled access phantom must NOT be detectable by bytesContainsAnyPhantomPrefix (that is the whole #5 bug)")
	}

	// --- Query-parameter placement. memA is active (position 0), so the
	// phantom must be swapped for memA's real access token "A-access-old".
	fq := newTestFlow(client, "GET",
		"https://auth.example.com/v1/userinfo?access_token="+url.QueryEscape(poolAccessPhantom)+"&foo=bar")
	addon.Request(fq)
	gotQ := fq.Request.URL.RawQuery
	if strings.Contains(gotQ, poolAccessPhantom) {
		t.Fatalf("#5: pooled access phantom NOT swapped in URL query (forwarded upstream verbatim)\n query=%q", gotQ)
	}
	if !strings.Contains(gotQ, "A-access-old") {
		t.Fatalf("#5: active member's real access token not injected into URL query\n query=%q", gotQ)
	}

	// --- Path-segment placement. ---
	fp := newTestFlow(client, "GET",
		"https://auth.example.com/v1/tokens/"+url.PathEscape(poolAccessPhantom)+"/info")
	addon.Request(fp)
	gotP := fp.Request.URL.Path
	if strings.Contains(gotP, poolAccessPhantom) {
		t.Fatalf("#5: pooled access phantom NOT swapped in URL path (forwarded upstream verbatim)\n path=%q", gotP)
	}
	if !strings.Contains(gotP, "A-access-old") {
		t.Fatalf("#5: active member's real access token not injected into URL path\n path=%q", gotP)
	}

	// --- Header placement still works (must-not-regress). ---
	fh := newTestFlow(client, "GET", "https://auth.example.com/v1/userinfo")
	fh.Request.Header.Set("Authorization", "Bearer "+poolAccessPhantom)
	addon.Request(fh)
	auth := fh.Request.Header.Get("Authorization")
	if strings.Contains(auth, poolAccessPhantom) || !strings.Contains(auth, "A-access-old") {
		t.Fatalf("#5: header phantom swap regressed; Authorization=%q", auth)
	}

	// --- SLUICE_PHANTOM-prefixed (refresh) phantom in query still swaps via
	// the unchanged prefix path (no regression to the non-pooled path). ---
	fr := newTestFlow(client, "GET",
		"https://auth.example.com/v1/refresh?rt="+url.QueryEscape("SLUICE_PHANTOM:codex_pool.refresh"))
	addon.Request(fr)
	if strings.Contains(fr.Request.URL.RawQuery, "SLUICE_PHANTOM") {
		t.Fatalf("prefix-form refresh phantom not swapped in query: %q", fr.Request.URL.RawQuery)
	}
	if !strings.Contains(fr.Request.URL.RawQuery, "A-refresh-old") {
		t.Fatalf("prefix-form refresh phantom not replaced with real refresh: %q", fr.Request.URL.RawQuery)
	}

	// --- R3 byte-identity preserved: fail member A over and confirm the
	// phantom the agent would hold is still byte-identical (pool-stable),
	// and the query swap now injects member B's real token. ---
	before := poolStablePhantomAccess("codex_pool")
	prPtr.Load().MarkCooldown("memA", timeFuture(), "429")
	if got, _ := prPtr.Load().ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("after cooldown active = %q, want memB", got)
	}
	after := poolStablePhantomAccess("codex_pool")
	if before != after {
		t.Fatalf("R3 byte-identity violated across member switch:\n before %q\n after  %q", before, after)
	}
	fq2 := newTestFlow(client, "GET",
		"https://auth.example.com/v1/userinfo?access_token="+url.QueryEscape(after))
	addon.Request(fq2)
	if strings.Contains(fq2.Request.URL.RawQuery, after) {
		t.Fatalf("#5: pooled access phantom not swapped after failover; query=%q", fq2.Request.URL.RawQuery)
	}
	if !strings.Contains(fq2.Request.URL.RawQuery, "B-access-old") {
		t.Fatalf("#5: post-failover query swap did not inject member B's real access token; query=%q", fq2.Request.URL.RawQuery)
	}
}

// TestR1RefreshAttributionByInjectedRefreshToken asserts a B-refresh
// response is persisted to B's vault entry, never A's, even though both
// members share one token URL (OAuthIndex.Match is 1:1 and collides).
func TestR1RefreshAttributionByInjectedRefreshToken(t *testing.T) {
	addon, provider, prPtr := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")

	// --- Member A round-trip via the real pass-2 path. ---
	// A is active; Request() swaps the pool refresh phantom -> A's real
	// refresh token AND tags A-refresh-old -> memA.
	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = refreshGrantBody("codex_pool")
	addon.Request(reqFlow)
	if !strings.Contains(string(reqFlow.Request.Body), "A-refresh-old") {
		t.Fatalf("pass-2 did not inject member-A real refresh token; body=%q", reqFlow.Request.Body)
	}

	respFlow := newPoolReqRespFlow(client, reqFlow.Request.Body, mustJSON(t, map[string]interface{}{
		"access_token":  "A-access-rotated-1",
		"refresh_token": "A-refresh-rotated-1",
		"expires_in":    3600,
	}))
	addon.Response(respFlow)
	waitAddonPersist(t, addon)

	credA, err := vault.ParseOAuth([]byte(provider.creds["memA"]))
	if err != nil {
		t.Fatalf("parse memA: %v", err)
	}
	if credA.RefreshToken != "A-refresh-rotated-1" {
		t.Errorf("memA refresh not persisted: got %q want A-refresh-rotated-1", credA.RefreshToken)
	}
	credB, err := vault.ParseOAuth([]byte(provider.creds["memB"]))
	if err != nil {
		t.Fatalf("parse memB: %v", err)
	}
	if credB.RefreshToken != "B-refresh-old" || credB.AccessToken != "B-access-old" {
		t.Errorf("memB MUST be untouched by an A-refresh response; got access=%q refresh=%q",
			credB.AccessToken, credB.RefreshToken)
	}

	// --- Member B round-trip after failover. ---
	prPtr.Load().MarkCooldown("memA", timeFuture(), "429")
	reqFlowB := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlowB.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlowB.Request.Body = refreshGrantBody("codex_pool")
	addon.Request(reqFlowB)
	if !strings.Contains(string(reqFlowB.Request.Body), "B-refresh-old") {
		t.Fatalf("pass-2 did not inject member-B real refresh token; body=%q", reqFlowB.Request.Body)
	}
	respFlowB := newPoolReqRespFlow(client, reqFlowB.Request.Body, mustJSON(t, map[string]interface{}{
		"access_token":  "B-access-rotated-1",
		"refresh_token": "B-refresh-rotated-1",
		"expires_in":    3600,
	}))
	addon.Response(respFlowB)
	waitAddonPersist(t, addon)

	credB2, _ := vault.ParseOAuth([]byte(provider.creds["memB"]))
	if credB2.RefreshToken != "B-refresh-rotated-1" {
		t.Errorf("memB refresh not persisted after failover: got %q", credB2.RefreshToken)
	}
	credA2, _ := vault.ParseOAuth([]byte(provider.creds["memA"]))
	if credA2.RefreshToken != "A-refresh-rotated-1" {
		t.Errorf("memA MUST retain its own rotated token; B-refresh response corrupted A: got %q",
			credA2.RefreshToken)
	}
}

// TestR1FailClosedWhenMemberTagMissing asserts that when the owning member
// cannot be recovered from the injected refresh token (no tag), the response
// is still swapped to phantoms (agent safe) but ZERO vault writes occur — no
// guess, no fallback to OAuthIndex.Match.
func TestR1FailClosedWhenMemberTagMissing(t *testing.T) {
	addon, provider, _ := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")

	beforeA := provider.creds["memA"]
	beforeB := provider.creds["memB"]

	// Request body carries a refresh token that was NEVER tagged (no
	// pass-2 ran, or the tag expired). resolveOAuthResponseAttribution
	// must fail closed.
	resp := newPoolReqRespFlow(client,
		[]byte("grant_type=refresh_token&refresh_token=untracked-refresh-xyz"),
		mustJSON(t, map[string]interface{}{
			"access_token":  "should-not-persist-access",
			"refresh_token": "should-not-persist-refresh",
			"expires_in":    3600,
		}))
	addon.Response(resp)

	// No persist goroutine should have been scheduled. Give any (buggy)
	// async write a chance to land, then assert nothing changed.
	select {
	case <-addon.persistDone:
		t.Fatal("R1 fail-closed violated: a vault persist was scheduled with no member tag")
	default:
	}

	if provider.creds["memA"] != beforeA {
		t.Error("memA vault entry mutated despite fail-closed")
	}
	if provider.creds["memB"] != beforeB {
		t.Error("memB vault entry mutated despite fail-closed")
	}

	// Agent must still be protected: real tokens swapped to phantoms.
	body := string(resp.Response.Body)
	if strings.Contains(body, "should-not-persist-access") || strings.Contains(body, "should-not-persist-refresh") {
		t.Errorf("fail-closed must still strip real tokens; body=%q", body)
	}
	if !strings.Contains(body, poolStablePhantomAccess("codex_pool")) {
		t.Errorf("fail-closed response missing pool-stable phantom; body=%q", body)
	}
}

// TestChokepointPlainCredentialUnchanged asserts a non-pool credential
// routes through the chokepoint as an identity (regression guard for
// Important I2: the single chokepoint must not alter plain-cred behavior).
func TestChokepointPlainCredentialUnchanged(t *testing.T) {
	addon, _ := setupOAuthAddon(t, "plain_oauth", &vault.OAuthCredential{
		AccessToken:  "plain-access-old",
		RefreshToken: "plain-refresh-old",
		TokenURL:     testOAuthTokenURL,
	})
	// Attach an (empty) pool resolver so the chokepoint code path runs.
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver(nil, nil))
	addon.SetPoolResolver(&prPtr)

	client := setupAddonConn(addon, "auth.example.com:443")
	resp := newTestResponseFlow(client, testOAuthTokenURL, 200, mustJSON(t, map[string]interface{}{
		"access_token":  "plain-real-access-NEW",
		"refresh_token": "plain-real-refresh-NEW",
		"expires_in":    3600,
	}), "application/json")
	addon.Response(resp)
	waitAddonPersist(t, addon)

	body := string(resp.Response.Body)
	if strings.Contains(body, "plain-real-access-NEW") {
		t.Error("plain cred: real token leaked")
	}
	// Plain creds keep the legacy per-real-token resign / static phantom.
	if !strings.Contains(body, oauthPhantomAccess("plain_oauth", "plain-real-access-NEW")) {
		t.Errorf("plain cred phantom changed; body=%q", body)
	}
}

// plainCredWithTokenURL builds a plain (non-pool) OAuth credential envelope
// with an explicit token URL.
func plainCredWithTokenURL(t *testing.T, access, refresh, tokenURL string) string {
	t.Helper()
	c := &vault.OAuthCredential{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenURL:     tokenURL,
	}
	data, err := c.Marshal()
	if err != nil {
		t.Fatalf("marshal oauth cred: %v", err)
	}
	return string(data)
}

// TestR1FailClosedPlainCredFirstMatchSharesPoolTokenURL is the Copilot
// Finding 1 regression. A PLAIN (non-pool) OAuth credential sorts FIRST in
// credential_meta and shares the SAME token URL as a pool. A pooled refresh
// response arrives whose owning member cannot be recovered (no live
// refresh-attr tag — it expired, or the response is slow). idx.Match
// returns the plain credential (first index entry). Before the fix,
// resolveOAuthResponseAttribution took the "matchedCred not pooled" branch
// and persisted the rotated POOLED tokens under the PLAIN credential's
// vault entry — an R1 ("never guess") violation that misfiles one pool
// member's rotated tokens under an unrelated plain credential.
//
// The fix: once ANY pool shares the token URL and the owning member cannot
// be recovered, skip persistence entirely (fail closed). The swap still
// runs so the agent never sees real tokens. A genuinely plain-only token
// URL (no pool sharing) must still persist normally — covered by the
// sub-test below so the fix is not over-restrictive.
//
// MUST fail before the fix: the plain credential's vault entry would be
// overwritten with the pooled refresh's rotated tokens.
func TestR1FailClosedPlainCredFirstMatchSharesPoolTokenURL(t *testing.T) {
	const poolName = "codex_pool"
	// "aaa_plain" sorts/indexes before the pool members so idx.Match (first
	// entry) returns it — exactly the Finding 1 collision shape.
	provider := &addonWritableProvider{
		creds: map[string]string{
			"aaa_plain": poolMemberCred(t, "plain-access-old", "plain-refresh-old"),
			"memA":      poolMemberCred(t, "A-access-old", "A-refresh-old"),
			"memB":      poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}
	bindings := []vault.Binding{{
		Destination: "auth.example.com",
		Ports:       []int{443},
		Credential:  poolName,
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)

	// aaa_plain is FIRST in the metas slice -> first index entry -> what
	// idx.Match returns for testOAuthTokenURL.
	addon.UpdateOAuthIndex([]store.CredentialMeta{
		{Name: "aaa_plain", CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: "memA", CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: "memB", CredType: "oauth", TokenURL: testOAuthTokenURL},
	})
	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "memA", Position: 0},
		{Credential: "memB", Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)

	client := setupAddonConn(addon, "auth.example.com:443")

	// Precondition: idx.Match returns the plain credential (first entry),
	// while MatchAll reveals a pool also shares the token URL.
	if idx := addon.oauthIndex.Load(); idx != nil {
		u, _ := url.Parse(testOAuthTokenURL)
		if m, _ := idx.Match(u); m != "aaa_plain" {
			t.Fatalf("precondition: idx.Match must return the plain first entry, got %q", m)
		}
	}

	beforePlain := provider.creds["aaa_plain"]
	beforeA := provider.creds["memA"]
	beforeB := provider.creds["memB"]

	// A pooled refresh response. NO refresh-attr tag is recorded (it
	// expired / the response is slow), so the owning member cannot be
	// recovered. The body's refresh token is untracked.
	resp := newPoolReqRespFlow(client,
		[]byte("grant_type=refresh_token&refresh_token=untracked-pooled-refresh"),
		mustJSON(t, map[string]interface{}{
			"access_token":  "rotated-pooled-access",
			"refresh_token": "rotated-pooled-refresh",
			"expires_in":    3600,
		}))
	addon.Response(resp)

	// No vault persist must have been scheduled to ANYONE.
	select {
	case <-addon.persistDone:
		t.Fatal("R1 fail-closed violated (Finding 1): a vault persist was scheduled " +
			"for a pooled refresh whose owner could not be recovered, while a plain " +
			"credential sorted first and shared the token URL")
	default:
	}
	if provider.creds["aaa_plain"] != beforePlain {
		t.Fatal("Finding 1: pooled refresh tokens were misfiled under the PLAIN " +
			"credential 'aaa_plain' (R1 'never guess' violation)")
	}
	if provider.creds["memA"] != beforeA || provider.creds["memB"] != beforeB {
		t.Fatal("Finding 1: pooled refresh tokens were written to a pool member " +
			"without a recovered owner (must fail closed)")
	}

	// Agent must still be protected: the real rotated tokens are swapped to
	// the pool-stable phantoms even though nothing was persisted.
	body := string(resp.Response.Body)
	if strings.Contains(body, "rotated-pooled-access") || strings.Contains(body, "rotated-pooled-refresh") {
		t.Errorf("fail-closed must still strip real tokens; body=%q", body)
	}
	if !strings.Contains(body, poolStablePhantomAccess(poolName)) {
		t.Errorf("fail-closed response missing pool-stable phantom; body=%q", body)
	}
}

// TestR1PlainOnlyTokenURLStillPersists is the no-regression companion to
// Finding 1: a plain OAuth credential whose token URL is NOT shared by any
// pool must still persist its rotated tokens normally. The fix only skips
// persistence when a pool shares the token URL, so this 1:1 plain path is
// unchanged.
func TestR1PlainOnlyTokenURLStillPersists(t *testing.T) {
	const plainTokenURL = "https://plain-only.example.com/oauth/token"
	provider := &addonWritableProvider{
		creds: map[string]string{
			// A pool exists but on a DIFFERENT token URL, so it does not
			// share plainTokenURL.
			"plainCred": plainCredWithTokenURL(t, "p-access-old", "p-refresh-old", plainTokenURL),
			"memA":      poolMemberCred(t, "A-access-old", "A-refresh-old"),
			"memB":      poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}
	bindings := []vault.Binding{{
		Destination: "plain-only.example.com",
		Ports:       []int{443},
		Credential:  "plainCred",
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)
	addon.UpdateOAuthIndex([]store.CredentialMeta{
		{Name: "plainCred", CredType: "oauth", TokenURL: plainTokenURL},
		// Pool members on the OTHER token URL (testOAuthTokenURL).
		{Name: "memA", CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: "memB", CredType: "oauth", TokenURL: testOAuthTokenURL},
	})
	pool := store.Pool{Name: "codex_pool", Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "memA", Position: 0},
		{Credential: "memB", Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)

	client := setupAddonConn(addon, "plain-only.example.com:443")
	resp := newTestResponseFlow(client, plainTokenURL, 200, mustJSON(t, map[string]interface{}{
		"access_token":  "p-real-access-NEW",
		"refresh_token": "p-real-refresh-NEW",
		"expires_in":    3600,
	}), "application/json")
	addon.Response(resp)
	waitAddonPersist(t, addon)

	// The plain credential's vault entry must now hold the rotated tokens.
	updated := provider.creds["plainCred"]
	if !strings.Contains(updated, "p-real-access-NEW") || !strings.Contains(updated, "p-real-refresh-NEW") {
		t.Fatalf("plain-only token URL must still persist rotated tokens to the "+
			"plain credential (no Finding 1 over-restriction); vault=%q", updated)
	}
	// Agent still gets phantoms, not the real rotated tokens.
	body := string(resp.Response.Body)
	if strings.Contains(body, "p-real-access-NEW") || strings.Contains(body, "p-real-refresh-NEW") {
		t.Errorf("plain-only: real token leaked to agent; body=%q", body)
	}
}
