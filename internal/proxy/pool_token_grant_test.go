package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// Task 4: the pool token-host phantom expansion must be scoped to the OAuth
// refresh round-trip. A pool's shared OAuth token host (e.g. auth.openai.com)
// also serves device_code (a fresh in-container `codex login --device-auth`)
// and authorization_code grants; rewriting those request bodies/headers with
// the pool refresh phantom corrupts them (Codex -> 400
// token_exchange_user_error). Only `grant_type=refresh_token` may be expanded;
// every other grant (including an absent / unparseable grant_type) must reach
// upstream byte-identical to what the agent sent.

// cloneHeader returns a deep copy of an http.Header for byte-comparison.
func cloneHeader(h http.Header) http.Header {
	c := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		c[k] = cp
	}
	return c
}

func headerEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}

// TestPoolTokenHost_RefreshGrantStillExpanded is the regression guard: a
// genuine `grant_type=refresh_token` POST to the pool token host must STILL be
// expanded exactly as before (pool refresh phantom -> active member's real
// refresh token, R1 attribution tag recorded). This mirrors
// TestSplitHost_RequestSidePhantomSwapOnTokenHost and protects the existing
// behavior against the Task-4 grant gate.
func TestPoolTokenHost_RefreshGrantStillExpanded(t *testing.T) {
	addon, _, prPtr := setupPoolSplitHostWithPlainCred(t)
	client := setupAddonConn(addon, "auth.example.com:443")

	if got, _ := prPtr.Load().ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-condition active = %q, want memA", got)
	}

	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = refreshGrantBody("codex_pool")

	addon.Requestheaders(reqFlow)
	addon.Request(reqFlow)

	body := string(reqFlow.Request.Body)
	if strings.Contains(body, "SLUICE_PHANTOM:codex_pool.refresh") {
		t.Fatalf("regression: refresh_token grant pool phantom NOT swapped; body=%q", body)
	}
	if !strings.Contains(body, "A-refresh-old") {
		t.Fatalf("regression: active member memA real refresh token not injected; body=%q", body)
	}
	if owner, ok := addon.refreshAttr.Peek("A-refresh-old"); !ok || owner != "memA" {
		t.Fatalf("regression: R1 attribution tag not recorded for memA; owner=%q ok=%v", owner, ok)
	}
}

// runNonRefreshGrantPassThrough drives a realistic non-refresh grant body
// (device_code / authorization_code / absent grant_type — none of which carry
// a refresh_token; a fresh in-container `codex login --device-auth` posts only
// device_code + client_id) through the addon and asserts the request body +
// headers reach upstream byte-identical. Before the Task-4 gate the pool
// token-host expansion would still build the pool pairs for this token URL and
// (via the unbound-phantom strip / pool-keyed swap) mutate the request,
// corrupting the in-container login into 400 token_exchange_user_error.
func runNonRefreshGrantPassThrough(t *testing.T, name string, body []byte) {
	t.Helper()
	addon, _, prPtr := setupPoolSplitHostWithPlainCred(t)
	client := setupAddonConn(addon, "auth.example.com:443")

	if got, _ := prPtr.Load().ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("[%s] pre-condition active = %q, want memA", name, got)
	}

	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = append([]byte(nil), body...)

	wantBody := append([]byte(nil), body...)
	wantHeader := cloneHeader(reqFlow.Request.Header)

	addon.Requestheaders(reqFlow)
	addon.Request(reqFlow)

	if string(reqFlow.Request.Body) != string(wantBody) {
		t.Fatalf("[%s] non-refresh grant body MUTATED; got=%q want=%q (codex login --device-auth would be corrupted)",
			name, reqFlow.Request.Body, wantBody)
	}
	if !headerEqual(reqFlow.Request.Header, wantHeader) {
		t.Fatalf("[%s] non-refresh grant headers MUTATED; got=%v want=%v", name, reqFlow.Request.Header, wantHeader)
	}
	// The R1 attribution tag must NOT be recorded: nothing was injected.
	if owner, ok := addon.refreshAttr.Peek("A-refresh-old"); ok {
		t.Fatalf("[%s] R1 attribution tag wrongly recorded (owner=%q) for a non-refresh grant", name, owner)
	}
}

// TestPoolTokenHost_DeviceCodeGrantPassThrough: a `grant_type=device_code`
// request (a fresh in-container `codex login --device-auth`) must reach
// upstream byte-unchanged so the login is not corrupted into 400
// token_exchange_user_error.
func TestPoolTokenHost_DeviceCodeGrantPassThrough(t *testing.T) {
	runNonRefreshGrantPassThrough(t, "device_code",
		[]byte("grant_type=device_code&device_code=abc123&client_id=codex-cli"))
}

// TestPoolTokenHost_AuthorizationCodeGrantPassThrough: a
// `grant_type=authorization_code` request must also pass through unmodified.
func TestPoolTokenHost_AuthorizationCodeGrantPassThrough(t *testing.T) {
	runNonRefreshGrantPassThrough(t, "authorization_code",
		[]byte("grant_type=authorization_code&code=xyz&client_id=codex-cli&redirect_uri=http://localhost"))
}

// TestPoolTokenHost_AbsentGrantTypePassThrough: a body with NO grant_type
// (unparseable / non-token request to the same host) must pass through
// unmodified — absent grant is treated the same as a non-refresh grant.
func TestPoolTokenHost_AbsentGrantTypePassThrough(t *testing.T) {
	runNonRefreshGrantPassThrough(t, "absent_grant",
		[]byte("client_id=codex-cli&scope=openid&foo=bar"))
}

// TestRequestGrantType_ParsesFormAndJSON unit-tests the helper the gate relies
// on (form first, JSON fallback, "" on absent/empty/unparseable).
func TestRequestGrantType_ParsesFormAndJSON(t *testing.T) {
	cases := []struct {
		name string
		body string
		ct   string
		want string
	}{
		{"form refresh", "grant_type=refresh_token&refresh_token=x", "application/x-www-form-urlencoded", "refresh_token"},
		{"form device", "grant_type=device_code&device_code=x", "application/x-www-form-urlencoded", "device_code"},
		{"form absent", "refresh_token=x", "application/x-www-form-urlencoded", ""},
		{"json refresh", `{"grant_type":"refresh_token"}`, "application/json", "refresh_token"},
		{"json absent", `{"foo":"bar"}`, "application/json", ""},
		{"empty body", "", "application/x-www-form-urlencoded", ""},
		{"form no content-type still parses", "grant_type=refresh_token", "", "refresh_token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := requestGrantType([]byte(c.body), c.ct); got != c.want {
				t.Fatalf("requestGrantType(%q,%q) = %q, want %q", c.body, c.ct, got, c.want)
			}
		})
	}
}
