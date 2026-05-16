//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/vault"
)

// fakeOAuthUpstream is a single TLS server that plays two roles for the
// credential-pool failover e2e:
//
//   - POST /token  : an OAuth refresh-grant token endpoint. It inspects the
//     refresh_token in the request body (which sluice has already swapped
//     from the pool phantom to the *active member's* real refresh token) to
//     learn WHICH member is refreshing, mints a fresh real JWT access token
//     plus a rotated real refresh token, and returns them. The minted tokens
//     are unique per member so the test can prove B's rotated tokens land in
//     B's vault entry, not A's (Risk R1).
//
//   - GET  /api    : a protected API endpoint. It reads the Bearer token
//     (which sluice injected as the active member's real access token) and
//     returns 429 for memberA's real access token and 200 for memberB's.
//     That 429 is what drives sluice's auto-failover from A to B.
//
// The token endpoint issues *real* JWTs (header.payload.signature, signed
// with an HMAC test key) so the "phantom access token byte-identical across
// the failover" assertion is meaningful: sluice must re-key the phantom on
// the POOL name, not on the per-member real JWT.
type fakeOAuthUpstream struct {
	mu sync.Mutex

	// realRefreshToMember maps a member's *current* real refresh token to
	// the member name. Seeded with the initial vault refresh tokens and
	// updated on every rotation so a follow-up refresh round-trip is still
	// attributable.
	realRefreshToMember map[string]string

	// realAccessToMember maps a minted real access token to the member it
	// was minted for. Used by /api to decide 429 (memberA) vs 200 (memberB).
	realAccessToMember map[string]string

	// counters
	tokenCalls map[string]int
	apiCalls   map[string]int
}

func newFakeOAuthUpstream() *fakeOAuthUpstream {
	return &fakeOAuthUpstream{
		realRefreshToMember: map[string]string{},
		realAccessToMember:  map[string]string{},
		tokenCalls:          map[string]int{},
		apiCalls:            map[string]int{},
	}
}

// seedMember registers a member's initial real refresh AND access tokens so
// the first refresh round-trip is attributable and an /api call made with
// the seed access token (before any /token mint) is still recognized.
func (u *fakeOAuthUpstream) seedMember(member, initialRefresh, initialAccess string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.realRefreshToMember[initialRefresh] = member
	u.realAccessToMember[initialAccess] = member
}

// mintJWT builds a real, structurally valid JWT whose payload encodes the
// member name and a monotonically increasing counter, signed with an HMAC
// key. Every call returns a DIFFERENT token (distinct per member and per
// refresh) so the test can prove sluice does not leak the real JWT to the
// agent (the agent must always see the pool-stable phantom instead).
func (u *fakeOAuthUpstream) mintJWT(member string, n int) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"real-%s","member":"%s","n":%d,"iss":"fake-upstream"}`, member, member, n),
	))
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte("fake-upstream-hmac-key"))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

func (u *fakeOAuthUpstream) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// sluice has already swapped the pool phantom for the active
		// member's REAL refresh token by the time the request reaches
		// the upstream, so the body carries the real refresh token.
		var refreshToken string
		// RFC 6749 form encoding (what sluice's CLI-added bindings use).
		if vals, err := parseFormBody(body); err == nil {
			refreshToken = vals
		}

		u.mu.Lock()
		member, known := u.realRefreshToMember[refreshToken]
		if !known {
			u.mu.Unlock()
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		u.tokenCalls[member]++
		n := u.tokenCalls[member]
		newAccess := u.mintJWT(member, n)
		newRefresh := fmt.Sprintf("real-refresh-%s-rot-%d", member, n)
		// Rotate: the old refresh token is single-use; register the new
		// one so a subsequent refresh by the same member still resolves.
		delete(u.realRefreshToMember, refreshToken)
		u.realRefreshToMember[newRefresh] = member
		u.realAccessToMember[newAccess] = member
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  newAccess,
			"refresh_token": newRefresh,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		bearer := strings.TrimPrefix(auth, "Bearer ")

		u.mu.Lock()
		member := u.realAccessToMember[bearer]
		u.apiCalls[member]++
		u.mu.Unlock()

		switch member {
		case "memberA":
			// memberA is rate-limited: this is the failover trigger.
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
		case "memberB":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("api-ok member=memberB\n"))
		default:
			// Unknown bearer (phantom leaked, or unexpected token).
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unknown bearer: " + bearer + "\n"))
		}
	})

	return mux
}

func (u *fakeOAuthUpstream) TokenCalls(member string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.tokenCalls[member]
}

func (u *fakeOAuthUpstream) APICalls(member string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.apiCalls[member]
}

// parseFormBody extracts the refresh_token field from an
// application/x-www-form-urlencoded body. Returns the value or "".
func parseFormBody(body []byte) (string, error) {
	for _, kv := range strings.Split(string(body), "&") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "refresh_token" {
			// Values are not percent-encoded in our test client, but
			// handle the common case anyway.
			return strings.ReplaceAll(parts[1], "%2F", "/"), nil
		}
	}
	return "", fmt.Errorf("no refresh_token")
}

// startFakeOAuthUpstreamWithCA starts the fake upstream over TLS using a
// cert signed by the supplied test CA so sluice's MITM transport trusts it.
func startFakeOAuthUpstreamWithCA(t *testing.T, ca *testCA, u *fakeOAuthUpstream) *httptest.Server {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.X509, &serverKey.PublicKey, ca.Cert.PrivateKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	srvCert := tls.Certificate{
		Certificate: [][]byte{der, ca.Cert.Certificate[0]},
		PrivateKey:  serverKey,
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{
		Listener: ln,
		TLS:      &tls.Config{Certificates: []tls.Certificate{srvCert}},
		Config:   &http.Server{Handler: u.handler()},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// readVaultOAuth opens the vault store and returns the parsed OAuth
// credential for the given name.
func readVaultOAuth(t *testing.T, vaultDir, name string) *vault.OAuthCredential {
	t.Helper()
	vs, err := vault.NewStore(vaultDir)
	if err != nil {
		t.Fatalf("open vault store: %v", err)
	}
	sb, err := vs.Get(name)
	if err != nil {
		t.Fatalf("vault get %q: %v", name, err)
	}
	defer sb.Release()
	cred, err := vault.ParseOAuth(sb.Bytes())
	if err != nil {
		t.Fatalf("parse oauth %q: %v", name, err)
	}
	return cred
}

// TestPoolFailover_EndToEnd is the GAP 1 e2e: two fake OAuth members behind
// one pool. It asserts:
//
//	(a) member A is used until its API call returns 429,
//	(b) sluice fails over so the NEXT request uses member B,
//	(c) member B's refreshed tokens persist to B's vault entry, NOT A's
//	    (the R1 attribution: both members share one fake token URL),
//	(d) the phantom access token the agent receives is byte-identical
//	    before and after the failover (the token endpoint issues real
//	    JWTs so this is a real test of pool-keyed phantom stability).
func TestPoolFailover_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	vaultDir := filepath.Join(tmpDir, "vault")
	ca := generateTestCA(t, vaultDir)

	caCertFile := filepath.Join(tmpDir, "ca-bundle.pem")
	if err := os.WriteFile(caCertFile, ca.CertPEM, 0o644); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	up := newFakeOAuthUpstream()
	srv := startFakeOAuthUpstreamWithCA(t, ca, up)
	host, portStr := mustSplitAddr(t, srv.URL)
	tokenURL := srv.URL + "/token"
	apiURL := srv.URL + "/api"

	// Initial real refresh tokens for each member. The fake upstream maps
	// these to the member so the first refresh round-trip is attributable.
	const (
		memARefresh = "real-refresh-memberA-seed"
		memBRefresh = "real-refresh-memberB-seed"
		memAAccess  = "real-access-memberA-seed"
		memBAccess  = "real-access-memberB-seed"
	)
	up.seedMember("memberA", memARefresh, memAAccess)
	up.seedMember("memberB", memBRefresh, memBAccess)

	// Policy: allow the upstream host:port (covers both /token and /api),
	// and trust the test CA so MITM works.
	config := fmt.Sprintf(`
[policy]
default = "deny"

[vault]
provider = "age"
dir = %q

[[allow]]
destination = %q
ports = [%s]
name = "allow fake upstream"
`, vaultDir, host, portStr)

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: config,
		Env: []string{
			"SSL_CERT_FILE=" + caCertFile,
			"SSL_CERT_DIR=",
		},
	})

	// Add the two OAuth members. They share ONE token URL (the R1
	// collision scenario): two members, one fake token endpoint.
	addOAuthMember := func(name, access, refresh string) {
		binary := buildSluice(t)
		cmd := exec.Command(binary, "cred", "add", "--db", proc.DBPath,
			"--type", "oauth", "--token-url", tokenURL, name)
		cmd.Stdin = strings.NewReader(access + "\n" + refresh + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cred add %s: %v\n%s", name, err, out)
		}
	}
	addOAuthMember("memberA", memAAccess, memARefresh)
	addOAuthMember("memberB", memBAccess, memBRefresh)

	// Create the failover pool with A first, B second.
	runSluiceCLI(t, proc, "pool", "create", "codexpool", "--members", "memberA,memberB")

	// Bind the pool to the upstream destination with a Bearer header so
	// the active member's real access token is injected into /api calls.
	bindingCmd := exec.Command(buildSluice(t), "binding", "add", "--db", proc.DBPath,
		"--destination", host, "--ports", portStr,
		"--header", "Authorization", "--template", "Bearer {value}",
		"codexpool")
	if out, err := bindingCmd.CombinedOutput(); err != nil {
		t.Fatalf("binding add codexpool: %v\n%s", err, out)
	}

	// Reload so the pool resolver, OAuth index, and binding resolver pick
	// up the new state.
	sendSIGHUP(t, proc)

	// The agent holds the POOL phantom for the refresh token. It is the
	// deterministic static string SLUICE_PHANTOM:<pool>.refresh.
	poolRefreshPhantom := "SLUICE_PHANTOM:codexpool.refresh"

	// doRefresh posts a refresh-grant to the token endpoint through the
	// proxy. sluice swaps the pool phantom for the active member's real
	// refresh token, the upstream mints a real JWT, and sluice swaps the
	// real JWT for the pool-stable phantom before the body reaches us.
	// Returns the phantom access token the "agent" receives.
	doRefresh := func() string {
		body := "grant_type=refresh_token&refresh_token=" + poolRefreshPhantom
		status, respBody := httpsRequestViaSOCKS5(t, proc.ProxyAddr, "POST", tokenURL,
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body)
		if status != http.StatusOK {
			t.Fatalf("refresh: status=%d body=%s", status, respBody)
		}
		var tr struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal([]byte(respBody), &tr); err != nil {
			t.Fatalf("refresh: decode response: %v\nbody=%s", err, respBody)
		}
		// The agent must NEVER receive a real upstream JWT. Real JWTs
		// have payload sub "real-memberX"; assert it is absent.
		if strings.Contains(respBody, `real-member`) {
			t.Fatalf("real JWT leaked to agent in refresh response:\n%s", respBody)
		}
		if strings.Contains(tr.RefreshToken, "real-refresh-") {
			t.Fatalf("real refresh token leaked to agent: %s", tr.RefreshToken)
		}
		return tr.AccessToken
	}

	// callAPI calls the protected API through the proxy with the pool
	// access phantom in the Authorization header (the binding template
	// also sets it, but sending it explicitly mirrors a real agent that
	// holds a phantom). Returns the HTTP status.
	callAPI := func() (int, string) {
		// The agent uses its phantom access token. sluice's binding
		// header injection overwrites Authorization with the active
		// member's real access token regardless, so the value we send
		// here only needs to be the pool access phantom for the body
		// phantom-swap path; the header injection is what /api checks.
		return httpsRequestViaSOCKS5(t, proc.ProxyAddr, "GET", apiURL, nil, "")
	}

	// ---- Phase 1: member A is active ----
	phantomBefore := doRefresh()
	if phantomBefore == "" {
		t.Fatal("phantom access token before failover is empty")
	}
	// It must be a structurally valid 3-part JWT (pool-stable synthetic).
	if parts := strings.Split(phantomBefore, "."); len(parts) != 3 {
		t.Fatalf("phantom access token is not a 3-part JWT: %q", phantomBefore)
	}

	// (a) member A used until it 429s.
	statusA, bodyA := callAPI()
	if statusA != http.StatusTooManyRequests {
		t.Fatalf("first API call: status=%d body=%s (want 429 from memberA)", statusA, bodyA)
	}
	if up.APICalls("memberA") < 1 {
		t.Fatalf("memberA API calls = %d, want >= 1", up.APICalls("memberA"))
	}
	if up.APICalls("memberB") != 0 {
		t.Fatalf("memberB API calls = %d before failover, want 0", up.APICalls("memberB"))
	}

	// ---- Phase 2: failover happened synchronously on the 429 response ----
	// (b) the NEXT API request uses member B and succeeds.
	var statusB int
	var bodyB string
	// The in-memory health swap is synchronous on the Response addon, so
	// the next request should already route to B. Retry briefly only to
	// absorb connection/keep-alive races, NOT to wait out a cooldown.
	deadline := time.Now().Add(5 * time.Second)
	for {
		statusB, bodyB = callAPI()
		if statusB == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("post-failover API call never succeeded: status=%d body=%s", statusB, bodyB)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(bodyB, "member=memberB") {
		t.Fatalf("post-failover API response not from memberB:\n%s", bodyB)
	}
	if up.APICalls("memberB") < 1 {
		t.Fatalf("memberB API calls = %d after failover, want >= 1", up.APICalls("memberB"))
	}

	// (d) phantom access token byte-identical after the failover. Refresh
	// again: now member B is active, so the upstream mints memberB's real
	// JWT. sluice must still hand the agent the SAME pool-keyed phantom.
	phantomAfter := doRefresh()
	if phantomAfter != phantomBefore {
		t.Fatalf("phantom access token changed across failover:\nbefore=%q\nafter =%q",
			phantomBefore, phantomAfter)
	}

	// (c) member B's refreshed tokens persisted to B's vault entry, NOT
	// A's. The vault write is async; poll until B's vault entry shows a
	// rotated refresh token (or time out).
	var bCred, aCred *vault.OAuthCredential
	pdl := time.Now().Add(5 * time.Second)
	for {
		bCred = readVaultOAuth(t, vaultDir, "memberB")
		if strings.HasPrefix(bCred.RefreshToken, "real-refresh-memberB-rot-") {
			break
		}
		if time.Now().After(pdl) {
			t.Fatalf("memberB vault refresh token never rotated; got %q", bCred.RefreshToken)
		}
		time.Sleep(200 * time.Millisecond)
	}
	aCred = readVaultOAuth(t, vaultDir, "memberA")

	// memberB's rotated tokens must reference memberB. The vault stores
	// the raw upstream JWT, so decode the payload to inspect the claim.
	bPayload := decodeJWTPayload(t, bCred.AccessToken)
	if !strings.Contains(bPayload, `"member":"memberB"`) {
		t.Fatalf("memberB vault access token is not memberB's minted JWT; payload=%s", bPayload)
	}
	// memberA's vault entry must NOT have been overwritten with B's
	// rotated tokens (the Risk R1 mis-attribution failure mode).
	if strings.HasPrefix(aCred.RefreshToken, "real-refresh-memberB-rot-") {
		t.Fatalf("R1 VIOLATION: memberB's rotated refresh token landed in memberA's vault entry: %q",
			aCred.RefreshToken)
	}
	aPayload := decodeJWTPayload(t, aCred.AccessToken)
	if strings.Contains(aPayload, `"member":"memberB"`) {
		t.Fatalf("R1 VIOLATION: memberB's minted access token landed in memberA's vault entry; payload=%s", aPayload)
	}

	// The token endpoint must have been hit for BOTH members across the
	// two refreshes (A before failover, B after).
	if up.TokenCalls("memberA") < 1 {
		t.Fatalf("token endpoint calls for memberA = %d, want >= 1", up.TokenCalls("memberA"))
	}
	if up.TokenCalls("memberB") < 1 {
		t.Fatalf("token endpoint calls for memberB = %d, want >= 1", up.TokenCalls("memberB"))
	}

	// Audit log should record the failover.
	if !auditLogContains(t, proc.AuditPath, "cred_failover") {
		t.Error("audit log should contain a cred_failover entry")
	}
}

// decodeJWTPayload base64url-decodes the payload segment of a JWT for
// diagnostics. Returns the raw JSON string or an error message.
func decodeJWTPayload(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "(not a 3-part JWT: " + jwt + ")"
	}
	dec, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "(payload not base64url: " + err.Error() + ")"
	}
	return string(dec)
}
