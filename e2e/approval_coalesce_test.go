//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedVerdictServer is a webhook channel backend that HOLDS the first
// approval decision until the test explicitly releases it. This is the
// piece the existing synchronous verdictServer cannot express: to observe
// broker-level approval coalescing we need a first approval to stay pending
// while a concurrent burst of requests to the same dest:port arrives. With
// a synchronous server every request would get an instant verdict and the
// burst would never overlap a pending approval.
//
// Behavior:
//   - Every approval POST increments approvalCalls and is recorded.
//   - The FIRST approval POST blocks on the release channel. The broker
//     coalesces concurrent same-dest:port requests into that one pending
//     waiter, so a correctly-coalescing sluice delivers exactly ONE
//     approval POST for the whole burst.
//   - After release, the held call (and any further calls) return the
//     configured verdict.
//
// maxConcurrent tracks the peak number of approval handlers in flight,
// which lets the test prove the burst genuinely overlapped the pending
// approval rather than serializing behind it.
type gatedVerdictServer struct {
	verdict string

	release chan struct{}
	once    sync.Once

	mu            sync.Mutex
	calls         int
	approvalCalls int
	cancelCalls   int
	requests      []map[string]interface{}

	inFlight      atomic.Int64
	maxConcurrent atomic.Int64
}

func newGatedVerdictServer(verdict string) *gatedVerdictServer {
	return &gatedVerdictServer{
		verdict: verdict,
		release: make(chan struct{}),
	}
}

// Release unblocks the held first approval. Safe to call once.
func (g *gatedVerdictServer) Release() {
	g.once.Do(func() { close(g.release) })
}

func (g *gatedVerdictServer) ApprovalCalls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.approvalCalls
}

func (g *gatedVerdictServer) CancelCalls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cancelCalls
}

func (g *gatedVerdictServer) MaxConcurrent() int64 {
	return g.maxConcurrent.Load()
}

func (g *gatedVerdictServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusInternalServerError)
		return
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	reqType, _ := parsed["type"].(string)

	g.mu.Lock()
	g.calls++
	g.requests = append(g.requests, parsed)
	if reqType != "approval" {
		if reqType == "cancel" {
			g.cancelCalls++
		}
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}
	g.approvalCalls++
	isFirst := g.approvalCalls == 1
	g.mu.Unlock()

	// Track concurrency of approval handlers in flight.
	n := g.inFlight.Add(1)
	for {
		cur := g.maxConcurrent.Load()
		if n <= cur || g.maxConcurrent.CompareAndSwap(cur, n) {
			break
		}
	}
	defer g.inFlight.Add(-1)

	if isFirst {
		// Hold the decision so the broker accumulates coalesced subs.
		<-g.release
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"verdict": g.verdict})
}

func startGatedVerdictServer(t *testing.T, verdict string) (*httptest.Server, *gatedVerdictServer) {
	t.Helper()
	g := newGatedVerdictServer(verdict)
	srv := newIPv4Server(t, g)
	t.Cleanup(srv.Close)
	return srv, g
}

// TestApprovalCoalesce_BurstOnePrompt is the GAP 2 e2e: a burst of
// concurrent requests to ONE Ask destination through the proxy must
// produce exactly ONE approval prompt (broker coalescing), and one
// resolve must fan out so ALL requests proceed.
//
// The gated verdict server holds the first approval pending while the
// rest of the burst arrives, so the coalescing window is real (not a
// synchronous race). Asserts:
//
//   - exactly ONE approval webhook call for the whole burst,
//   - all N requests succeed after the single release,
//   - the peak concurrency at the webhook is 1 (the burst coalesced into
//     the single held approval rather than each firing its own POST).
func TestApprovalCoalesce_BurstOnePrompt(t *testing.T) {
	backend := startTLSEchoServer(t)
	host, port := mustSplitAddr(t, backend.URL)

	// always_allow so the single resolve both fans out to every coalesced
	// waiter AND persists a rule (the persisted rule is keyed dest:port —
	// the same key the broker coalesces on).
	srv, g := startGatedVerdictServer(t, "always_allow")

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%s]
name = "ask backend"
`, host, port)

	proc := sluiceWithWebhook(t, config, srv.URL)

	const burst = 8

	type result struct {
		status int
		err    error
	}
	results := make(chan result, burst)

	// Launch the burst. Each goroutine opens its OWN SOCKS5 CONNECT to the
	// same dest:port, so each is an independent connection-level Ask that
	// hits broker.Request with the same dedup key. The first opens the
	// prompt (held by the gated server); the rest must coalesce onto it.
	var launched sync.WaitGroup
	for i := 0; i < burst; i++ {
		launched.Add(1)
		go func() {
			launched.Done()
			status, _, err := tryHTTPGetViaSOCKS5(t, proc.ProxyAddr, backend.URL+"/burst")
			results <- result{status: status, err: err}
		}()
	}
	launched.Wait()

	// Give the burst time to reach the broker and coalesce behind the
	// single held approval before releasing. The first approval POST is
	// blocked in the gated server during this window.
	deadline := time.Now().Add(8 * time.Second)
	for {
		if g.ApprovalCalls() >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no approval webhook call arrived; broker never delivered the prompt")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Let the rest of the burst pile up onto the pending waiter.
	time.Sleep(1500 * time.Millisecond)

	// Exactly ONE approval prompt for the whole burst.
	if got := g.ApprovalCalls(); got != 1 {
		t.Fatalf("approval webhook calls during pending window = %d, want exactly 1 (burst must coalesce)", got)
	}

	// Release the single held decision; it must fan out to ALL waiters.
	g.Release()

	// Collect all results.
	oks := 0
	for i := 0; i < burst; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("burst request %d errored: %v", i, r.err)
				continue
			}
			if r.status == http.StatusOK {
				oks++
			} else {
				t.Errorf("burst request %d: status=%d, want 200", i, r.status)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("burst request %d never completed (fan-out broke)", i)
		}
	}

	if oks != burst {
		t.Fatalf("only %d/%d burst requests succeeded after single resolve", oks, burst)
	}

	// Still exactly one approval call total: the coalesced subs must not
	// have triggered their own webhook deliveries.
	if got := g.ApprovalCalls(); got != 1 {
		t.Fatalf("total approval webhook calls = %d, want exactly 1 (coalesced subs must not re-prompt)", got)
	}

	// Peak concurrency at the webhook proves the burst overlapped the
	// pending approval (it was 1 because all but the first coalesced and
	// never reached the webhook).
	if mc := g.MaxConcurrent(); mc != 1 {
		t.Fatalf("peak concurrent approval handlers = %d, want 1 (more than 1 means requests did NOT coalesce)", mc)
	}
}
