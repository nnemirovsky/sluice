package channel

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ErrPendingLimitExceeded is returned when the broker's pending request
// limit is reached.
var ErrPendingLimitExceeded = fmt.Errorf("approval pending limit exceeded")

// ErrDestinationRateLimited is returned when a destination exceeds its
// per-minute request allowance.
var ErrDestinationRateLimited = fmt.Errorf("destination rate limited")

// timedOutTTL is how long timed-out request IDs are retained for channel-side
// cleanup. After this duration, unclaimed entries are garbage collected
// during the next timeout to prevent unbounded map growth when operators
// never tap expired buttons.
const timedOutTTL = 10 * time.Minute

// maxCoalescedSubs caps how many coalesced subscribers may attach to a single
// primary prompt. Coalesced subscribers deliberately bypass both the pending
// limit and the per-destination rate limit (the operator answers the whole
// burst with one tap), but an unbounded attach lets an abusive client
// hammering one dest:port accumulate goroutines and channels without limit.
// The cap bounds that fan-out: a reasonable burst still coalesces to one
// prompt, but once the primary already has this many subscribers the excess
// callers are rejected with the broker's standard over-capacity response
// (ResponseDeny + ErrPendingLimitExceeded) instead of being appended. 256 is
// well above any legitimate concurrent burst to a single target yet small
// enough that the worst-case goroutine/channel footprint per primary stays
// bounded.
const maxCoalescedSubs = 256

// Broker coordinates approval flow across multiple enabled channels.
// Approval requests are broadcast to all channels. The first Resolve call
// wins. Other channels receive CancelApproval for cleanup.
type Broker struct {
	mu       sync.Mutex
	channels []Channel
	waiters  map[string]waiter
	timedOut map[string]time.Time
	nextID   atomic.Int64

	// dedupIndex maps a persistence-equivalent target key ("dest:port")
	// to the primary request ID currently holding an open prompt for that
	// target. Concurrent requests to the same target while the primary is
	// pending attach to the primary as coalesced subscribers instead of
	// opening their own prompt.
	dedupIndex map[string]string

	// coalesced retains the final coalesced count for a primary request ID
	// after its waiter has been removed (resolved/timed-out/cancelled), so
	// channels editing the resolved/cancelled message can render how many
	// requests the single decision covered. GC'd like timedOut.
	coalesced map[string]coalescedRecord

	// closed is set to true by CancelAll under the mutex, before the done
	// channel is closed. Request checks this flag under the same mutex to
	// prevent registering new waiters after CancelAll has copied and reset
	// the waiters map.
	closed bool

	// done is closed by CancelAll to unblock goroutines waiting during
	// graceful shutdown.
	done chan struct{}

	// MaxPendingRequests is the maximum number of concurrent approval
	// requests awaiting a response. When exceeded, new requests are
	// auto-denied. Zero means no limit.
	MaxPendingRequests int

	// destRateMax is the maximum number of approval requests allowed per
	// destination within destRateWindow. Zero means no per-destination limit.
	destRateMax    int
	destRateWindow time.Duration
	destTimestamps map[string][]time.Time

	// nowFunc is used for testing to control time. If nil, time.Now is used.
	nowFunc func() time.Time

	// resolveAfterDeleteHook is a test-only seam invoked inside Resolve
	// immediately after the waiter has been deleted from b.waiters and the
	// coalesced count recorded, but before the primary/subscriber response
	// sends. It runs while b.mu is held (post-fix the sends are also under
	// the lock), so a test can drive a coalesced subscriber's deadline path
	// concurrently and assert it cannot observe a lost wakeup. nil in
	// production.
	resolveAfterDeleteHook func()

	// subDeadlineGate is a test-only seam invoked at the very top of
	// waitSub's deadline branch, before detachSub. A test uses it to park a
	// coalesced subscriber exactly at the start of its timeout-handling path
	// so the resolve/detach interleave can be forced deterministically
	// without sleeps. nil in production.
	subDeadlineGate func()
}

// waiter tracks a pending approval request and its response channel.
//
// subs holds buffered (cap 1) response channels for coalesced requests that
// attached to this primary waiter while it was pending. count starts at 1
// (the primary) and increments for every attached sub. dedupKey is the
// "dest:port" key under which this waiter is registered in dedupIndex (empty
// when the request opted out of coalescing).
type waiter struct {
	ch       chan Response
	req      ApprovalRequest
	subs     []chan Response
	count    int
	dedupKey string
}

// coalescedRecord retains a resolved primary's final coalesced count for a
// bounded TTL so message-edit paths can render it after the waiter is gone.
type coalescedRecord struct {
	count int
	at    time.Time
}

// BrokerOption configures a Broker.
type BrokerOption func(*Broker)

// WithMaxPending sets the maximum number of pending approval requests.
func WithMaxPending(n int) BrokerOption {
	return func(b *Broker) {
		b.MaxPendingRequests = n
	}
}

// WithDestinationRateLimit sets the per-destination rate limit.
func WithDestinationRateLimit(maxReqs int, window time.Duration) BrokerOption {
	return func(b *Broker) {
		b.destRateMax = maxReqs
		b.destRateWindow = window
	}
}

// NewBroker creates a Broker that coordinates approval across the given channels.
func NewBroker(channels []Channel, opts ...BrokerOption) *Broker {
	b := &Broker{
		channels:           channels,
		waiters:            make(map[string]waiter),
		timedOut:           make(map[string]time.Time),
		dedupIndex:         make(map[string]string),
		coalesced:          make(map[string]coalescedRecord),
		done:               make(chan struct{}),
		MaxPendingRequests: 50,
		destRateMax:        5,
		destRateWindow:     time.Minute,
		destTimestamps:     make(map[string][]time.Time),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

func (b *Broker) now() time.Time {
	if b.nowFunc != nil {
		return b.nowFunc()
	}
	return time.Now()
}

// RequestOption configures optional fields on an ApprovalRequest, or
// toggles request-scoped broker behavior such as rate limit bypass.
type RequestOption func(*requestConfig)

// requestConfig carries both the approval request payload (which is copied
// out to ApprovalRequest once finalized) and request-scoped broker flags
// that do not belong on the wire.
type requestConfig struct {
	req             ApprovalRequest
	bypassRateLimit bool
	noCoalesce      bool
}

// WithNoCoalesce disables broker-level coalescing for this request. Use it
// when distinct requests to the same "dest:port" are NOT semantically
// equivalent — e.g. MCP tool calls, whose ToolArgs differ and feed
// arg-sensitive ContentInspector/exec rules. Such requests must each get
// their own prompt.
func WithNoCoalesce() RequestOption {
	return func(c *requestConfig) {
		c.noCoalesce = true
	}
}

// WithToolArgs sets the truncated tool arguments on an MCP approval request.
func WithToolArgs(args string) RequestOption {
	return func(c *requestConfig) {
		c.req.ToolArgs = args
	}
}

// WithMethodAndPath sets the HTTP method and path for a per-request approval.
// Use this when triggering the approval broker for an individual HTTP/HTTPS
// or QUIC/HTTP3 request so channels can render context like "GET https://example.com/users".
func WithMethodAndPath(method, path string) RequestOption {
	return func(c *requestConfig) {
		c.req.Method = method
		c.req.Path = path
	}
}

// WithHTTPVersion sets the negotiated HTTP version (e.g. "HTTP/2") for a
// per-request approval so channels can display the protocol version.
func WithHTTPVersion(version string) RequestOption {
	return func(c *requestConfig) {
		c.req.HTTPVersion = version
	}
}

// WithBypassRateLimit tells the broker to skip the per-destination rate
// limiter for this request. Per-request policy callers use this so a
// keep-alive connection hammering a single destination does not silently
// 403 once the 5-per-minute cap is reached. Connection-level callers
// should not use this option.
func WithBypassRateLimit() RequestOption {
	return func(c *requestConfig) {
		c.bypassRateLimit = true
	}
}

// Request sends an approval request to all channels and blocks until one
// responds or the timeout expires. Returns the first response received.
//
// Coalescing: concurrent requests sharing a persistence-equivalent target
// ("dest:port") collapse onto the first one's prompt. Only the first opens a
// prompt; later arrivals attach as buffered subscribers and receive the same
// response when the primary resolves/times out/is cancelled. Pass
// WithNoCoalesce to opt out (MCP tool calls).
func (b *Broker) Request(dest string, port int, protocol string, timeout time.Duration, opts ...RequestOption) (Response, error) {
	ch := make(chan Response, 1)

	cfg := requestConfig{
		req: ApprovalRequest{
			Destination: dest,
			Port:        port,
			Protocol:    protocol,
			CreatedAt:   b.now(),
		},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	var dedupKey string
	if !cfg.noCoalesce {
		dedupKey = dest + ":" + strconv.Itoa(port)
	}

	// Single deadline for the entire request lifecycle (covers both the
	// primary path and the coalesced-subscriber path).
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ResponseDeny, fmt.Errorf("approval broker shutting down")
	}

	// Coalesce: attach to an existing pending prompt for the same target.
	// This runs before the pending/rate-limit checks because a coalesced
	// subscriber consumes neither budget — the primary already did, and the
	// whole point is to avoid both the prompt wall and spurious rate-limit
	// denials for a burst the operator will answer with a single tap.
	if dedupKey != "" {
		if primaryID, ok := b.dedupIndex[dedupKey]; ok {
			if w, ok := b.waiters[primaryID]; ok {
				// Bound the coalesced fan-out. Without a cap an abusive
				// client hammering one dest:port grows w.subs (and a
				// blocked goroutine per sub) without limit, since
				// coalesced subscribers intentionally skip the pending
				// and per-destination limits. Mirror the broker's
				// existing over-capacity behavior (the pending-limit
				// branch below) and reject the excess caller instead of
				// appending unboundedly.
				if len(w.subs) >= maxCoalescedSubs {
					b.mu.Unlock()
					return ResponseDeny, ErrPendingLimitExceeded
				}
				subCh := make(chan Response, 1)
				w.subs = append(w.subs, subCh)
				w.count++
				b.waiters[primaryID] = w
				b.mu.Unlock()
				return b.waitSub(primaryID, subCh, deadline.C, timeout)
			}
		}
	}

	// Check pending limit.
	if b.MaxPendingRequests > 0 && len(b.waiters) >= b.MaxPendingRequests {
		b.mu.Unlock()
		return ResponseDeny, ErrPendingLimitExceeded
	}
	// Check per-destination rate limit, unless the caller explicitly
	// opted out (per-request policy). Even when bypassed the timestamp
	// bookkeeping is skipped entirely so per-request traffic does not
	// consume budget meant for connection-level approvals.
	if !cfg.bypassRateLimit && b.destRateMax > 0 && b.destRateWindow > 0 {
		now := b.now()
		cutoff := now.Add(-b.destRateWindow)
		timestamps := b.destTimestamps[dest]
		// Trim timestamps outside the window.
		start := 0
		for start < len(timestamps) && timestamps[start].Before(cutoff) {
			start++
		}
		timestamps = timestamps[start:]
		if len(timestamps) >= b.destRateMax {
			b.destTimestamps[dest] = timestamps
			b.mu.Unlock()
			return ResponseDeny, ErrDestinationRateLimited
		}
		b.destTimestamps[dest] = append(timestamps, now)
		// Lazy cleanup: prune stale destination entries to prevent
		// unbounded map growth from destinations that stop sending requests.
		if len(b.destTimestamps) > 100 {
			for k, ts := range b.destTimestamps {
				if k == dest {
					continue
				}
				if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
					delete(b.destTimestamps, k)
				}
			}
		}
	}

	id := fmt.Sprintf("req_%d", b.nextID.Add(1))
	cfg.req.ID = id
	req := cfg.req
	b.waiters[id] = waiter{ch: ch, req: req, count: 1, dedupKey: dedupKey}
	if dedupKey != "" {
		b.dedupIndex[dedupKey] = id
	}
	b.mu.Unlock()

	// Broadcast to all channels (non-blocking).
	b.broadcast(req)

	select {
	case resp := <-ch:
		return resp, nil
	case <-b.done:
		// CancelAll sends ResponseDeny on ch before closing done.
		// Drain the buffered channel first to return without error.
		select {
		case resp := <-ch:
			return resp, nil
		default:
		}
		b.mu.Lock()
		w, ok := b.waiters[id]
		if ok {
			delete(b.waiters, id)
			if w.dedupKey != "" {
				delete(b.dedupIndex, w.dedupKey)
			}
			// Retain the final coalesced count so the shutdown
			// CancelApproval edit can still render "applied to N
			// requests" for a burst that was pending at shutdown.
			b.recordCoalescedLocked(id, w.count)
		}
		b.mu.Unlock()
		// Fan the terminal deny to any coalesced subscribers (buffered
		// cap 1, so a send to a detached sub never blocks).
		for _, sub := range w.subs {
			sub <- ResponseDeny
		}
		b.cancelOnChannels(id)
		return ResponseDeny, fmt.Errorf("approval broker shutting down")
	case <-deadline.C:
		b.mu.Lock()
		w, stillPending := b.waiters[id]
		if stillPending {
			delete(b.waiters, id)
			if w.dedupKey != "" {
				delete(b.dedupIndex, w.dedupKey)
			}
			b.timedOut[id] = b.now()
			b.recordCoalescedLocked(id, w.count)
			// Garbage-collect stale timedOut entries.
			now := b.now()
			for k, t := range b.timedOut {
				if now.Sub(t) > timedOutTTL {
					delete(b.timedOut, k)
				}
			}
		}
		b.mu.Unlock()
		if !stillPending {
			// Resolve already consumed the waiter and sent a response
			// on the buffered channel. Honor it so the decision matches
			// what the channel showed to the operator.
			return <-ch, nil
		}
		// Fan the terminal deny to every coalesced subscriber.
		for _, sub := range w.subs {
			sub <- ResponseDeny
		}
		b.cancelOnChannels(id)
		return ResponseDeny, fmt.Errorf("approval timeout after %v", timeout)
	}
}

// waitSub blocks a coalesced subscriber until the primary resolves (its
// response is fanned to subCh), the deadline fires, or the broker shuts
// down. A subscriber owns no waiter/timedOut entry: on timeout it detaches
// only itself from the primary's subs slice and must never tear down the
// shared primary waiter.
func (b *Broker) waitSub(primaryID string, subCh chan Response, deadlineC <-chan time.Time, timeout time.Duration) (Response, error) {
	select {
	case resp := <-subCh:
		return resp, nil
	case <-b.done:
		// Prefer a response the primary may have already fanned out.
		select {
		case resp := <-subCh:
			return resp, nil
		default:
		}
		b.detachSub(primaryID, subCh)
		return ResponseDeny, fmt.Errorf("approval broker shutting down")
	case <-deadlineC:
		if b.subDeadlineGate != nil {
			b.subDeadlineGate()
		}
		b.detachSub(primaryID, subCh)
		// The primary may have resolved between the deadline firing and
		// the detach completing. The sub chan is buffered (cap 1), so a
		// concurrent fan-out send already landed; honor it rather than
		// denying an approved request.
		select {
		case resp := <-subCh:
			return resp, nil
		default:
		}
		return ResponseDeny, fmt.Errorf("approval timeout after %v", timeout)
	}
}

// detachSub removes a single subscriber channel from a primary waiter's subs
// slice if the waiter is still present. It never deletes the waiter itself.
func (b *Broker) detachSub(primaryID string, subCh chan Response) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.waiters[primaryID]
	if !ok {
		return
	}
	for i, c := range w.subs {
		if c == subCh {
			w.subs = append(w.subs[:i], w.subs[i+1:]...)
			// A subscriber that timed out and detached is no longer
			// covered by the primary's eventual decision, so it must not
			// inflate the coalesced count. Decrement, never below 1 (the
			// primary itself is always counted) (Finding 3).
			if w.count > 1 {
				w.count--
			}
			b.waiters[primaryID] = w
			return
		}
	}
}

// recordCoalescedLocked stores a resolved/timed-out primary's final coalesced
// count for a bounded TTL so message-edit paths can render it after the
// waiter is gone. Caller must hold b.mu.
func (b *Broker) recordCoalescedLocked(id string, count int) {
	now := b.now()
	b.coalesced[id] = coalescedRecord{count: count, at: now}
	for k, r := range b.coalesced {
		if now.Sub(r.at) > timedOutTTL {
			delete(b.coalesced, k)
		}
	}
}

// CoalescedCount reports how many requests a single approval decision covered
// for the given primary request ID. While the waiter is still pending it
// returns the live count; after resolution it returns the retained final
// count; if nothing is known it returns 1 (a lone request).
func (b *Broker) CoalescedCount(id string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if w, ok := b.waiters[id]; ok {
		return w.count
	}
	if r, ok := b.coalesced[id]; ok {
		return r.count
	}
	return 1
}

// broadcast sends the approval request to all channels. Errors and panics
// from individual channels are logged but do not prevent other channels from
// receiving the request.
func (b *Broker) broadcast(req ApprovalRequest) {
	for _, ch := range b.channels {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[WARN] channel panicked during approval request %s: %v", req.ID, r)
				}
			}()
			if err := ch.RequestApproval(context.Background(), req); err != nil {
				log.Printf("[WARN] channel failed to send approval request %s: %v", req.ID, err)
			}
		}()
	}
}

// cancelOnChannels calls CancelApproval on all channels for cleanup.
func (b *Broker) cancelOnChannels(id string) {
	for _, ch := range b.channels {
		_ = ch.CancelApproval(id)
	}
}

// PendingCount returns the number of approval requests awaiting a response.
func (b *Broker) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.waiters)
}

// PendingRequests returns a snapshot of all pending approval requests.
func (b *Broker) PendingRequests() []ApprovalRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	reqs := make([]ApprovalRequest, 0, len(b.waiters))
	for _, w := range b.waiters {
		reqs = append(reqs, w.req)
	}
	return reqs
}

// HasWaiter reports whether a request ID still has an active waiter.
func (b *Broker) HasWaiter(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.waiters[id]
	return ok
}

// WasTimedOut reports whether a request timed out (as opposed to being
// resolved by a callback).
func (b *Broker) WasTimedOut(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.timedOut[id]
	return ok
}

// ClearTimedOut removes the timed-out flag for a request ID.
func (b *Broker) ClearTimedOut(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.timedOut, id)
}

// Resolve delivers a response to a pending approval request. The first call
// wins. Subsequent calls for the same ID return false. After the first
// resolution, CancelApproval is called on all channels for cleanup.
func (b *Broker) Resolve(id string, resp Response) bool {
	b.mu.Lock()
	w, ok := b.waiters[id]
	if ok {
		// Delete the waiter AND its dedup index entry in the same locked
		// section. This is what closes the late-attach race: any request
		// that took b.mu before this point either found the waiter (and
		// attached as a sub captured in w.subs below) or, after this,
		// finds neither the dedupIndex entry nor the waiter and opens its
		// own fresh prompt — it can never attach to a dead waiter.
		delete(b.waiters, id)
		if w.dedupKey != "" {
			delete(b.dedupIndex, w.dedupKey)
		}
		b.recordCoalescedLocked(id, w.count)

		if b.resolveAfterDeleteHook != nil {
			b.resolveAfterDeleteHook()
		}

		// Deliver the primary response and fan it to every coalesced
		// subscriber WHILE STILL HOLDING b.mu. The primary ch and every
		// sub chan are buffered cap-1 and receive exactly one value, so
		// these sends cannot block — holding the lock here is safe and
		// closes the resolve/detach lost-wakeup window: a subscriber
		// whose deadline fires takes b.mu in detachSub, so it serializes
		// against this section. It therefore either detaches BEFORE this
		// runs (removed from w.subs, gets no send, returns its own
		// timeout — correct, it never coalesced under this decision) or
		// AFTER (the response is already buffered on its cap-1 chan, and
		// waitSub's post-detach non-blocking read picks it up instead of
		// denying an approved request). There is no instant where a sub
		// can observe "waiter gone AND response not yet sent".
		w.ch <- resp
		for _, sub := range w.subs {
			sub <- resp
		}
	}
	b.mu.Unlock()

	if ok {
		// Cancel on all channels so they can clean up (e.g. edit
		// message). This calls into channel implementations that may do
		// blocking network I/O, so it must stay OUTSIDE b.mu.
		b.cancelOnChannels(id)
	}
	return ok
}

// CancelAll auto-denies all pending approval requests. Called during graceful
// shutdown so that in-flight goroutines blocked on approval can complete
// promptly.
func (b *Broker) CancelAll() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	waiters := make(map[string]waiter, len(b.waiters))
	for id, w := range b.waiters {
		waiters[id] = w
		// Retain each waiter's final coalesced count before the map is
		// cleared, mirroring Resolve and the primary-timeout path. Without
		// this the shutdown CancelApproval edit sees CoalescedCount==1 and
		// omits "applied to N requests" for a burst that was pending at
		// shutdown (Finding 2).
		b.recordCoalescedLocked(id, w.count)
	}
	b.waiters = make(map[string]waiter)
	b.dedupIndex = make(map[string]string)
	b.mu.Unlock()

	// Send deny responses before closing done. This ensures goroutines in
	// the select see the response on ch before they see done closed, so
	// they return the response without an error. Coalesced subscribers are
	// fanned the same deny on their buffered (cap 1) chans.
	for id, w := range waiters {
		w.ch <- ResponseDeny
		for _, sub := range w.subs {
			sub <- ResponseDeny
		}
		b.cancelOnChannels(id)
	}

	// Close done to unblock any goroutines that have not yet reached the
	// response select (e.g. still being rate-checked) and to reject future
	// Request calls that pass the closed flag check.
	close(b.done)
}

// IsClosed reports whether the broker has been shut down via CancelAll.
func (b *Broker) IsClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Channels returns the list of channels registered with this broker.
func (b *Broker) Channels() []Channel {
	return b.channels
}
