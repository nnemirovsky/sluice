// Package telegram provides Telegram bot integration for human approval of
// agent actions. It supports inline keyboard approval UX, admin commands for
// policy and credential management, and rate limiting of approval requests.
package telegram

import (
	"fmt"
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

// Response represents a human operator's decision on an approval request.
type Response int

const (
	// ResponseAllowOnce permits the connection for this request only.
	ResponseAllowOnce Response = iota
	// ResponseAlwaysAllow permits the connection and adds a dynamic allow rule.
	ResponseAlwaysAllow
	// ResponseDeny rejects the connection request.
	ResponseDeny
)

func (r Response) String() string {
	switch r {
	case ResponseAllowOnce:
		return "allow_once"
	case ResponseAlwaysAllow:
		return "always_allow"
	case ResponseDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// ApprovalRequest represents a pending connection that requires human approval.
type ApprovalRequest struct {
	ID          string
	Destination string
	Port        int
	CreatedAt   time.Time
}

// timedOutTTL is how long timed-out request IDs are retained for bot-side
// cleanup. After this duration, unclaimed entries are garbage collected
// during the next timeout to prevent unbounded map growth when operators
// never tap expired buttons.
const timedOutTTL = 10 * time.Minute

// ApprovalBroker mediates between the proxy (which needs approval for
// connections) and the Telegram bot (which presents inline keyboards to the
// operator). It enforces MaxPendingRequests and per-destination rate limits
// to prevent approval queue flooding.
type ApprovalBroker struct {
	mu       sync.Mutex
	pending  chan ApprovalRequest
	waiters  map[string]chan Response
	timedOut map[string]time.Time
	nextID   atomic.Int64

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
}

// BrokerOption configures an ApprovalBroker.
type BrokerOption func(*ApprovalBroker)

// WithMaxPending sets the maximum number of pending approval requests.
func WithMaxPending(n int) BrokerOption {
	return func(b *ApprovalBroker) {
		b.MaxPendingRequests = n
	}
}

// WithDestinationRateLimit sets the per-destination rate limit.
func WithDestinationRateLimit(max int, window time.Duration) BrokerOption {
	return func(b *ApprovalBroker) {
		b.destRateMax = max
		b.destRateWindow = window
	}
}

func NewApprovalBroker(opts ...BrokerOption) *ApprovalBroker {
	b := &ApprovalBroker{
		pending:            make(chan ApprovalRequest, 100),
		waiters:            make(map[string]chan Response),
		timedOut:           make(map[string]time.Time),
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

func (b *ApprovalBroker) now() time.Time {
	if b.nowFunc != nil {
		return b.nowFunc()
	}
	return time.Now()
}

func (b *ApprovalBroker) Pending() <-chan ApprovalRequest {
	return b.pending
}

func (b *ApprovalBroker) Request(dest string, port int, timeout time.Duration) (Response, error) {
	id := fmt.Sprintf("req_%d", b.nextID.Add(1))
	ch := make(chan Response, 1)

	b.mu.Lock()
	// Check pending limit.
	if b.MaxPendingRequests > 0 && len(b.waiters) >= b.MaxPendingRequests {
		b.mu.Unlock()
		return ResponseDeny, ErrPendingLimitExceeded
	}
	// Check per-destination rate limit.
	if b.destRateMax > 0 && b.destRateWindow > 0 {
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
	}
	b.waiters[id] = ch
	b.mu.Unlock()

	req := ApprovalRequest{
		ID:          id,
		Destination: dest,
		Port:        port,
		CreatedAt:   b.now(),
	}

	// Single deadline for the entire request lifecycle (enqueue + wait)
	// to prevent blocking for 2x the configured timeout.
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	// Use a timeout when sending to the pending channel to prevent proxy
	// goroutines from blocking indefinitely when the channel is full
	// (e.g., Telegram API outage).
	select {
	case b.pending <- req:
	case <-deadline.C:
		b.mu.Lock()
		delete(b.waiters, id)
		b.mu.Unlock()
		return ResponseDeny, fmt.Errorf("approval queue full (timeout after %v)", timeout)
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-deadline.C:
		b.mu.Lock()
		_, stillPending := b.waiters[id]
		if stillPending {
			delete(b.waiters, id)
			b.timedOut[id] = time.Now()
			// Garbage-collect stale timedOut entries that were never
			// consumed by the bot (operator never tapped the button).
			for k, t := range b.timedOut {
				if time.Since(t) > timedOutTTL {
					delete(b.timedOut, k)
				}
			}
		}
		b.mu.Unlock()
		if !stillPending {
			// Resolve already consumed the waiter and sent a response
			// on the buffered channel. Honor it so the proxy decision
			// matches what the Telegram message shows to the operator.
			return <-ch, nil
		}
		return ResponseDeny, fmt.Errorf("approval timeout after %v", timeout)
	}
}

// PendingCount returns the number of approval requests awaiting a response.
func (b *ApprovalBroker) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.waiters)
}

// HasWaiter reports whether a request ID still has an active waiter.
// Returns false if the request has already timed out or been resolved.
func (b *ApprovalBroker) HasWaiter(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.waiters[id]
	return ok
}

// WasTimedOut reports whether a request timed out (as opposed to being
// resolved by a callback). This is a non-destructive read. Call
// ClearTimedOut to remove the entry after handling it.
func (b *ApprovalBroker) WasTimedOut(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.timedOut[id]
	return ok
}

// ClearTimedOut removes the timed-out flag for a request ID.
// Call this after successfully handling the timeout (e.g. editing the
// Telegram message) so other code paths do not attempt to handle it again.
func (b *ApprovalBroker) ClearTimedOut(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.timedOut, id)
}

// Resolve delivers a response to a pending approval request.
// Returns true if the request was still pending, false if it had already
// timed out or been resolved (so the caller can show an appropriate message).
func (b *ApprovalBroker) Resolve(id string, resp Response) bool {
	b.mu.Lock()
	ch, ok := b.waiters[id]
	if ok {
		delete(b.waiters, id)
	}
	b.mu.Unlock()

	if ok {
		ch <- resp
	}
	return ok
}

// CancelAll auto-denies all pending approval requests. Called during
// graceful shutdown so that in-flight proxy goroutines blocked on
// approval can complete promptly.
func (b *ApprovalBroker) CancelAll() {
	b.mu.Lock()
	waiters := make(map[string]chan Response, len(b.waiters))
	for id, ch := range b.waiters {
		waiters[id] = ch
	}
	b.waiters = make(map[string]chan Response)
	b.mu.Unlock()

	for _, ch := range waiters {
		ch <- ResponseDeny
	}
}
