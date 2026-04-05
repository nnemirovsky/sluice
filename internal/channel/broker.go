package channel

import (
	"context"
	"fmt"
	"log"
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

// Broker coordinates approval flow across multiple enabled channels.
// Approval requests are broadcast to all channels. The first Resolve call
// wins. Other channels receive CancelApproval for cleanup.
type Broker struct {
	mu       sync.Mutex
	channels []Channel
	waiters  map[string]waiter
	timedOut map[string]time.Time
	nextID   atomic.Int64

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
}

// waiter tracks a pending approval request and its response channel.
type waiter struct {
	ch  chan Response
	req ApprovalRequest
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
func WithDestinationRateLimit(max int, window time.Duration) BrokerOption {
	return func(b *Broker) {
		b.destRateMax = max
		b.destRateWindow = window
	}
}

// NewBroker creates a Broker that coordinates approval across the given channels.
func NewBroker(channels []Channel, opts ...BrokerOption) *Broker {
	b := &Broker{
		channels:           channels,
		waiters:            make(map[string]waiter),
		timedOut:           make(map[string]time.Time),
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

// Request sends an approval request to all channels and blocks until one
// responds or the timeout expires. Returns the first response received.
func (b *Broker) Request(dest string, port int, timeout time.Duration) (Response, error) {
	id := fmt.Sprintf("req_%d", b.nextID.Add(1))
	ch := make(chan Response, 1)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ResponseDeny, fmt.Errorf("approval broker shutting down")
	}
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

	req := ApprovalRequest{
		ID:          id,
		Destination: dest,
		Port:        port,
		CreatedAt:   b.now(),
	}
	b.waiters[id] = waiter{ch: ch, req: req}
	b.mu.Unlock()

	// Broadcast to all channels (non-blocking).
	b.broadcast(req)

	// Single deadline for the entire request lifecycle.
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

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
		delete(b.waiters, id)
		b.mu.Unlock()
		b.cancelOnChannels(id)
		return ResponseDeny, fmt.Errorf("approval broker shutting down")
	case <-deadline.C:
		b.mu.Lock()
		_, stillPending := b.waiters[id]
		if stillPending {
			delete(b.waiters, id)
			b.timedOut[id] = b.now()
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
		b.cancelOnChannels(id)
		return ResponseDeny, fmt.Errorf("approval timeout after %v", timeout)
	}
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
		delete(b.waiters, id)
	}
	b.mu.Unlock()

	if ok {
		w.ch <- resp
		// Cancel on all channels so they can clean up (e.g. edit message).
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
	}
	b.waiters = make(map[string]waiter)
	b.mu.Unlock()

	// Send deny responses before closing done. This ensures goroutines in
	// the select see the response on ch before they see done closed, so
	// they return the response without an error.
	for id, w := range waiters {
		w.ch <- ResponseDeny
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
