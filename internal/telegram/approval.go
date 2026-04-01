package telegram

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Response int

const (
	ResponseAllowOnce Response = iota
	ResponseAlwaysAllow
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

type ApprovalRequest struct {
	ID          string
	Destination string
	Port        int
	CreatedAt   time.Time
}

type ApprovalBroker struct {
	mu      sync.Mutex
	pending chan ApprovalRequest
	waiters map[string]chan Response
	nextID  atomic.Int64
}

func NewApprovalBroker() *ApprovalBroker {
	return &ApprovalBroker{
		pending: make(chan ApprovalRequest, 100),
		waiters: make(map[string]chan Response),
	}
}

func (b *ApprovalBroker) Pending() <-chan ApprovalRequest {
	return b.pending
}

func (b *ApprovalBroker) Request(dest string, port int, timeout time.Duration) (Response, error) {
	id := fmt.Sprintf("req_%d", b.nextID.Add(1))
	ch := make(chan Response, 1)

	b.mu.Lock()
	b.waiters[id] = ch
	b.mu.Unlock()

	b.pending <- ApprovalRequest{
		ID:          id,
		Destination: dest,
		Port:        port,
		CreatedAt:   time.Now(),
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		b.mu.Lock()
		delete(b.waiters, id)
		b.mu.Unlock()
		return ResponseDeny, fmt.Errorf("approval timeout after %v", timeout)
	}
}

func (b *ApprovalBroker) Resolve(id string, resp Response) {
	b.mu.Lock()
	ch, ok := b.waiters[id]
	if ok {
		delete(b.waiters, id)
	}
	b.mu.Unlock()

	if ok {
		ch <- resp
	}
}
