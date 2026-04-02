package telegram

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestApprovalFlowAllowOnce(t *testing.T) {
	broker := NewApprovalBroker()

	go func() {
		// Simulate user responding after 10ms
		time.Sleep(10 * time.Millisecond)
		req := <-broker.Pending()
		broker.Resolve(req.ID, ResponseAllowOnce)
	}()

	resp, err := broker.Request("evil.com", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp != ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}
}

func TestApprovalFlowTimeout(t *testing.T) {
	broker := NewApprovalBroker()

	resp, err := broker.Request("evil.com", 443, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error, got response %v", resp)
	}
	if resp != ResponseDeny {
		t.Errorf("expected ResponseDeny on timeout, got %v", resp)
	}
}

func TestApprovalFlowDeny(t *testing.T) {
	broker := NewApprovalBroker()

	go func() {
		time.Sleep(10 * time.Millisecond)
		req := <-broker.Pending()
		broker.Resolve(req.ID, ResponseDeny)
	}()

	resp, err := broker.Request("evil.com", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
}

func TestPendingLimitExceeded(t *testing.T) {
	broker := NewApprovalBroker(WithMaxPending(3))

	// Fill up the pending slots by sending requests that won't be resolved.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			broker.Request("example.com", 443, 2*time.Second)
		}()
	}
	// Wait until all 3 are registered as waiters.
	for {
		if broker.PendingCount() == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// The 4th request should be auto-denied.
	resp, err := broker.Request("example.com", 443, time.Second)
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
	if !errors.Is(err, ErrPendingLimitExceeded) {
		t.Errorf("expected ErrPendingLimitExceeded, got %v", err)
	}

	// Drain pending and resolve to unblock goroutines.
	go func() {
		for req := range broker.Pending() {
			broker.Resolve(req.ID, ResponseDeny)
		}
	}()
	wg.Wait()
}

func TestPendingLimitZeroMeansUnlimited(t *testing.T) {
	broker := NewApprovalBroker(
		WithMaxPending(0),
		WithDestinationRateLimit(0, 0),
	)

	// Drain and resolve requests in background.
	go func() {
		for req := range broker.Pending() {
			broker.Resolve(req.ID, ResponseDeny)
		}
	}()

	// Should accept many requests without hitting any pending limit.
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := broker.Request("example.com", 443, 5*time.Second)
			if errors.Is(err, ErrPendingLimitExceeded) {
				t.Error("should not hit pending limit with MaxPending=0")
			}
		}()
	}
	wg.Wait()
}

func TestDestinationRateLimiting(t *testing.T) {
	fakeNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	broker := NewApprovalBroker(
		WithMaxPending(0),
		WithDestinationRateLimit(3, time.Minute),
	)
	broker.nowFunc = func() time.Time { return fakeNow }

	// Drain and resolve requests in background.
	go func() {
		for req := range broker.Pending() {
			broker.Resolve(req.ID, ResponseAllowOnce)
		}
	}()

	// First 3 requests to the same destination should succeed.
	for i := 0; i < 3; i++ {
		_, err := broker.Request("api.example.com", 443, time.Second)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}

	// 4th request within the same window should be rate limited.
	resp, err := broker.Request("api.example.com", 443, time.Second)
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
	if !errors.Is(err, ErrDestinationRateLimited) {
		t.Errorf("expected ErrDestinationRateLimited, got %v", err)
	}

	// A different destination should still work.
	_, err = broker.Request("other.example.com", 443, time.Second)
	if err != nil {
		t.Fatalf("different destination should not be rate limited: %v", err)
	}

	// Advance time past the window. The original destination should work again.
	fakeNow = fakeNow.Add(61 * time.Second)
	_, err = broker.Request("api.example.com", 443, time.Second)
	if err != nil {
		t.Fatalf("after window expiry, request should succeed: %v", err)
	}
}

func TestDestinationRateLimitDisabled(t *testing.T) {
	broker := NewApprovalBroker(
		WithMaxPending(0),
		WithDestinationRateLimit(0, 0),
	)

	// Drain and resolve requests in background.
	go func() {
		for req := range broker.Pending() {
			broker.Resolve(req.ID, ResponseAllowOnce)
		}
	}()

	// Should accept many requests without rate limiting.
	for i := 0; i < 20; i++ {
		_, err := broker.Request("api.example.com", 443, time.Second)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}
}
