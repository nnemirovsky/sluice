package telegram

import (
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
