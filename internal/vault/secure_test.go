package vault

import "testing"

func TestSecureBytesRelease(t *testing.T) {
	s := NewSecureBytes("super-secret-key")
	if s.String() != "super-secret-key" {
		t.Fatal("value mismatch before release")
	}
	if s.Len() != 16 {
		t.Fatalf("expected len 16, got %d", s.Len())
	}
	s.Release()
	for _, b := range s.Bytes() {
		if b != 0 {
			t.Fatal("memory not zeroed after release")
		}
	}
	if !s.IsReleased() {
		t.Fatal("IsReleased should return true after release")
	}
}

func TestSecureBytesDoubleRelease(t *testing.T) {
	s := NewSecureBytes("test-value")
	s.Release()
	s.Release() // should not panic
	if !s.IsReleased() {
		t.Fatal("expected zeroed after double release")
	}
}

func TestSecureBytesEmpty(t *testing.T) {
	s := NewSecureBytes("")
	if s.Len() != 0 {
		t.Fatalf("expected len 0, got %d", s.Len())
	}
	s.Release() // should not panic on empty
	if !s.IsReleased() {
		t.Fatal("empty SecureBytes should report as released")
	}
}
