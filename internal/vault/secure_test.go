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

func TestSecureBytesReUseAfterRelease(t *testing.T) {
	s := NewSecureBytes("sensitive-data")
	s.Release()

	// After release, String should return zeroed bytes (all nulls).
	str := s.String()
	for _, c := range str {
		if c != 0 {
			t.Fatalf("String() after Release should return zeroed data, got %q", str)
		}
	}

	// Len should still return the original length (the slice is zeroed, not truncated).
	if s.Len() != 14 {
		t.Errorf("Len() after Release = %d, want 14", s.Len())
	}

	// Bytes should return zeroed slice.
	for i, b := range s.Bytes() {
		if b != 0 {
			t.Fatalf("Bytes()[%d] = %d after Release, want 0", i, b)
		}
	}

	// IsReleased should be true.
	if !s.IsReleased() {
		t.Error("IsReleased should return true after Release")
	}
}

func TestSecureBytesValuePreservedBeforeRelease(t *testing.T) {
	s := NewSecureBytes("keep-this")
	defer s.Release()

	if s.String() != "keep-this" {
		t.Errorf("String() = %q, want 'keep-this'", s.String())
	}
	if s.Len() != 9 {
		t.Errorf("Len() = %d, want 9", s.Len())
	}
	if s.IsReleased() {
		t.Error("IsReleased should be false before Release")
	}
	if len(s.Bytes()) != 9 {
		t.Errorf("Bytes() len = %d, want 9", len(s.Bytes()))
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
