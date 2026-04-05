package vault

import "unsafe"

// SecureBytes holds a credential value and zeroes it on Release.
// Use Release() as soon as the value is no longer needed.
type SecureBytes struct {
	data     []byte
	released bool
}

// NewSecureBytes creates a SecureBytes from a string value.
func NewSecureBytes(val string) SecureBytes {
	b := make([]byte, len(val))
	copy(b, val)
	return SecureBytes{data: b}
}

// String returns the credential value as a string.
func (s *SecureBytes) String() string {
	return string(s.data)
}

// Bytes returns the underlying byte slice.
func (s *SecureBytes) Bytes() []byte {
	return s.data
}

// Len returns the length of the credential value.
func (s *SecureBytes) Len() int {
	return len(s.data)
}

// IsReleased returns true if Release has been called.
func (s *SecureBytes) IsReleased() bool {
	return s.released
}

// Release zeroes the underlying memory. Safe to call multiple times.
func (s *SecureBytes) Release() {
	s.released = true
	if len(s.data) == 0 {
		return
	}
	for i := range s.data {
		s.data[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing.
	_ = *(*byte)(unsafe.Pointer(&s.data[0]))
}
