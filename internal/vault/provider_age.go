package vault

// Store implements the Provider interface as the default age-encrypted
// file-based credential backend.
//
// The Get and List methods satisfy the Provider contract. Add and Remove
// are age-specific storage operations not part of the Provider interface
// since external providers manage their own storage.

// Name returns the provider identifier.
func (s *Store) Name() string { return "age" }
