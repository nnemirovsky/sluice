// Package vault manages age-encrypted credential storage with pluggable
// provider backends. It supports age file encryption, environment variables,
// and HashiCorp Vault as credential sources.
package vault

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// Store manages age-encrypted credentials on disk.
type Store struct {
	dir       string
	identity  *age.X25519Identity
	recipient age.Recipient
}

// NewStore opens or initializes a credential store at the given directory.
// An X25519 identity key is generated on first use and stored as vault-key.txt.
func NewStore(dir string) (*Store, error) {
	credsDir := filepath.Join(dir, "credentials")
	if err := os.MkdirAll(credsDir, 0700); err != nil {
		return nil, fmt.Errorf("create credentials dir: %w", err)
	}

	keyPath := filepath.Join(dir, "vault-key.txt")
	identity, err := loadOrCreateIdentity(keyPath)
	if err != nil {
		return nil, err
	}

	return &Store{
		dir:       dir,
		identity:  identity,
		recipient: identity.Recipient(),
	}, nil
}

func loadOrCreateIdentity(path string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		id, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("parse identity: %w", err)
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}

	// Write to a temporary file then hard-link to the final path for
	// atomic visibility. Concurrent processes see either the old state
	// (file not found) or the complete file, never a partial write.
	// os.CreateTemp guarantees a unique name even for concurrent
	// goroutines within the same process.
	tmpFile, tmpErr := os.CreateTemp(filepath.Dir(path), ".vault-key-*.tmp")
	if tmpErr != nil {
		return nil, fmt.Errorf("create identity temp: %w", tmpErr)
	}
	tmpPath := tmpFile.Name()
	if _, writeErr := tmpFile.WriteString(id.String() + "\n"); writeErr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("write identity temp: %w", writeErr)
	}
	if writeErr := tmpFile.Close(); writeErr != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("close identity temp: %w", writeErr)
	}
	if chmodErr := os.Chmod(tmpPath, 0600); chmodErr != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("chmod identity temp: %w", chmodErr)
	}

	// os.Link fails with EEXIST if path already exists (another process
	// won the race). The winner's file is fully written before being
	// linked, so the loser can safely read it.
	if linkErr := os.Link(tmpPath, path); linkErr != nil {
		os.Remove(tmpPath)
		if os.IsExist(linkErr) {
			// Another process created the file first. Read their key.
			return loadOrCreateIdentity(path)
		}
		return nil, fmt.Errorf("create identity file: %w", linkErr)
	}
	os.Remove(tmpPath)
	return id, nil
}

func (s *Store) credPath(name string) (string, error) {
	if err := validateCredentialName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, "credentials", name+".age"), nil
}

// Add encrypts and stores a credential with the given name.
// Uses temp file + atomic rename so a concurrent Get never sees a
// partial or truncated ciphertext file. Returns the raw ciphertext
// bytes that were written, so callers needing compare-and-swap
// semantics can use them without a re-read (which would be racy).
func (s *Store) Add(name, value string) ([]byte, error) {
	path, err := s.credPath(name)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if _, err := io.WriteString(w, value); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close: %w", err)
	}

	ciphertext := make([]byte, buf.Len())
	copy(ciphertext, buf.Bytes())

	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".cred-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("write temp: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("rename temp: %w", err)
	}
	return ciphertext, nil
}

// Get decrypts and returns the credential with the given name.
// The caller must call Release() on the returned SecureBytes when done.
func (s *Store) Get(name string) (SecureBytes, error) {
	path, err := s.credPath(name)
	if err != nil {
		return SecureBytes{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("read credential %q: %w", name, err)
	}
	r, err := age.Decrypt(bytes.NewReader(data), s.identity)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("decrypt %q: %w", name, err)
	}
	val, err := io.ReadAll(r)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("read decrypted %q: %w", name, err)
	}
	// Wrap in SecureBytes so caller can zero memory after use.
	sb := SecureBytes{data: val}
	return sb, nil
}

// List returns the names of all stored credentials.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "credentials"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".age") {
			names = append(names, strings.TrimSuffix(e.Name(), ".age"))
		}
	}
	return names, nil
}

// Remove deletes a stored credential by name.
func (s *Store) Remove(name string) error {
	path, err := s.credPath(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// ReadRawCredential returns the raw (encrypted) bytes for the named credential.
// Returns nil, nil if the credential does not exist.
func (s *Store) ReadRawCredential(name string) ([]byte, error) {
	path, err := s.credPath(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read raw credential %q: %w", name, err)
	}
	return data, nil
}

// WriteRawCredential writes raw (already encrypted) bytes as the named credential,
// using the same temp file + atomic rename pattern as Add.
func (s *Store) WriteRawCredential(name string, data []byte) error {
	path, err := s.credPath(name)
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".cred-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}
