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

	// Use O_CREATE|O_EXCL for atomic creation to prevent TOCTOU races
	// where concurrent processes could overwrite each other's key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Another process created the file first. Read their key.
			return loadOrCreateIdentity(path)
		}
		return nil, fmt.Errorf("create identity file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(id.String() + "\n"); err != nil {
		return nil, fmt.Errorf("write identity: %w", err)
	}
	return id, nil
}

func (s *Store) credPath(name string) (string, error) {
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || name == "." {
		return "", fmt.Errorf("invalid credential name %q: must not contain path separators or '..'", name)
	}
	if name == "" {
		return "", fmt.Errorf("credential name must not be empty")
	}
	return filepath.Join(s.dir, "credentials", name+".age"), nil
}

// Add encrypts and stores a credential with the given name.
func (s *Store) Add(name, value string) error {
	path, err := s.credPath(name)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipient)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if _, err := io.WriteString(w, value); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return os.WriteFile(path, buf.Bytes(), 0600)
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
