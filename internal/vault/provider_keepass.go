package vault

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

// KeePassConfig holds configuration for the KeePass provider.
type KeePassConfig struct {
	// Path is the path to the .kdbx database file.
	Path string

	// Password is the master password. Falls back to KEEPASS_PASSWORD env var if empty.
	Password string

	// KeyFilePath is the optional path to a key file for composite key auth.
	KeyFilePath string
}

// KeePassProvider retrieves credentials from a KeePass .kdbx database file.
type KeePassProvider struct {
	dbPath      string
	password    string
	keyFilePath string

	mu      sync.Mutex
	index   map[string]string // entry title -> password
	modTime time.Time         // last known file modification time
}

// NewKeePassProvider creates a provider that reads secrets from a KeePass .kdbx file.
// password is the master password (falls back to KEEPASS_PASSWORD env var).
// keyFilePath is optional for composite key authentication.
func NewKeePassProvider(dbPath, password, keyFilePath string) (*KeePassProvider, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("keepass: database path is required")
	}
	if password == "" {
		password = os.Getenv("KEEPASS_PASSWORD")
	}
	if password == "" {
		return nil, fmt.Errorf("keepass: no password provided (set KEEPASS_PASSWORD or config password)")
	}

	p := &KeePassProvider{
		dbPath:      dbPath,
		password:    password,
		keyFilePath: keyFilePath,
	}

	// Verify the file can be opened and decrypted on creation.
	if err := p.loadDB(); err != nil {
		return nil, err
	}

	return p, nil
}

// Get retrieves a credential from KeePass by entry title.
// Re-reads the file if it has been modified since last load.
func (p *KeePassProvider) Get(name string) (SecureBytes, error) {
	if err := validateCredentialName(name); err != nil {
		return SecureBytes{}, err
	}

	if err := p.reloadIfChanged(); err != nil {
		return SecureBytes{}, err
	}

	p.mu.Lock()
	val, ok := p.index[name]
	p.mu.Unlock()

	if !ok {
		return SecureBytes{}, fmt.Errorf("keepass: entry %q not found", name)
	}

	return NewSecureBytes(val), nil
}

// List returns all entry titles in the database.
func (p *KeePassProvider) List() ([]string, error) {
	if err := p.reloadIfChanged(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	names := make([]string, 0, len(p.index))
	for title := range p.index {
		names = append(names, title)
	}
	return names, nil
}

// Name returns "keepass".
func (p *KeePassProvider) Name() string { return "keepass" }

// reloadIfChanged re-reads the .kdbx file if the modification time has changed.
func (p *KeePassProvider) reloadIfChanged() error {
	info, err := os.Stat(p.dbPath)
	if err != nil {
		return fmt.Errorf("keepass: stat %q: %w", p.dbPath, err)
	}

	p.mu.Lock()
	needsReload := info.ModTime() != p.modTime
	if !needsReload {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	return p.loadDB()
}

// loadDB opens, decrypts, and indexes the .kdbx database.
// The caller must not hold p.mu.
func (p *KeePassProvider) loadDB() error {
	f, err := os.Open(p.dbPath)
	if err != nil {
		return fmt.Errorf("keepass: open %q: %w", p.dbPath, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("keepass: stat %q: %w", p.dbPath, err)
	}

	db := gokeepasslib.NewDatabase()

	creds, err := p.buildCredentials()
	if err != nil {
		return err
	}
	db.Credentials = creds

	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return fmt.Errorf("keepass: decode %q: %w", p.dbPath, err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return fmt.Errorf("keepass: unlock entries: %w", err)
	}

	index := make(map[string]string)
	for _, group := range db.Content.Root.Groups {
		p.indexGroup(group, index)
	}

	p.mu.Lock()
	// Double-check: another goroutine may have already reloaded.
	if info.ModTime().Equal(p.modTime) {
		p.mu.Unlock()
		return nil
	}
	p.index = index
	p.modTime = info.ModTime()
	p.mu.Unlock()

	return nil
}

// indexGroup recursively indexes all entries in a group and its subgroups.
func (p *KeePassProvider) indexGroup(group gokeepasslib.Group, index map[string]string) {
	for _, entry := range group.Entries {
		title := getEntryValue(entry, "Title")
		password := getEntryValue(entry, "Password")
		if title != "" {
			// First entry with a given title wins (don't overwrite).
			if _, exists := index[title]; !exists {
				index[title] = password
			}
		}
	}
	for _, sub := range group.Groups {
		p.indexGroup(sub, index)
	}
}

// getEntryValue extracts a value from a KeePass entry's value list by key.
func getEntryValue(entry gokeepasslib.Entry, key string) string {
	for _, v := range entry.Values {
		if v.Key == key {
			return v.Value.Content
		}
	}
	return ""
}

// buildCredentials creates the appropriate gokeepasslib credentials.
func (p *KeePassProvider) buildCredentials() (*gokeepasslib.DBCredentials, error) {
	if p.keyFilePath != "" {
		creds, err := gokeepasslib.NewPasswordAndKeyCredentials(p.password, p.keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("keepass: create composite credentials: %w", err)
		}
		return creds, nil
	}
	return gokeepasslib.NewPasswordCredentials(p.password), nil
}
