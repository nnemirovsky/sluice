package vault

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// createTestKDBX creates a .kdbx file in the given directory with the specified entries.
// Each entry is a title->password pair. Returns the file path.
func createTestKDBX(t *testing.T, dir, password string, entries map[string]string) string {
	t.Helper()

	dbPath := filepath.Join(dir, "test.kdbx")
	return createTestKDBXAt(t, dbPath, password, entries, nil)
}

// createTestKDBXWithGroups creates a .kdbx file with entries in nested groups.
func createTestKDBXWithGroups(t *testing.T, dir, password string, rootEntries map[string]string, subGroups map[string]map[string]string) string {
	t.Helper()

	dbPath := filepath.Join(dir, "test.kdbx")
	return createTestKDBXAt(t, dbPath, password, rootEntries, subGroups)
}

// createTestKDBXAt creates a .kdbx file at the specified path.
func createTestKDBXAt(t *testing.T, dbPath, password string, entries map[string]string, subGroups map[string]map[string]string) string {
	t.Helper()

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	for title, pw := range entries {
		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values,
			mkValue("Title", title),
			mkProtectedValue("Password", pw),
		)
		rootGroup.Entries = append(rootGroup.Entries, entry)
	}

	for groupName, groupEntries := range subGroups {
		sub := gokeepasslib.NewGroup()
		sub.Name = groupName
		for title, pw := range groupEntries {
			entry := gokeepasslib.NewEntry()
			entry.Values = append(entry.Values,
				mkValue("Title", title),
				mkProtectedValue("Password", pw),
			)
			sub.Entries = append(sub.Entries, entry)
		}
		rootGroup.Groups = append(rootGroup.Groups, sub)
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("lock entries: %v", err)
	}

	f, err := os.Create(dbPath)
	if err != nil {
		t.Fatalf("create kdbx file: %v", err)
	}
	defer f.Close()

	enc := gokeepasslib.NewEncoder(f)
	if err := enc.Encode(db); err != nil {
		t.Fatalf("encode kdbx: %v", err)
	}

	return dbPath
}

func mkValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: w.NewBoolWrapper(true)},
	}
}

func TestKeePassProviderGet(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"anthropic_api_key": "sk-ant-real-123",
		"openai_key":        "sk-openai-456",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	if p.Name() != "keepass" {
		t.Errorf("Name() = %q, want \"keepass\"", p.Name())
	}

	sb, err := p.Get("anthropic_api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "sk-ant-real-123" {
		t.Errorf("Get value = %q, want \"sk-ant-real-123\"", sb.String())
	}

	sb2, err := p.Get("openai_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "sk-openai-456" {
		t.Errorf("Get value = %q, want \"sk-openai-456\"", sb2.String())
	}
}

func TestKeePassProviderGetNotFound(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"existing": "val",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	_, err = p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain \"not found\"", err.Error())
	}
}

func TestKeePassProviderWrongPassword(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "correctpass", map[string]string{
		"key1": "val1",
	})

	_, err := NewKeePassProvider(dbPath, "wrongpass", "")
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestKeePassProviderMissingFile(t *testing.T) {
	_, err := NewKeePassProvider("/nonexistent/path/test.kdbx", "pass", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestKeePassProviderNoPassword(t *testing.T) {
	t.Setenv("KEEPASS_PASSWORD", "")

	_, err := NewKeePassProvider("/some/path.kdbx", "", "")
	if err == nil {
		t.Fatal("expected error when no password provided")
	}
	if !strings.Contains(err.Error(), "no password") {
		t.Errorf("error = %q, want it to contain \"no password\"", err.Error())
	}
}

func TestKeePassProviderNoDBPath(t *testing.T) {
	_, err := NewKeePassProvider("", "pass", "")
	if err == nil {
		t.Fatal("expected error when no db path provided")
	}
	if !strings.Contains(err.Error(), "database path is required") {
		t.Errorf("error = %q, want it to contain \"database path is required\"", err.Error())
	}
}

func TestKeePassProviderEnvPassword(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "envpass", map[string]string{
		"key1": "val1",
	})

	t.Setenv("KEEPASS_PASSWORD", "envpass")

	p, err := NewKeePassProvider(dbPath, "", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	sb, err := p.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "val1" {
		t.Errorf("Get value = %q, want \"val1\"", sb.String())
	}
}

func TestKeePassProviderList(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"anthropic_api_key": "val1",
		"openai_key":        "val2",
		"github_token":      "val3",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("List returned %d names, want 3", len(names))
	}

	sort.Strings(names)
	expected := []string{"anthropic_api_key", "github_token", "openai_key"}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("names[%d] = %q, want %q", i, names[i], want)
		}
	}
}

func TestKeePassProviderListEmpty(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("List returned %d names, want 0", len(names))
	}
}

func TestKeePassProviderSubGroups(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBXWithGroups(t, dir, "testpass",
		map[string]string{"root_key": "root_val"},
		map[string]map[string]string{
			"APIs": {"api_key": "api_val"},
			"SSH":  {"ssh_key": "ssh_val"},
		},
	)

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	// Should find entries in all groups.
	for _, tc := range []struct {
		name string
		want string
	}{
		{"root_key", "root_val"},
		{"api_key", "api_val"},
		{"ssh_key", "ssh_val"},
	} {
		sb, err := p.Get(tc.name)
		if err != nil {
			t.Errorf("Get(%q): %v", tc.name, err)
			continue
		}
		if sb.String() != tc.want {
			t.Errorf("Get(%q) = %q, want %q", tc.name, sb.String(), tc.want)
		}
		sb.Release()
	}

	names, err := p.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 3 {
		t.Errorf("List returned %d names, want 3", len(names))
	}
}

func TestKeePassProviderReloadOnModification(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"key1": "val1",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	sb, err := p.Get("key1")
	if err != nil {
		t.Fatalf("Get key1: %v", err)
	}
	if sb.String() != "val1" {
		t.Errorf("initial Get = %q, want \"val1\"", sb.String())
	}
	sb.Release()

	// key2 should not exist yet.
	_, err = p.Get("key2")
	if err == nil {
		t.Fatal("expected error for key2 before modification")
	}

	// Rewrite the database with a new entry.
	createTestKDBXAt(t, dbPath, "testpass", map[string]string{
		"key1": "val1_updated",
		"key2": "val2",
	}, nil)

	// After modification, Get should reload and find the new entry.
	sb2, err := p.Get("key2")
	if err != nil {
		t.Fatalf("Get key2 after modification: %v", err)
	}
	defer sb2.Release()
	if sb2.String() != "val2" {
		t.Errorf("Get key2 = %q, want \"val2\"", sb2.String())
	}

	// Updated value should also be visible.
	sb3, err := p.Get("key1")
	if err != nil {
		t.Fatalf("Get key1 after modification: %v", err)
	}
	defer sb3.Release()
	if sb3.String() != "val1_updated" {
		t.Errorf("Get key1 = %q, want \"val1_updated\"", sb3.String())
	}
}

func TestKeePassProviderPathTraversal(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"key1": "val1",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	for _, name := range []string{"../../etc/passwd", "../secret", "foo/bar", "foo\\bar", "..", "."} {
		_, err := p.Get(name)
		if err == nil {
			t.Errorf("Get(%q) should have returned an error for path traversal", name)
		}
	}
}

func TestKeePassProviderInterfaceCompliance(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"test": "val",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	var provider Provider = p
	sb, err := provider.Get("test")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()
	if sb.String() != "val" {
		t.Errorf("via Provider interface: got %q, want \"val\"", sb.String())
	}
}

func TestKeePassProviderSecureBytesRelease(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"key": "sensitive-value",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	sb, err := p.Get("key")
	if err != nil {
		t.Fatal(err)
	}
	if sb.String() != "sensitive-value" {
		t.Errorf("before release: got %q", sb.String())
	}

	sb.Release()
	if !sb.IsReleased() {
		t.Error("expected IsReleased() to be true after Release()")
	}
}

func TestKeePassProviderDuplicateTitles(t *testing.T) {
	// When entries share the same title, first one wins.
	dir := t.TempDir()

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Add two entries with the same title.
	for _, pw := range []string{"first-value", "second-value"} {
		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values,
			mkValue("Title", "dup_key"),
			mkProtectedValue("Password", pw),
		)
		rootGroup.Entries = append(rootGroup.Entries, entry)
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("lock: %v", err)
	}

	dbPath := filepath.Join(dir, "dup.kdbx")
	f, err := os.Create(dbPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatalf("encode: %v", err)
	}
	f.Close()

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	sb, err := p.Get("dup_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer sb.Release()
	if sb.String() != "first-value" {
		t.Errorf("Get value = %q, want \"first-value\" (first match)", sb.String())
	}
}

func TestKeePassProviderEmptyName(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestKDBX(t, dir, "testpass", map[string]string{
		"key1": "val1",
	})

	p, err := NewKeePassProvider(dbPath, "testpass", "")
	if err != nil {
		t.Fatalf("NewKeePassProvider: %v", err)
	}

	_, err = p.Get("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}
