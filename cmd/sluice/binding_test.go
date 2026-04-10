package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

// setupBindingDB creates a temporary SQLite DB for binding CLI tests.
func setupBindingDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create test DB: %v", err)
	}
	_ = db.Close()
	return dbPath
}

// TestHandleBindingCommandDispatch verifies the top-level dispatcher.
func TestHandleBindingCommandDispatch(t *testing.T) {
	if err := handleBindingCommand(nil); err == nil {
		t.Error("expected usage error for empty args")
	}
	if err := handleBindingCommand([]string{"bogus"}); err == nil {
		t.Error("expected error for unknown subcommand")
	}
}

// TestHandleBindingAdd tests adding a binding via the CLI.
func TestHandleBindingAdd(t *testing.T) {
	dbPath := setupBindingDB(t)

	output := captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.example.com",
			"--ports", "443",
			"--header", "Authorization",
			"--template", "Bearer {value}",
			"mycred",
		}); err != nil {
			t.Fatalf("binding add: %v", err)
		}
	})

	if !strings.Contains(output, "added allow rule") {
		t.Errorf("expected allow rule message, got: %s", output)
	}
	if !strings.Contains(output, "added binding") {
		t.Errorf("expected binding message, got: %s", output)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Verify rule was created with expected source tag.
	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.example.com" {
		t.Errorf("rule destination = %q, want %q", rules[0].Destination, "api.example.com")
	}
	if rules[0].Source != bindingAddSourcePrefix+"mycred" {
		t.Errorf("rule source = %q, want %q", rules[0].Source, bindingAddSourcePrefix+"mycred")
	}
	if len(rules[0].Ports) != 1 || rules[0].Ports[0] != 443 {
		t.Errorf("rule ports = %v, want [443]", rules[0].Ports)
	}

	// Verify binding.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.Destination != "api.example.com" {
		t.Errorf("binding destination = %q, want %q", b.Destination, "api.example.com")
	}
	if b.Credential != "mycred" {
		t.Errorf("binding credential = %q, want %q", b.Credential, "mycred")
	}
	if b.Header != "Authorization" {
		t.Errorf("binding header = %q, want %q", b.Header, "Authorization")
	}
	if b.Template != "Bearer {value}" {
		t.Errorf("binding template = %q, want %q", b.Template, "Bearer {value}")
	}
}

// TestHandleBindingAddMissingCredential verifies the usage error when no
// positional credential name is given.
func TestHandleBindingAddMissingCredential(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.example.com",
	})
	if err == nil {
		t.Fatal("expected error when credential name missing")
	}
	if !strings.Contains(err.Error(), "usage") {
		t.Errorf("expected usage error, got: %v", err)
	}
}

// TestHandleBindingAddMissingDestination verifies the error when no
// --destination flag is given.
func TestHandleBindingAddMissingDestination(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"add",
		"--db", dbPath,
		"mycred",
	})
	if err == nil {
		t.Fatal("expected error when destination missing")
	}
	if !strings.Contains(err.Error(), "destination") {
		t.Errorf("expected destination error, got: %v", err)
	}
}

// TestHandleBindingAddInvalidPort verifies invalid port rejection.
func TestHandleBindingAddInvalidPort(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.example.com",
		"--ports", "99999",
		"mycred",
	})
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

// TestHandleBindingAddNameBeforeFlags verifies that the credential name can
// appear before the flags thanks to reorderFlagsBeforePositional.
func TestHandleBindingAddNameBeforeFlags(t *testing.T) {
	dbPath := setupBindingDB(t)

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"add",
			"mycred", // positional first
			"--db", dbPath,
			"--destination", "api.example.com",
			"--header", "X-API-Key",
		}); err != nil {
			t.Fatalf("binding add: %v", err)
		}
	})

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Header != "X-API-Key" {
		t.Errorf("expected header X-API-Key, got %q", bindings[0].Header)
	}
}

// TestHandleBindingList tests listing bindings.
func TestHandleBindingList(t *testing.T) {
	dbPath := setupBindingDB(t)

	// Empty list prints "no bindings found" but does not error.
	output := captureStdout(t, func() {
		if err := handleBindingCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("list empty: %v", err)
		}
	})
	if !strings.Contains(output, "no bindings found") {
		t.Errorf("expected no bindings message, got: %s", output)
	}

	// Add a couple via the store directly.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.a.com", "cred_a", store.BindingOpts{
		Ports: []int{443}, Header: "Authorization",
	}); err != nil {
		t.Fatalf("add binding 1: %v", err)
	}
	if _, err := db.AddBinding("api.b.com", "cred_b", store.BindingOpts{
		Ports: []int{8080}, Template: "Bearer {value}",
	}); err != nil {
		t.Fatalf("add binding 2: %v", err)
	}
	_ = db.Close()

	// List all.
	output = captureStdout(t, func() {
		if err := handleBindingCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(output, "api.a.com") || !strings.Contains(output, "cred_a") {
		t.Errorf("list output missing first binding: %s", output)
	}
	if !strings.Contains(output, "api.b.com") || !strings.Contains(output, "cred_b") {
		t.Errorf("list output missing second binding: %s", output)
	}
	if !strings.Contains(output, "header=Authorization") {
		t.Errorf("list output missing header: %s", output)
	}
	if !strings.Contains(output, "template=Bearer {value}") {
		t.Errorf("list output missing template: %s", output)
	}
	if !strings.Contains(output, "ports=443") {
		t.Errorf("list output missing ports=443: %s", output)
	}
	if !strings.Contains(output, "ports=8080") {
		t.Errorf("list output missing ports=8080: %s", output)
	}
}

// TestHandleBindingListFiltered tests filtering bindings by credential.
func TestHandleBindingListFiltered(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.a.com", "cred_a", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.b.com", "cred_b", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("other.b.com", "cred_b", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"list", "--db", dbPath, "--credential", "cred_b",
		}); err != nil {
			t.Fatalf("filtered list: %v", err)
		}
	})

	if strings.Contains(output, "cred_a") {
		t.Errorf("filtered list should not include cred_a: %s", output)
	}
	if !strings.Contains(output, "api.b.com") || !strings.Contains(output, "other.b.com") {
		t.Errorf("filtered list missing cred_b bindings: %s", output)
	}
}

// TestHandleBindingUpdateSingleField tests updating a single field.
func TestHandleBindingUpdateSingleField(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{
		Ports:  []int{443},
		Header: "Authorization",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Update only the header.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--header", "X-API-Key",
			"1",
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
	})

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.ID != id {
		t.Errorf("binding id changed: got %d, want %d", b.ID, id)
	}
	if b.Header != "X-API-Key" {
		t.Errorf("header = %q, want %q", b.Header, "X-API-Key")
	}
	// Unchanged fields should remain.
	if b.Destination != "api.example.com" {
		t.Errorf("destination changed unexpectedly: %q", b.Destination)
	}
	if len(b.Ports) != 1 || b.Ports[0] != 443 {
		t.Errorf("ports changed unexpectedly: %v", b.Ports)
	}
}

// TestHandleBindingUpdateMultipleFields tests updating multiple fields.
func TestHandleBindingUpdateMultipleFields(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{
		Ports: []int{443},
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--destination", "other.example.com",
			"--ports", "8080,9090",
			"--header", "Authorization",
			"--template", "Bearer {value}",
			"1",
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
	})

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.Destination != "other.example.com" {
		t.Errorf("destination = %q, want %q", b.Destination, "other.example.com")
	}
	if len(b.Ports) != 2 || b.Ports[0] != 8080 || b.Ports[1] != 9090 {
		t.Errorf("ports = %v, want [8080 9090]", b.Ports)
	}
	if b.Header != "Authorization" {
		t.Errorf("header = %q, want Authorization", b.Header)
	}
	if b.Template != "Bearer {value}" {
		t.Errorf("template = %q, want Bearer {value}", b.Template)
	}
}

// TestHandleBindingUpdateClearField tests that passing an empty string clears
// a field.
func TestHandleBindingUpdateClearField(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{
		Header: "Authorization",
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--header", "",
			"1",
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
	})

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if bindings[0].Header != "" {
		t.Errorf("header should be cleared, got %q", bindings[0].Header)
	}
}

// TestHandleBindingUpdateNotFound verifies error on unknown ID.
func TestHandleBindingUpdateNotFound(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"update",
		"--db", dbPath,
		"--header", "X-API-Key",
		"999",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent binding")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// TestHandleBindingUpdateNoFields verifies that an update with no fields
// returns a helpful error.
func TestHandleBindingUpdateNoFields(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	err = handleBindingCommand([]string{
		"update",
		"--db", dbPath,
		"1",
	})
	if err == nil {
		t.Fatal("expected error when no fields provided")
	}
	if !strings.Contains(err.Error(), "no fields to update") {
		t.Errorf("expected no-fields error, got: %v", err)
	}
}

// TestHandleBindingUpdateInvalidID verifies error when ID is not a number.
func TestHandleBindingUpdateInvalidID(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"update",
		"--db", dbPath,
		"--header", "X-API-Key",
		"abc",
	})
	if err == nil {
		t.Fatal("expected error for non-numeric ID")
	}
}

// TestHandleBindingRemove tests removing a binding.
func TestHandleBindingRemove(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"remove", "--db", dbPath, "1",
		}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after remove, got %d", len(bindings))
	}
}

// TestHandleBindingRemoveNotFound verifies the not-found error.
func TestHandleBindingRemoveNotFound(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"remove", "--db", dbPath, "999",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent binding")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// TestHandleBindingRemoveInvalidID verifies error on non-numeric ID.
func TestHandleBindingRemoveInvalidID(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{
		"remove", "--db", dbPath, "notanumber",
	})
	if err == nil {
		t.Fatal("expected error for non-numeric ID")
	}
}

// TestHandleBindingRemoveMissingArg verifies usage error when no ID given.
func TestHandleBindingRemoveMissingArg(t *testing.T) {
	dbPath := setupBindingDB(t)

	err := handleBindingCommand([]string{"remove", "--db", dbPath})
	if err == nil {
		t.Fatal("expected usage error")
	}
}
