package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

// bindingAddSourcePrefix and credAddSourcePrefix are test-only aliases for
// the store constants. They keep test assertions readable when comparing
// rule source tags. Production code uses store.BindingAddSourcePrefix and
// store.CredAddSourcePrefix directly.
const (
	bindingAddSourcePrefix = store.BindingAddSourcePrefix
	credAddSourcePrefix    = store.CredAddSourcePrefix
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

// TestHandleBindingAddWithEnvVar verifies that --env-var is stored on the
// new binding when add is invoked.
func TestHandleBindingAddWithEnvVar(t *testing.T) {
	dbPath := setupBindingDB(t)

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.example.com",
			"--env-var", "MY_API_KEY",
			"mycred",
		}); err != nil {
			t.Fatalf("binding add --env-var: %v", err)
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
	if bindings[0].EnvVar != "MY_API_KEY" {
		t.Errorf("env_var = %q, want %q", bindings[0].EnvVar, "MY_API_KEY")
	}
}

// TestHandleBindingAddRejectsDuplicate verifies that calling binding add
// twice with the same credential and destination returns a clear error
// instead of silently creating two rows.
func TestHandleBindingAddRejectsDuplicate(t *testing.T) {
	dbPath := setupBindingDB(t)

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.example.com",
			"mycred",
		}); err != nil {
			t.Fatalf("first add: %v", err)
		}
	})

	err := handleBindingCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.example.com",
		"mycred",
	})
	if err == nil {
		t.Fatal("expected error for duplicate binding")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected already-exists error, got: %v", err)
	}

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
		t.Errorf("expected 1 binding after duplicate reject, got %d", len(bindings))
	}
	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 allow rule after duplicate reject, got %d", len(rules))
	}
}

// TestHandleBindingUpdateClearPorts verifies that passing --ports "" clears
// the ports list on an existing binding.
func TestHandleBindingUpdateClearPorts(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{
		Ports: []int{443, 8080},
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--ports", "",
			"1",
		}); err != nil {
			t.Fatalf("update clear ports: %v", err)
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
	if len(bindings[0].Ports) != 0 {
		t.Errorf("ports should be cleared, got %v", bindings[0].Ports)
	}
}

// TestHandleBindingUpdateProtocols verifies the --protocols flag on update.
func TestHandleBindingUpdateProtocols(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{
		Protocols: []string{"https"},
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--protocols", "http,grpc",
			"1",
		}); err != nil {
			t.Fatalf("update protocols: %v", err)
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
	if len(bindings[0].Protocols) != 2 || bindings[0].Protocols[0] != "http" || bindings[0].Protocols[1] != "grpc" {
		t.Errorf("protocols = %v, want [http grpc]", bindings[0].Protocols)
	}

	// Clear protocols with empty string.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--protocols", "",
			"1",
		}); err != nil {
			t.Fatalf("update clear protocols: %v", err)
		}
	})

	bindings, _ = db.ListBindings()
	if len(bindings[0].Protocols) != 0 {
		t.Errorf("protocols should be cleared, got %v", bindings[0].Protocols)
	}
}

// TestHandleBindingUpdateEnvVar verifies that --env-var can be set, changed,
// and cleared via binding update.
func TestHandleBindingUpdateEnvVar(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.example.com", "mycred", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Set env_var.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--env-var", "MY_KEY",
			"1",
		}); err != nil {
			t.Fatalf("set env-var: %v", err)
		}
	})

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	bindings, _ := db.ListBindings()
	if bindings[0].EnvVar != "MY_KEY" {
		t.Errorf("env_var = %q, want MY_KEY", bindings[0].EnvVar)
	}

	// Change env_var.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--env-var", "OTHER_KEY",
			"1",
		}); err != nil {
			t.Fatalf("change env-var: %v", err)
		}
	})

	bindings, _ = db.ListBindings()
	if bindings[0].EnvVar != "OTHER_KEY" {
		t.Errorf("env_var = %q, want OTHER_KEY", bindings[0].EnvVar)
	}

	// Clear env_var with empty string.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--env-var", "",
			"1",
		}); err != nil {
			t.Fatalf("clear env-var: %v", err)
		}
	})

	bindings, _ = db.ListBindings()
	if bindings[0].EnvVar != "" {
		t.Errorf("env_var should be cleared, got %q", bindings[0].EnvVar)
	}
}

// TestHandleBindingUpdateDestinationSyncsRule verifies that updating a
// binding's destination also updates the paired auto-created allow rule.
// Without this sync, the new destination would be orphaned (no allow rule)
// and the old rule would linger with no binding pointing at it.
func TestHandleBindingUpdateDestinationSyncsRule(t *testing.T) {
	dbPath := setupBindingDB(t)

	// Create a binding via the CLI so the paired rule is tagged with
	// bindingAddSourcePrefix (same as production code path).
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.old.com",
			"--ports", "443",
			"mycred",
		}); err != nil {
			t.Fatalf("binding add: %v", err)
		}
	})

	// Update the destination.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--destination", "api.new.com",
			"1",
		}); err != nil {
			t.Fatalf("binding update --destination: %v", err)
		}
	})

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Binding should point at the new destination.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Destination != "api.new.com" {
		t.Errorf("binding destination = %q, want api.new.com", bindings[0].Destination)
	}

	// Exactly one allow rule should exist, and it should point at the new
	// destination. The old destination rule must be gone.
	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule after destination sync, got %d", len(rules))
	}
	if rules[0].Destination != "api.new.com" {
		t.Errorf("rule destination = %q, want api.new.com", rules[0].Destination)
	}
	if rules[0].Source != bindingAddSourcePrefix+"mycred" {
		t.Errorf("rule source = %q, want %q", rules[0].Source, bindingAddSourcePrefix+"mycred")
	}
}

// TestHandleBindingRemoveCleansUpPairedRule verifies that removing a binding
// also removes the paired auto-created allow rule so the destination is not
// left open after its binding is gone.
func TestHandleBindingRemoveCleansUpPairedRule(t *testing.T) {
	dbPath := setupBindingDB(t)

	// Create the binding via the CLI so the paired rule is tagged with
	// bindingAddSourcePrefix (matching the production path).
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.example.com",
			"--ports", "443",
			"mycred",
		}); err != nil {
			t.Fatalf("binding add: %v", err)
		}
	})

	// Sanity check: rule was created.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule before remove, got %d", len(rules))
	}
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	id := bindings[0].ID
	_ = db.Close()

	// Remove the binding.
	_ = captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"remove", "--db", dbPath, strconv.FormatInt(id, 10),
		}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Paired allow rule should also be gone.
	rules, err = db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 allow rules after remove, got %d", len(rules))
	}
}

// TestHandleBindingUpdateDuplicateDestinationRejected verifies that updating
// a binding's destination to one already used by another binding of the same
// credential is rejected. This prevents the update path from creating a
// duplicate that binding add would reject.
func TestHandleBindingUpdateDuplicateDestinationRejected(t *testing.T) {
	dbPath := setupBindingDB(t)

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBinding("api.a.com", "mycred", store.BindingOpts{}); err != nil {
		t.Fatal(err)
	}
	id, err := db.AddBinding("api.b.com", "mycred", store.BindingOpts{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Attempt to update the second binding to collide with the first.
	err = handleBindingCommand([]string{
		"update",
		"--db", dbPath,
		"--destination", "api.a.com",
		strconv.FormatInt(id, 10),
	})
	if err == nil {
		t.Fatal("expected error for duplicate destination on update")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected already-exists error, got: %v", err)
	}

	// Both bindings should still exist with their original destinations.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
}

// TestHandleBindingUpdateDestinationWarnsWithoutPairedRule verifies that if
// the paired allow rule was removed manually, updating the binding
// destination still succeeds but prints a warning and does NOT create a
// new fallback rule. Silently recreating the rule would mask an operator's
// deliberate decision to remove it.
func TestHandleBindingUpdateDestinationWarnsWithoutPairedRule(t *testing.T) {
	dbPath := setupBindingDB(t)

	// Create a binding directly through the store, without a paired rule.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.AddBinding("api.old.com", "mycred", store.BindingOpts{
		Ports: []int{443},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleBindingCommand([]string{
			"update",
			"--db", dbPath,
			"--destination", "api.new.com",
			strconv.FormatInt(id, 10),
		}); err != nil {
			t.Fatalf("binding update: %v", err)
		}
	})

	if !strings.Contains(output, "warning: no paired allow rule found") {
		t.Errorf("expected warning about missing paired rule, got: %s", output)
	}

	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Binding destination still updates.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Destination != "api.new.com" {
		t.Errorf("expected binding destination api.new.com, got %v", bindings)
	}

	// No fallback rule was created.
	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules (no fallback), got %d", len(rules))
	}
}
