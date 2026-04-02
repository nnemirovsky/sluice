package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/vault"
)

// TestHandleCredAdd tests adding a credential via piped stdin.
func TestHandleCredAdd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SLUICE_VAULT_DIR", dir)

	// Pipe the secret via stdin (non-terminal path).
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("my-secret-value\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"add", "test_key"})

	outW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, `credential "test_key" added`) {
		t.Errorf("unexpected output: %s", output)
	}

	// Verify credential was stored and can be retrieved.
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sb, err := store.Get("test_key")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()
	if sb.String() != "my-secret-value" {
		t.Errorf("got %q, want %q", sb.String(), "my-secret-value")
	}
}

// TestHandleCredList tests listing credentials.
func TestHandleCredList(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SLUICE_VAULT_DIR", dir)

	// Pre-populate some credentials.
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if err := store.Add(name, "secret-"+name); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"list"})

	outW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(output, name) {
			t.Errorf("expected %q in output, got: %s", name, output)
		}
	}
}

// TestHandleCredRemove tests removing a credential.
func TestHandleCredRemove(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SLUICE_VAULT_DIR", dir)

	// Pre-populate a credential.
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("to_remove", "secret"); err != nil {
		t.Fatal(err)
	}

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"remove", "to_remove"})

	outW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, `credential "to_remove" removed`) {
		t.Errorf("unexpected output: %s", output)
	}

	// Verify credential was removed.
	names, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "to_remove" {
			t.Error("credential should have been removed")
		}
	}
}

// TestHandleCredListEmpty tests listing when no credentials exist.
func TestHandleCredListEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SLUICE_VAULT_DIR", dir)

	// Initialize the vault so the credentials dir exists.
	_, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"list"})

	outW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := strings.TrimSpace(buf.String())
	if output != "" {
		t.Errorf("expected empty output for empty vault, got: %q", output)
	}
}

// TestHandleCredNoArgs verifies exit 1 when no subcommand is given.
func TestHandleCredNoArgs(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "no_args" {
		handleCredCommand([]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredNoArgs")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=no_args")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // expected non-zero exit
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredAddNoName verifies exit 1 when add is called without a name.
func TestHandleCredAddNoName(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "add_no_name" {
		handleCredCommand([]string{"add"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredAddNoName")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=add_no_name")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredRemoveNoName verifies exit 1 when remove is called without a name.
func TestHandleCredRemoveNoName(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "remove_no_name" {
		handleCredCommand([]string{"remove"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredRemoveNoName")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=remove_no_name")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredUnknownSubcommand verifies exit 1 for unknown subcommand.
func TestHandleCredUnknownSubcommand(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "unknown" {
		handleCredCommand([]string{"bogus"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredUnknownSubcommand")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=unknown")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredRemoveNonexistent verifies exit 1 when removing a credential that does not exist.
func TestHandleCredRemoveNonexistent(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "remove_nonexistent" {
		dir := os.Getenv("TEST_VAULT_DIR")
		os.Setenv("SLUICE_VAULT_DIR", dir)
		handleCredCommand([]string{"remove", "does_not_exist"})
		return
	}
	dir := t.TempDir()
	// Initialize vault so credentials dir exists.
	if _, err := vault.NewStore(dir); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredRemoveNonexistent")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=remove_nonexistent", "TEST_VAULT_DIR="+dir)
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
}
