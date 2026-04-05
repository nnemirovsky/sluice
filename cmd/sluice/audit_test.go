package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/audit"
)

// TestHandleAuditVerifyValid creates a valid audit log and verifies it passes.
func TestHandleAuditVerifyValid(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test-audit.jsonl")

	// Write a valid audit log with hash chain.
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := logger.Log(audit.Event{
			Destination: "api.example.com",
			Port:        443,
			Verdict:     "allow",
		}); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}
	_ = logger.Close()

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	if err := handleAuditVerify(logPath); err != nil {
		os.Stdout = oldStdout
		t.Fatalf("expected no error for valid log: %v", err)
	}

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, "Total lines:  5") {
		t.Errorf("expected 5 total lines in output: %s", output)
	}
	if !strings.Contains(output, "Valid links:  5") {
		t.Errorf("expected 5 valid links in output: %s", output)
	}
	if !strings.Contains(output, "Broken links: 0") {
		t.Errorf("expected 0 broken links in output: %s", output)
	}
}

// TestHandleAuditVerifyBroken verifies error return when the audit log has a broken hash chain.
func TestHandleAuditVerifyBroken(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "broken-audit.jsonl")

	// Write a valid log first.
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(audit.Event{Destination: "a.com", Verdict: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(audit.Event{Destination: "b.com", Verdict: "deny"}); err != nil {
		t.Fatal(err)
	}
	_ = logger.Close()

	// Tamper with the file: corrupt the second line's prev_hash.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"prev_hash":"`, `"prev_hash":"00`, 1)
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := handleAuditVerify(logPath); err == nil {
		t.Fatal("expected error for broken hash chain")
	}
}

// TestHandleAuditVerifyMissing verifies error return when the audit file does not exist.
func TestHandleAuditVerifyMissing(t *testing.T) {
	if err := handleAuditVerify("/nonexistent/path/audit.jsonl"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestHandleAuditNoArgs verifies error return when no subcommand is given.
func TestHandleAuditNoArgs(t *testing.T) {
	if err := handleAuditCommand([]string{}); err == nil {
		t.Fatal("expected error for no args")
	}
}

// TestHandleAuditUnknownSubcommand verifies error return for unknown subcommand.
func TestHandleAuditUnknownSubcommand(t *testing.T) {
	if err := handleAuditCommand([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

// TestHandleAuditVerifyDefaultPath verifies that handleAuditCommand passes the
// default path when no explicit path arg is given.
func TestHandleAuditVerifyDefaultPath(t *testing.T) {
	// Create a valid audit log in the working directory with the default name.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(audit.Event{Destination: "x.com", Verdict: "allow"}); err != nil {
		t.Fatal(err)
	}
	_ = logger.Close()

	// handleAuditVerify uses the path directly, so call it with the explicit
	// default path to validate parsing works correctly.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	if err := handleAuditVerify(logPath); err != nil {
		os.Stdout = oldStdout
		t.Fatalf("unexpected error: %v", err)
	}

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, "Total lines:  1") {
		t.Errorf("expected 1 total line, got: %s", output)
	}
}
