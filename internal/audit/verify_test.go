package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyChainValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	for i := range 5 {
		if err := logger.Log(Event{
			Destination: "host" + string(rune('0'+i)) + ".example.com",
			Port:        443,
			Verdict:     "allow",
		}); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}
	_ = logger.Close()

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	if result.TotalLines != 5 {
		t.Errorf("TotalLines = %d, want 5", result.TotalLines)
	}
	if result.ValidLinks != 5 {
		t.Errorf("ValidLinks = %d, want 5", result.ValidLinks)
	}
	if len(result.BrokenLinks) != 0 {
		t.Errorf("BrokenLinks = %d, want 0", len(result.BrokenLinks))
	}
	if result.LegacyLines != 0 {
		t.Errorf("LegacyLines = %d, want 0", result.LegacyLines)
	}
}

func TestVerifyChainTampered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	for i := range 5 {
		if err := logger.Log(Event{
			Destination: "host" + string(rune('0'+i)) + ".example.com",
			Port:        443,
			Verdict:     "allow",
		}); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}
	_ = logger.Close()

	// Tamper with the middle line (line index 2, line number 3).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	// Modify the verdict in line 2 to simulate tampering.
	var evt Event
	if err := json.Unmarshal([]byte(lines[2]), &evt); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	evt.Verdict = "deny"
	tampered, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	lines[2] = string(tampered)

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	if result.TotalLines != 5 {
		t.Errorf("TotalLines = %d, want 5", result.TotalLines)
	}

	// Tampering line 2 breaks the link at line 3 (which expects hash of original line 2).
	// Line 3's prev_hash still points to the original line 2, but expected_hash was
	// computed from the tampered line 2. So line 3 is where the break is detected.
	if len(result.BrokenLinks) != 1 {
		t.Fatalf("BrokenLinks = %d, want 1; broken: %+v", len(result.BrokenLinks), result.BrokenLinks)
	}
	if result.BrokenLinks[0].LineNumber != 4 {
		t.Errorf("broken link at line %d, want 4", result.BrokenLinks[0].LineNumber)
	}
}

func TestVerifyChainDeletedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	for i := range 5 {
		if err := logger.Log(Event{
			Destination: "host" + string(rune('0'+i)) + ".example.com",
			Port:        443,
			Verdict:     "allow",
		}); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}
	_ = logger.Close()

	// Delete line 2 (index 2). Lines 0,1,3,4 remain.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	// Remove line at index 2.
	remaining := append(lines[:2], lines[3:]...)
	if err := os.WriteFile(path, []byte(strings.Join(remaining, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write modified file: %v", err)
	}

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	if result.TotalLines != 4 {
		t.Errorf("TotalLines = %d, want 4", result.TotalLines)
	}

	// Deleting line 2 means line 3 (now at position 3) has prev_hash pointing to
	// the deleted line, but expected_hash was computed from line 1. So line 3
	// (now at file line 3) is broken.
	if len(result.BrokenLinks) != 1 {
		t.Fatalf("BrokenLinks = %d, want 1; broken: %+v", len(result.BrokenLinks), result.BrokenLinks)
	}
	if result.BrokenLinks[0].LineNumber != 3 {
		t.Errorf("broken link at line %d, want 3", result.BrokenLinks[0].LineNumber)
	}
}

func TestVerifyChainLegacyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write legacy entries (no prev_hash) followed by chained entries.
	// Simulate a pre-upgrade log that was later upgraded.
	legacyLine1 := `{"timestamp":"2025-01-01T00:00:00Z","destination":"old.com","port":443,"verdict":"allow"}`
	legacyLine2 := `{"timestamp":"2025-01-02T00:00:00Z","destination":"old2.com","port":80,"verdict":"deny"}`

	if err := os.WriteFile(path, []byte(legacyLine1+"\n"+legacyLine2+"\n"), 0o600); err != nil {
		t.Fatalf("write legacy lines: %v", err)
	}

	// Now open a logger which will recover the last hash and continue chaining.
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	if err := logger.Log(Event{Destination: "new.com", Port: 443, Verdict: "allow"}); err != nil {
		t.Fatalf("log chained event: %v", err)
	}
	_ = logger.Close()

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	if result.TotalLines != 3 {
		t.Errorf("TotalLines = %d, want 3", result.TotalLines)
	}
	if result.LegacyLines != 2 {
		t.Errorf("LegacyLines = %d, want 2", result.LegacyLines)
	}
	if len(result.BrokenLinks) != 0 {
		t.Errorf("BrokenLinks = %d, want 0", len(result.BrokenLinks))
	}
	// The chained entry is valid, plus the 2 legacy lines.
	if result.ValidLinks != 1 {
		t.Errorf("ValidLinks = %d, want 1", result.ValidLinks)
	}
}

func TestVerifyChainEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	if result.TotalLines != 0 {
		t.Errorf("TotalLines = %d, want 0", result.TotalLines)
	}
	if result.ValidLinks != 0 {
		t.Errorf("ValidLinks = %d, want 0", result.ValidLinks)
	}
	if len(result.BrokenLinks) != 0 {
		t.Errorf("BrokenLinks = %d, want 0", len(result.BrokenLinks))
	}
}

func TestVerifyChainFileNotFound(t *testing.T) {
	_, err := VerifyChain("/nonexistent/path/audit.jsonl")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
