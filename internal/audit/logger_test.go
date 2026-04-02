package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerWritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	if err := logger.Log(Event{
		Destination: "api.anthropic.com",
		Port:        443,
		Verdict:     "allow",
	}); err != nil {
		t.Fatalf("log event 1: %v", err)
	}
	if err := logger.Log(Event{
		Destination: "evil.com",
		Port:        80,
		Verdict:     "deny",
	}); err != nil {
		t.Fatalf("log event 2: %v", err)
	}
	_ = logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	lines := splitNonEmpty(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var evt Event
	if err := json.Unmarshal([]byte(lines[0]), &evt); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if evt.Destination != "api.anthropic.com" {
		t.Errorf("expected destination api.anthropic.com, got %q", evt.Destination)
	}
	if evt.Port != 443 {
		t.Errorf("expected port 443, got %d", evt.Port)
	}
	if evt.Verdict != "allow" {
		t.Errorf("expected verdict allow, got %q", evt.Verdict)
	}
	if evt.Timestamp == "" {
		t.Error("expected timestamp to be set automatically")
	}
	if evt.PrevHash == "" {
		t.Error("expected prev_hash to be set on first entry")
	}

	var evt2 Event
	if err := json.Unmarshal([]byte(lines[1]), &evt2); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if evt2.Destination != "evil.com" {
		t.Errorf("expected destination evil.com, got %q", evt2.Destination)
	}
	if evt2.Verdict != "deny" {
		t.Errorf("expected verdict deny, got %q", evt2.Verdict)
	}
	if evt2.PrevHash == "" {
		t.Error("expected prev_hash to be set on second entry")
	}
}

func TestHashChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	events := []Event{
		{Destination: "first.com", Port: 443, Verdict: "allow"},
		{Destination: "second.com", Port: 80, Verdict: "deny"},
		{Destination: "third.com", Port: 22, Verdict: "ask"},
	}
	for i, evt := range events {
		if err := logger.Log(evt); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}
	_ = logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := splitNonEmpty(string(data))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// First entry's prev_hash must be blake3 of empty string (genesis).
	genesisHash := hashLine([]byte(""))
	var first Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if first.PrevHash != genesisHash {
		t.Errorf("first entry prev_hash = %q, want genesis %q", first.PrevHash, genesisHash)
	}

	// Second entry's prev_hash must be blake3 of first line's raw JSON.
	expectedHash1 := hashLine([]byte(lines[0]))
	var second Event
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if second.PrevHash != expectedHash1 {
		t.Errorf("second entry prev_hash = %q, want %q", second.PrevHash, expectedHash1)
	}

	// Third entry's prev_hash must be blake3 of second line's raw JSON.
	expectedHash2 := hashLine([]byte(lines[1]))
	var third Event
	if err := json.Unmarshal([]byte(lines[2]), &third); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	if third.PrevHash != expectedHash2 {
		t.Errorf("third entry prev_hash = %q, want %q", third.PrevHash, expectedHash2)
	}
}

func TestHashChainContinuityAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// First session: write two entries.
	logger1, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger (session 1): %v", err)
	}
	if err := logger1.Log(Event{Destination: "a.com", Port: 443, Verdict: "allow"}); err != nil {
		t.Fatalf("log event 1: %v", err)
	}
	if err := logger1.Log(Event{Destination: "b.com", Port: 80, Verdict: "deny"}); err != nil {
		t.Fatalf("log event 2: %v", err)
	}
	_ = logger1.Close()

	// Second session: reopen and write one more entry.
	logger2, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger (session 2): %v", err)
	}
	if err := logger2.Log(Event{Destination: "c.com", Port: 22, Verdict: "ask"}); err != nil {
		t.Fatalf("log event 3: %v", err)
	}
	_ = logger2.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := splitNonEmpty(string(data))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Verify the full chain is unbroken across the restart boundary.
	genesisHash := hashLine([]byte(""))
	var evts [3]Event
	for i := range 3 {
		if err := json.Unmarshal([]byte(lines[i]), &evts[i]); err != nil {
			t.Fatalf("unmarshal line %d: %v", i, err)
		}
	}

	if evts[0].PrevHash != genesisHash {
		t.Errorf("entry 0 prev_hash = %q, want genesis %q", evts[0].PrevHash, genesisHash)
	}
	if evts[1].PrevHash != hashLine([]byte(lines[0])) {
		t.Errorf("entry 1 prev_hash = %q, want hash of line 0", evts[1].PrevHash)
	}
	// This is the critical check: entry written after restart must chain to the last entry
	// from the previous session.
	if evts[2].PrevHash != hashLine([]byte(lines[1])) {
		t.Errorf("entry 2 (post-restart) prev_hash = %q, want hash of line 1", evts[2].PrevHash)
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
