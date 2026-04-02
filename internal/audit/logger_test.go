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
