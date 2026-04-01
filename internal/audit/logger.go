package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event represents a single audit log entry for a connection attempt.
type Event struct {
	Timestamp   string `json:"timestamp"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Action      string `json:"action,omitempty"`
	Credential  string `json:"credential_used,omitempty"`
}

// FileLogger writes audit events as JSON lines to a file.
type FileLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewFileLogger creates a new append-only JSON lines audit logger.
func NewFileLogger(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileLogger{file: f, enc: json.NewEncoder(f)}, nil
}

// Log writes an event to the audit log. It is safe for concurrent use.
func (l *FileLogger) Log(evt Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	l.enc.Encode(evt)
}

// Close closes the underlying file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
