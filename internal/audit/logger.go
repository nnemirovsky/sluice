// Package audit provides tamper-evident JSON Lines logging with blake3 hash
// chaining. Each log entry includes the hash of the previous entry, enabling
// detection of log tampering or truncation.
package audit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

// Event represents a single audit log entry for a connection attempt.
type Event struct {
	Timestamp   string `json:"timestamp"`
	PrevHash    string `json:"prev_hash"`
	Destination string `json:"destination"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Action      string `json:"action,omitempty"`
	Credential  string `json:"credential_used,omitempty"`
}

// FileLogger writes audit events as JSON lines to a file.
// Each entry includes a blake3 hash of the previous entry for tamper evidence.
type FileLogger struct {
	mu       sync.Mutex
	file     *os.File
	lastHash string
}

// NewFileLogger creates a new append-only JSON lines audit logger.
// If the file already contains entries, the last line is read to recover
// the hash chain for restart continuity.
func NewFileLogger(path string) (*FileLogger, error) {
	lastHash, err := recoverLastHash(path)
	if err != nil {
		return nil, fmt.Errorf("recover hash chain: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileLogger{file: f, lastHash: lastHash}, nil
}

// Log writes an event to the audit log. It is safe for concurrent use.
// The event's PrevHash is set to the blake3 hash of the previous line
// (or blake3 of empty string for the first entry).
func (l *FileLogger) Log(evt Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	evt.PrevHash = l.lastHash

	line, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}

	// Update lastHash to the hash of what was just written (without trailing newline).
	l.lastHash = hashLine(line[:len(line)-1])
	return nil
}

// Close closes the underlying file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// hashLine computes the blake3-256 hash of data and returns the hex-encoded string.
func hashLine(data []byte) string {
	h := blake3.Sum256(data)
	return hex.EncodeToString(h[:])
}

// recoverLastHash reads the last non-empty line from an existing log file
// and returns its blake3 hash. If the file does not exist or is empty,
// it returns the genesis hash (blake3 of empty string).
//
// The function reads backwards from the end of the file so it is O(line_length)
// rather than O(file_size), and has no line-length limit.
func recoverLastHash(path string) (string, error) {
	genesis := hashLine([]byte(""))

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return genesis, nil
		}
		return "", err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := info.Size()
	if size == 0 {
		return genesis, nil
	}

	// Read backwards from end of file to find the last complete line.
	// Audit lines are JSON objects terminated by '\n'.
	const chunkSize = 4096
	buf := make([]byte, 0, chunkSize)
	offset := size

	for offset > 0 {
		readLen := int64(chunkSize)
		if readLen > offset {
			readLen = offset
		}
		offset -= readLen

		chunk := make([]byte, readLen)
		if _, err := f.ReadAt(chunk, offset); err != nil && err != io.EOF {
			return "", fmt.Errorf("read audit log tail: %w", err)
		}
		buf = append(chunk, buf...)

		// Look for the last complete line in what we have so far.
		// Strip any trailing newline, then find the previous newline.
		trimmed := buf
		for len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\n' {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if len(trimmed) == 0 {
			continue
		}

		// Find start of the last line.
		lastNL := -1
		for i := len(trimmed) - 1; i >= 0; i-- {
			if trimmed[i] == '\n' {
				lastNL = i
				break
			}
		}

		if lastNL >= 0 || offset == 0 {
			var line []byte
			if lastNL >= 0 {
				line = trimmed[lastNL+1:]
			} else {
				line = trimmed
			}
			if len(line) > 0 {
				return hashLine(line), nil
			}
		}
	}

	return genesis, nil
}
