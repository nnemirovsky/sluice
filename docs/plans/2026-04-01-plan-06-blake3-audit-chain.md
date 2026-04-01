# Sluice Plan 6: Blake3 Tamper-Evident Audit Chain

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the existing JSON lines audit logger (Plan 1, Task 5) with blake3 hash chaining so every audit entry includes a cryptographic link to the previous entry. This makes the audit log tamper-evident: deleting or modifying any entry breaks the chain and is detectable.

**Why:** Security-focused tools (Bulwark, nono) use hash chains for audit integrity. Plain JSON lines can be silently edited by an attacker who compromises the Sluice container. With hash chains, tampering is detectable by any verifier with access to the log file.

**Architecture:** Each JSON line gets a `prev_hash` field containing the blake3 hash of the previous line's raw JSON bytes. The first entry uses a well-known genesis hash (`blake3("")`). A `sluice audit verify` CLI command walks the file and reports any broken links.

**Tech Stack:** Go, `lukechampine.com/blake3`

**Depends on:** Plan 1 Task 5 (existing JSON lines audit logger, already implemented)

---

## Context

- Existing logger: `internal/audit/logger.go` (append-only JSON lines, thread-safe)
- Existing tests: `internal/audit/logger_test.go`
- Existing Event struct has: Timestamp, Destination, Port, Verdict, Reason, Tool, Action, Credential
- The logger is used by the SOCKS5 proxy (`internal/proxy/server.go`) and will be used by the MCP gateway (Plan 4)

## Development Approach

- **Testing approach**: TDD
- Modify existing audit logger in-place (not a new module)
- Backward compatible: logs without `prev_hash` are treated as legacy (verification skips them)
- Keep JSON lines format (greppable, streamable, tail-friendly)
- blake3 chosen over SHA-256 for speed (audit logging is on the hot path for every connection)

## Implementation Steps

### Task 1: Add blake3 hash chaining to audit logger

**Files:**
- Modify: `internal/audit/logger.go`
- Modify: `internal/audit/logger_test.go`
- New dep: `lukechampine.com/blake3`

- [ ] **Step 1: Add `prev_hash` field to Event struct**

```go
// internal/audit/logger.go
type Event struct {
	Timestamp   string `json:"timestamp"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty"`
	Verdict     string `json:"verdict,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Action      string `json:"action,omitempty"`
	Credential  string `json:"credential_used,omitempty"`
	PrevHash    string `json:"prev_hash"`
}
```

- [ ] **Step 2: Track last hash in FileLogger and compute chain**

```go
type FileLogger struct {
	mu       sync.Mutex
	file     *os.File
	lastHash string // hex-encoded blake3 hash of last written line
}

// Genesis hash: blake3 of empty string
const genesisHash = "" // computed once at init

func NewFileLogger(path string) (*FileLogger, error) {
	// ... existing open logic ...
	// Read last line of existing file to recover lastHash for continuity.
	// If file is empty or new, use genesis hash.
	lastHash := computeLastHash(path)
	return &FileLogger{file: f, lastHash: lastHash}, nil
}

func (l *FileLogger) Log(evt Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	evt.PrevHash = l.lastHash
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	raw, _ := json.Marshal(evt)
	l.file.Write(raw)
	l.file.Write([]byte("\n"))
	l.lastHash = hashLine(raw)
}

func hashLine(line []byte) string {
	h := blake3.Sum256(line)
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 3: Implement recovery of lastHash from existing log file**

```go
// computeLastHash reads the last non-empty line of the file,
// parses it, and returns blake3(line). If file is empty/missing,
// returns genesis hash.
func computeLastHash(path string) string
```

This ensures hash chain continuity across Sluice restarts.

- [ ] **Step 4: Add blake3 dependency**

```bash
go get lukechampine.com/blake3
```

- [ ] **Step 5: Write test for hash chain integrity**

```go
func TestLoggerHashChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, _ := NewFileLogger(path)
	logger.Log(Event{Destination: "a.com", Port: 443, Verdict: "allow"})
	logger.Log(Event{Destination: "b.com", Port: 80, Verdict: "deny"})
	logger.Log(Event{Destination: "c.com", Port: 22, Verdict: "ask"})
	logger.Close()

	// Read lines and verify chain
	data, _ := os.ReadFile(path)
	lines := splitNonEmpty(string(data))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// First entry's prev_hash should be genesis
	var evt0 Event
	json.Unmarshal([]byte(lines[0]), &evt0)
	genesis := hashLine([]byte(""))
	if evt0.PrevHash != genesis {
		t.Errorf("first entry prev_hash: got %q, want genesis %q", evt0.PrevHash, genesis)
	}

	// Second entry's prev_hash should be blake3 of first line
	var evt1 Event
	json.Unmarshal([]byte(lines[1]), &evt1)
	expectedHash := hashLine([]byte(lines[0]))
	if evt1.PrevHash != expectedHash {
		t.Errorf("second entry prev_hash mismatch")
	}

	// Third entry's prev_hash should be blake3 of second line
	var evt2 Event
	json.Unmarshal([]byte(lines[2]), &evt2)
	expectedHash2 := hashLine([]byte(lines[1]))
	if evt2.PrevHash != expectedHash2 {
		t.Errorf("third entry prev_hash mismatch")
	}
}
```

- [ ] **Step 6: Write test for chain continuity across restarts**

```go
func TestLoggerHashChainContinuity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Session 1: write 2 entries
	logger1, _ := NewFileLogger(path)
	logger1.Log(Event{Destination: "a.com", Port: 443, Verdict: "allow"})
	logger1.Log(Event{Destination: "b.com", Port: 80, Verdict: "deny"})
	logger1.Close()

	// Session 2: reopen and write 1 more
	logger2, _ := NewFileLogger(path)
	logger2.Log(Event{Destination: "c.com", Port: 22, Verdict: "ask"})
	logger2.Close()

	// Verify the third entry chains to the second (across restart)
	data, _ := os.ReadFile(path)
	lines := splitNonEmpty(string(data))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	var evt2 Event
	json.Unmarshal([]byte(lines[2]), &evt2)
	expectedHash := hashLine([]byte(lines[1]))
	if evt2.PrevHash != expectedHash {
		t.Errorf("cross-restart chain broken")
	}
}
```

- [ ] **Step 7: Update existing tests to account for prev_hash field**

Existing `TestLoggerWritesJSONLines` should still pass. The Event struct
now has `prev_hash` but existing assertions check other fields.

- [ ] **Step 8: Run tests**

Run: `go test ./internal/audit/ -v`
Expected: ALL PASS

- [ ] **Step 9: Commit**

```bash
git add internal/audit/ go.mod go.sum
git commit -m "feat: blake3 hash chain for tamper-evident audit log"
```

---

### Task 2: Audit verification CLI command

**Files:**
- Create: `internal/audit/verify.go`
- Create: `internal/audit/verify_test.go`
- Modify: `cmd/sluice/main.go` (add `audit verify` subcommand)

- [ ] **Step 1: Implement chain verification function**

```go
// internal/audit/verify.go

type VerifyResult struct {
	TotalLines  int
	ValidLinks  int
	BrokenLinks []BrokenLink
	LegacyLines int // lines without prev_hash (pre-upgrade)
}

type BrokenLink struct {
	LineNumber   int
	ExpectedHash string
	ActualHash   string
}

// VerifyChain reads the audit log and checks every hash link.
// Returns a result indicating how many links are valid and which
// (if any) are broken.
func VerifyChain(path string) (*VerifyResult, error)
```

- [ ] **Step 2: Write test for valid chain verification**

```go
func TestVerifyChainValid(t *testing.T) {
	// Create a valid 5-entry log, verify returns 0 broken links
}
```

- [ ] **Step 3: Write test for tampered chain detection**

```go
func TestVerifyChainDetectsTampering(t *testing.T) {
	// Create valid log, modify middle line, verify detects broken link
}

func TestVerifyChainDetectsDeletion(t *testing.T) {
	// Create valid log, delete a line, verify detects broken link
}
```

- [ ] **Step 4: Add `audit verify` CLI subcommand**

```go
// cmd/sluice/main.go
case "audit":
	if len(os.Args) > 2 && os.Args[2] == "verify" {
		result, err := audit.VerifyChain(auditPath)
		// Print result: total lines, valid links, broken links
	}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/audit/ -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/audit/verify.go internal/audit/verify_test.go cmd/
git commit -m "feat: audit verify CLI command for hash chain integrity check"
```

---

### Task 3: Verify acceptance criteria

- [ ] Verify hash chain is computed correctly (blake3 of raw JSON bytes)
- [ ] Verify chain continuity across logger restarts
- [ ] Verify tampered entries are detected by `sluice audit verify`
- [ ] Verify deleted entries are detected
- [ ] Verify legacy logs (no prev_hash) are handled gracefully
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 4: [Final] Update documentation

- [ ] Update ARCHITECTURE.md audit logger section to mention blake3 hash chains
- [ ] Update Plan 1 Task 5 description to note it was upgraded by this plan

## Technical Details

### Hash chain format

Each JSON line:
```json
{"timestamp":"2026-04-01T12:00:00Z","destination":"api.anthropic.com","port":443,"verdict":"allow","prev_hash":"a1b2c3..."}
```

Where `prev_hash` = `hex(blake3(raw_json_bytes_of_previous_line))`.

First entry: `prev_hash` = `hex(blake3(""))` (genesis).

### Verification algorithm

```
expected_hash = blake3("")  // genesis
for each line in file:
    parse line as JSON
    if line.prev_hash != expected_hash:
        report broken link at this line
    expected_hash = blake3(raw_line_bytes)
```

### Performance

blake3 is ~3x faster than SHA-256 on modern hardware. For audit logging
(hundreds to low thousands of entries per day), this adds negligible
overhead. The hash computation is inside the mutex-protected `Log` call
which is already serialized.

## Post-Completion

**Integration points:**
- The `/audit recent N` Telegram command (Plan 2, Task 5) should display `prev_hash` truncated to 8 chars for readability
- The MCP gateway (Plan 4) will use the same logger and automatically gets hash chaining
- Consider adding `sluice audit export --format=csv` for compliance reporting (future)
