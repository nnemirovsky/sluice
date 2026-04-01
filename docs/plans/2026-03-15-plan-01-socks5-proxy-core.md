# Sluice Plan 1: SOCKS5 Proxy Core + Policy Engine

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a SOCKS5 proxy that evaluates connection requests against a TOML policy file (allow/deny/ask) and blocks or forwards accordingly. No Telegram yet (ask = deny in this plan). This is the foundation everything else builds on.

**Architecture:** Single Go binary with a SOCKS5 server that intercepts every TCP connection, matches destination:port against policy rules with glob patterns, and returns allow/deny verdicts. Policy loaded from TOML at startup with hot-reload on SIGHUP.

**Tech Stack:** Go 1.22+, `github.com/armon/go-socks5`, `github.com/BurntSushi/toml`, standard library for logging/net.

---

## File Structure

```
sluice/
  go.mod
  go.sum
  cmd/
    sluice/
      main.go              # CLI entrypoint, flag parsing, starts proxy
  internal/
    proxy/
      server.go            # SOCKS5 server setup + lifecycle
      server_test.go
    policy/
      engine.go            # Policy loading, matching, verdict
      engine_test.go
      glob.go              # Glob pattern compilation to regex
      glob_test.go
      types.go             # Policy structs, Verdict enum
    audit/
      logger.go            # Append-only JSON lines audit log
      logger_test.go
  testdata/
    policy_allow_all.toml
    policy_deny_all.toml
    policy_mixed.toml
```

---

## Chunk 1: Project Scaffolding + Policy Engine

### Task 1: Initialize Go module and project structure

**Files:**
- Create: `go.mod`
- Create: `cmd/sluice/main.go`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/nemirovsky/Developer/sluice
go mod init github.com/nemirovsky/sluice
```

- [ ] **Step 2: Create minimal main.go**

```go
// cmd/sluice/main.go
package main

import "fmt"

func main() {
	fmt.Println("sluice: not implemented")
}
```

- [ ] **Step 3: Verify it compiles and runs**

Run: `go run ./cmd/sluice/`
Expected: prints "sluice: not implemented"

- [ ] **Step 4: Commit**

```bash
git init
git add go.mod cmd/
git commit -m "init: scaffold Go module and entrypoint"
```

---

### Task 2: Policy types and TOML parsing

**Files:**
- Create: `internal/policy/types.go`
- Create: `internal/policy/engine.go`
- Create: `internal/policy/engine_test.go`
- Create: `testdata/policy_mixed.toml`

- [ ] **Step 1: Create test policy file**

```toml
# testdata/policy_mixed.toml
[policy]
default = "deny"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
destination = "*.github.com"
ports = [443, 80]

[[deny]]
destination = "169.254.169.254"

[[deny]]
destination = "*.crypto-mining.example"
```

- [ ] **Step 2: Write failing test for policy loading**

```go
// internal/policy/engine_test.go
package policy

import (
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	if eng.Default != Deny {
		t.Errorf("expected default Deny, got %v", eng.Default)
	}
	if len(eng.AllowRules) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(eng.AllowRules))
	}
	if len(eng.DenyRules) != 2 {
		t.Errorf("expected 2 deny rules, got %d", len(eng.DenyRules))
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/policy/ -v -run TestLoadPolicy`
Expected: FAIL (package doesn't exist yet)

- [ ] **Step 4: Implement types.go**

```go
// internal/policy/types.go
package policy

type Verdict int

const (
	Allow Verdict = iota
	Deny
	Ask
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	default:
		return "unknown"
	}
}

type Rule struct {
	Destination string `toml:"destination"`
	Ports       []int  `toml:"ports"`
	Note        string `toml:"note"`
	// Credential fields (used later by vault)
	InjectHeader string `toml:"inject_header"`
	Credential   string `toml:"credential"`
	Template     string `toml:"template"`
	Protocol     string `toml:"protocol"`
}

type PolicyConfig struct {
	Default string `toml:"default"`
	Timeout int    `toml:"timeout_sec"`
}

type policyFile struct {
	Policy PolicyConfig `toml:"policy"`
	Allow  []Rule       `toml:"allow"`
	Deny   []Rule       `toml:"deny"`
	Ask    []Rule       `toml:"ask"`
}
```

- [ ] **Step 5: Implement engine.go (loading only)**

```go
// internal/policy/engine.go
package policy

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Engine struct {
	Default    Verdict
	AllowRules []Rule
	DenyRules  []Rule
	AskRules   []Rule
	TimeoutSec int
}

func LoadFromFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return LoadFromBytes(data)
}

func LoadFromBytes(data []byte) (*Engine, error) {
	var pf policyFile
	if err := toml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy TOML: %w", err)
	}

	defaultVerdict := Deny
	switch pf.Policy.Default {
	case "allow":
		defaultVerdict = Allow
	case "deny":
		defaultVerdict = Deny
	case "ask":
		defaultVerdict = Ask
	default:
		if pf.Policy.Default != "" {
			return nil, fmt.Errorf("unknown default verdict: %q", pf.Policy.Default)
		}
	}

	timeout := pf.Policy.Timeout
	if timeout == 0 {
		timeout = 120
	}

	return &Engine{
		Default:    defaultVerdict,
		AllowRules: pf.Allow,
		DenyRules:  pf.Deny,
		AskRules:   pf.Ask,
		TimeoutSec: timeout,
	}, nil
}
```

- [ ] **Step 6: Add toml dependency and run test**

```bash
cd /Users/nemirovsky/Developer/sluice
go get github.com/BurntSushi/toml
go test ./internal/policy/ -v -run TestLoadPolicy
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/policy/ testdata/ go.mod go.sum
git commit -m "feat: policy types and TOML loading"
```

---

### Task 3: Glob pattern matching

**Files:**
- Create: `internal/policy/glob.go`
- Create: `internal/policy/glob_test.go`

- [ ] **Step 1: Write failing tests for glob matching**

```go
// internal/policy/glob_test.go
package policy

import "testing"

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{"api.anthropic.com", "api.anthropic.com", true},
		{"api.anthropic.com", "api.openai.com", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "raw.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "evil.com", false},
		{"169.254.169.254", "169.254.169.254", true},
		{"*.crypto-mining.*", "pool.crypto-mining.io", true},
		{"*", "anything.at.all", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.input, func(t *testing.T) {
			g, err := CompileGlob(tt.pattern)
			if err != nil {
				t.Fatalf("compile glob %q: %v", tt.pattern, err)
			}
			got := g.Match(tt.input)
			if got != tt.want {
				t.Errorf("Glob(%q).Match(%q) = %v, want %v",
					tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -v -run TestGlobMatch`
Expected: FAIL

- [ ] **Step 3: Implement glob.go**

```go
// internal/policy/glob.go
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

type Glob struct {
	pattern string
	re      *regexp.Regexp
}

func CompileGlob(pattern string) (*Glob, error) {
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			re.WriteString("[^.]*")
			// Check for ** (match across dots)
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				re.Reset()
				re.WriteString("^")
				re.WriteString(".*")
				i++
			}
		case '?':
			re.WriteString("[^.]")
		case '.':
			re.WriteString(`\.`)
		default:
			re.WriteByte(pattern[i])
		}
	}
	re.WriteString("$")

	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return nil, fmt.Errorf("compile glob %q -> regex %q: %w",
			pattern, re.String(), err)
	}
	return &Glob{pattern: pattern, re: compiled}, nil
}

func (g *Glob) Match(s string) bool {
	return g.re.MatchString(s)
}

func (g *Glob) String() string {
	return g.pattern
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -v -run TestGlobMatch`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/glob.go internal/policy/glob_test.go
git commit -m "feat: glob pattern matching for policy rules"
```

---

### Task 4: Policy evaluation (Evaluate method)

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

- [ ] **Step 1: Write failing tests for Evaluate**

Add to `engine_test.go`:

```go
func TestEvaluate(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := eng.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	tests := []struct {
		dest string
		port int
		want Verdict
	}{
		{"api.anthropic.com", 443, Allow},
		{"api.github.com", 443, Allow},
		{"api.github.com", 80, Allow},
		{"api.github.com", 22, Deny},    // port not in allow rule, default deny
		{"169.254.169.254", 80, Deny},    // explicit deny
		{"pool.crypto-mining.example", 443, Deny}, // glob deny
		{"random.unknown.com", 443, Deny}, // default deny
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			got := eng.Evaluate(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("Evaluate(%q, %d) = %v, want %v",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -v -run TestEvaluate`
Expected: FAIL (Compile and Evaluate methods don't exist)

- [ ] **Step 3: Implement Compile and Evaluate on Engine**

Add to `engine.go`:

```go
type compiledRule struct {
	glob  *Glob
	ports map[int]bool
	rule  Rule
}

type compiledEngine struct {
	allowRules []compiledRule
	denyRules  []compiledRule
	askRules   []compiledRule
}

func compileRules(rules []Rule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		g, err := CompileGlob(r.Destination)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", r.Destination, err)
		}
		ports := make(map[int]bool, len(r.Ports))
		for _, p := range r.Ports {
			ports[p] = true
		}
		out = append(out, compiledRule{glob: g, ports: ports, rule: r})
	}
	return out, nil
}

func (e *Engine) Compile() error {
	var err error
	e.compiled = &compiledEngine{}
	e.compiled.allowRules, err = compileRules(e.AllowRules)
	if err != nil {
		return err
	}
	e.compiled.denyRules, err = compileRules(e.DenyRules)
	if err != nil {
		return err
	}
	e.compiled.askRules, err = compileRules(e.AskRules)
	if err != nil {
		return err
	}
	return nil
}

func matchRules(rules []compiledRule, dest string, port int) bool {
	for _, r := range rules {
		if !r.glob.Match(dest) {
			continue
		}
		// If no ports specified, match all ports
		if len(r.ports) == 0 || r.ports[port] {
			return true
		}
	}
	return false
}

func (e *Engine) Evaluate(dest string, port int) Verdict {
	if e.compiled == nil {
		return e.Default
	}
	// Deny rules checked first (deny takes precedence)
	if matchRules(e.compiled.denyRules, dest, port) {
		return Deny
	}
	// Then allow rules
	if matchRules(e.compiled.allowRules, dest, port) {
		return Allow
	}
	// Then ask rules
	if matchRules(e.compiled.askRules, dest, port) {
		return Ask
	}
	return e.Default
}
```

Also add `compiled *compiledEngine` field to the `Engine` struct.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -v -run TestEvaluate`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/
git commit -m "feat: policy evaluation with glob matching"
```

---

## Chunk 2: SOCKS5 Proxy Server + Audit Logger

### Task 5: Audit logger (JSON lines)

**Files:**
- Create: `internal/audit/logger.go`
- Create: `internal/audit/logger_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/audit/logger_test.go
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoggerWritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	logger.Log(Event{
		Destination: "api.anthropic.com",
		Port:        443,
		Verdict:     "allow",
	})
	logger.Log(Event{
		Destination: "evil.com",
		Port:        80,
		Verdict:     "deny",
	})
	logger.Close()

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
```

(Add `"strings"` to imports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -v`
Expected: FAIL

- [ ] **Step 3: Implement logger.go**

```go
// internal/audit/logger.go
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

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

type FileLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func NewFileLogger(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileLogger{file: f, enc: json.NewEncoder(f)}, nil
}

func (l *FileLogger) Log(evt Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	l.enc.Encode(evt)
}

func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/audit/
git commit -m "feat: JSON lines audit logger"
```

---

### Task 6: SOCKS5 proxy server with policy integration

**Files:**
- Create: `internal/proxy/server.go`
- Create: `internal/proxy/server_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/proxy/server_test.go
package proxy

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/nemirovsky/sluice/internal/policy"
)

func TestProxyAllowsAllowedConnection(t *testing.T) {
	// Start a simple TCP echo server
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	// Create policy that allows localhost
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}
	eng.Compile()

	// Start sluice proxy
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	// Wait for proxy to start
	time.Sleep(50 * time.Millisecond)

	// Connect through SOCKS5 proxy
	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestProxyDeniesBlockedConnection(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}
	eng.Compile()

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	dialer, err := proxy.SOCKS5("tcp", srv.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialer.Dial("tcp", "93.184.216.34:80")
	if err == nil {
		t.Fatal("expected connection to be denied")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go get golang.org/x/net/proxy && go test ./internal/proxy/ -v -timeout 10s`
Expected: FAIL

- [ ] **Step 3: Implement server.go**

```go
// internal/proxy/server.go
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/armon/go-socks5"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
)

type Config struct {
	ListenAddr string
	Policy     *policy.Engine
	Audit      *audit.FileLogger
}

type Server struct {
	listener net.Listener
	socks    *socks5.Server
	policy   *policy.Engine
	audit    *audit.FileLogger
}

type policyRuleSet struct {
	engine *policy.Engine
	audit  *audit.FileLogger
}

func (r *policyRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	dest := req.DestAddr.FQDN
	if dest == "" {
		dest = req.DestAddr.IP.String()
	}
	port := req.DestAddr.Port

	verdict := r.engine.Evaluate(dest, port)

	if r.audit != nil {
		r.audit.Log(audit.Event{
			Destination: dest,
			Port:        port,
			Verdict:     verdict.String(),
		})
	}

	switch verdict {
	case policy.Allow:
		return ctx, true
	case policy.Ask:
		// In this plan, ask = deny (Telegram not yet implemented)
		log.Printf("[ASK->DENY] %s:%d (Telegram not configured)", dest, port)
		return ctx, false
	default:
		return ctx, false
	}
}

func New(cfg Config) (*Server, error) {
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	rules := &policyRuleSet{engine: cfg.Policy, audit: cfg.Audit}

	socksCfg := &socks5.Config{
		Rules: rules,
	}
	socksServer, err := socks5.New(socksCfg)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("socks5: %w", err)
	}

	return &Server{
		listener: ln,
		socks:    socksServer,
		policy:   cfg.Policy,
		audit:    cfg.Audit,
	}, nil
}

func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *Server) ListenAndServe() error {
	return s.socks.Serve(s.listener)
}

func (s *Server) Close() error {
	return s.listener.Close()
}
```

- [ ] **Step 4: Add go-socks5 dependency and run tests**

```bash
cd /Users/nemirovsky/Developer/sluice
go get github.com/armon/go-socks5
go test ./internal/proxy/ -v -timeout 10s
```

Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/ go.mod go.sum
git commit -m "feat: SOCKS5 proxy server with policy enforcement"
```

---

### Task 7: Wire it all together in main.go

**Files:**
- Modify: `cmd/sluice/main.go`

- [ ] **Step 1: Implement CLI with flag parsing**

```go
// cmd/sluice/main.go
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/proxy"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	policyPath := flag.String("policy", "policy.toml", "path to policy TOML file")
	auditPath := flag.String("audit", "audit.jsonl", "path to audit log file")
	flag.Parse()

	eng, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	if err := eng.Compile(); err != nil {
		log.Fatalf("compile policy: %v", err)
	}
	log.Printf("loaded policy: %d allow, %d deny, %d ask rules (default: %s)",
		len(eng.AllowRules), len(eng.DenyRules), len(eng.AskRules), eng.Default)

	logger, err := audit.NewFileLogger(*auditPath)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()

	srv, err := proxy.New(proxy.Config{
		ListenAddr: *listenAddr,
		Policy:     eng,
		Audit:      logger,
	})
	if err != nil {
		log.Fatalf("start proxy: %v", err)
	}

	log.Printf("sluice SOCKS5 proxy listening on %s", srv.Addr())

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("proxy stopped: %v", err)
		}
	}()

	<-sigCh
	log.Println("shutting down...")
	srv.Close()
}
```

- [ ] **Step 2: Build and test manually**

```bash
cd /Users/nemirovsky/Developer/sluice
go build -o sluice ./cmd/sluice/
./sluice -policy testdata/policy_mixed.toml -listen 127.0.0.1:1080 &
# In another terminal, test with curl:
# curl -x socks5h://127.0.0.1:1080 https://api.anthropic.com/ (should connect)
# curl -x socks5h://127.0.0.1:1080 http://169.254.169.254/ (should fail)
kill %1
```

- [ ] **Step 3: Commit**

```bash
git add cmd/sluice/main.go
git commit -m "feat: wire CLI entrypoint with proxy, policy, and audit"
```

---

### Task 8: Run all tests and verify

- [ ] **Step 1: Run full test suite**

Run: `go test ./... -v -timeout 30s`
Expected: ALL PASS

- [ ] **Step 2: Verify binary builds cleanly**

Run: `go build -o sluice ./cmd/sluice/ && echo "OK"`
Expected: OK

- [ ] **Step 3: Tag milestone**

```bash
git tag v0.0.1-alpha
```

---

## Chunk 3: Non-HTTP Protocol Handling

### Task 9: Protocol detection and per-protocol connection handling

The SOCKS5 proxy currently treats all connections as opaque TCP. For
credential injection (Plan 3) and protocol-specific governance, the proxy
needs to detect the protocol and hand off to the appropriate handler.

**Files:**
- Create: `internal/proxy/protocol.go`
- Create: `internal/proxy/protocol_test.go`
- Modify: `internal/proxy/server.go` (add protocol detection after policy allow)

- [ ] **Step 1: Define protocol types and detection**

```go
// internal/proxy/protocol.go
// Detect protocol from destination port and initial bytes:
//   - 80, 8080 -> HTTP
//   - 443, 8443 -> HTTPS (TLS ClientHello)
//   - 22 -> SSH
//   - 143 -> IMAP, 993 -> IMAPS
//   - 25, 587 -> SMTP, 465 -> SMTPS
//   - everything else -> Generic TCP

type Protocol string
const (
    ProtoHTTP    Protocol = "http"
    ProtoHTTPS   Protocol = "https"
    ProtoSSH     Protocol = "ssh"
    ProtoIMAP    Protocol = "imap"
    ProtoSMTP    Protocol = "smtp"
    ProtoGeneric Protocol = "generic"
)

func DetectProtocol(dest string, port int) Protocol
```

- [ ] **Step 2: Write tests for protocol detection**

```go
func TestDetectProtocol(t *testing.T) {
    tests := []struct{ dest string; port int; want Protocol }{
        {"api.anthropic.com", 443, ProtoHTTPS},
        {"github.com", 22, ProtoSSH},
        {"imap.gmail.com", 993, ProtoIMAP},
        {"smtp.gmail.com", 587, ProtoSMTP},
        {"random.com", 9999, ProtoGeneric},
    }
    // ...
}
```

- [ ] **Step 3: Integrate protocol detection into server.go Allow handler**

After policy verdict is Allow, detect protocol and store in context for
credential injection (Plan 3) to use.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/proxy/ -v -timeout 10s`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/protocol.go internal/proxy/protocol_test.go internal/proxy/server.go
git commit -m "feat: protocol detection for per-protocol credential handling"
```
