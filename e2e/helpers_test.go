//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// buildOnce ensures the sluice binary is built exactly once per test run.
var (
	buildOnce   sync.Once
	builtBinary string
	buildErr    error
)

// SluiceOpts configures a sluice process for testing.
type SluiceOpts struct {
	// ConfigTOML is optional TOML content written to a temp file and passed
	// as --config to sluice for DB seeding.
	ConfigTOML string

	// ExtraArgs are additional CLI flags passed to the sluice binary.
	ExtraArgs []string

	// Env adds extra environment variables to the sluice process in
	// "KEY=VALUE" format. These are appended to os.Environ().
	Env []string
}

// SluiceProcess holds handles to a running sluice instance.
type SluiceProcess struct {
	Cmd       *exec.Cmd
	ProxyAddr string // host:port of the SOCKS5 proxy
	HealthURL string // full URL to /healthz endpoint
	DBPath    string
	AuditPath string
	ConfigDir string
	cancel    context.CancelFunc
}

// buildSluice compiles the sluice binary once and returns its path.
func buildSluice(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		// Build to a well-known location in the temp dir.
		builtBinary = filepath.Join(os.TempDir(), "sluice-e2e-test")
		cmd := exec.Command("go", "build", "-o", builtBinary, "./cmd/sluice/")
		cmd.Dir = findProjectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build sluice: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtBinary
}

// findProjectRoot walks up from the test file directory to find go.mod.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (go.mod)")
		}
		dir = parent
	}
}

// startSluice spawns a sluice process with a temp DB, audit log, and optional
// config. It waits for the health endpoint to respond before returning.
func startSluice(t *testing.T, opts SluiceOpts) *SluiceProcess {
	t.Helper()

	binary := buildSluice(t)
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "sluice.db")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	// Find free ports for SOCKS5 and health HTTP server.
	proxyPort := freePort(t)
	healthPort := freePort(t)

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	healthAddr := fmt.Sprintf("127.0.0.1:%d", healthPort)

	args := []string{
		"--listen", proxyAddr,
		"--db", dbPath,
		"--audit", auditPath,
		"--health-addr", healthAddr,
		"--runtime", "none",
	}

	if opts.ConfigTOML != "" {
		configPath := filepath.Join(tmpDir, "config.toml")
		if err := os.WriteFile(configPath, []byte(opts.ConfigTOML), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		args = append(args, "--config", configPath)
	}

	args = append(args, opts.ExtraArgs...)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = os.Stderr // show sluice logs in test output
	cmd.Stderr = os.Stderr
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sluice: %v", err)
	}

	proc := &SluiceProcess{
		Cmd:       cmd,
		ProxyAddr: proxyAddr,
		HealthURL: fmt.Sprintf("http://%s/healthz", healthAddr),
		DBPath:    dbPath,
		AuditPath: auditPath,
		ConfigDir: tmpDir,
		cancel:    cancel,
	}

	t.Cleanup(func() {
		stopSluice(t, proc)
	})

	waitForHealthy(t, proc.HealthURL, 10*time.Second)
	return proc
}

// stopSluice terminates a running sluice process gracefully. It sends SIGTERM
// first to allow clean shutdown (audit log flush, DB close), then falls back
// to SIGKILL via context cancellation if the process does not exit in time.
func stopSluice(t *testing.T, proc *SluiceProcess) {
	t.Helper()
	if proc.Cmd.Process != nil {
		_ = proc.Cmd.Process.Signal(syscall.SIGTERM)
	}
	done := make(chan error, 1)
	go func() { done <- proc.Cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		if proc.cancel != nil {
			proc.cancel()
		}
		<-done
	}
}

// waitForHealthy polls the health endpoint until it returns 200 or the
// timeout expires.
func waitForHealthy(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("sluice did not become healthy at %s within %v", url, timeout)
}

// connectSOCKS5 creates a SOCKS5 dialer connected to the given proxy address.
func connectSOCKS5(t *testing.T, proxyAddr string) proxy.Dialer {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("create SOCKS5 dialer: %v", err)
	}
	return dialer
}

// importConfig runs `sluice policy import <path>` against a running sluice's DB.
// Note: --db must come before the positional toml path arg because Go's flag
// package stops parsing flags at the first non-flag argument.
func importConfig(t *testing.T, proc *SluiceProcess, toml string) {
	t.Helper()
	binary := buildSluice(t)
	configPath := filepath.Join(proc.ConfigDir, "import.toml")
	if err := os.WriteFile(configPath, []byte(toml), 0o644); err != nil {
		t.Fatalf("write import config: %v", err)
	}
	cmd := exec.Command(binary, "policy", "import", "--db", proc.DBPath, configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy import: %v\n%s", err, out)
	}
}

// startEchoServer starts an HTTP server that echoes request details back.
// Returns an httptest.Server; the caller should defer s.Close().
func startEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Method: %s\n", r.Method)
		fmt.Fprintf(w, "URL: %s\n", r.URL.String())
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		for name, vals := range r.Header {
			for _, v := range vals {
				fmt.Fprintf(w, "Header: %s: %s\n", name, v)
			}
		}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				fmt.Fprintf(w, "Body: %s\n", string(body))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startTLSEchoServer starts an HTTPS echo server. Returns the server and its
// address (host:port). The server uses a self-signed certificate.
func startTLSEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Method: %s\n", r.Method)
		fmt.Fprintf(w, "URL: %s\n", r.URL.String())
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		for name, vals := range r.Header {
			for _, v := range vals {
				fmt.Fprintf(w, "Header: %s: %s\n", name, v)
			}
		}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				fmt.Fprintf(w, "Body: %s\n", string(body))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// httpGetViaSOCKS5 makes an HTTP GET request through the SOCKS5 proxy.
func httpGetViaSOCKS5(t *testing.T, proxyAddr, url string) (int, string) {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s via SOCKS5: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// freePort returns a port number that is currently available for binding.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// readAuditLog reads the audit log file and returns its contents as a string.
func readAuditLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read audit log: %v", err)
	}
	return string(data)
}

// auditLogContains checks if the audit log contains a specific substring.
func auditLogContains(t *testing.T, path, substr string) bool {
	t.Helper()
	return strings.Contains(readAuditLog(t, path), substr)
}

// runSluiceCLI runs a sluice subcommand and returns the combined output.
// The --db flag is inserted after the subcommand name so it is parsed
// correctly even when positional arguments follow.
func runSluiceCLI(t *testing.T, proc *SluiceProcess, args ...string) string {
	t.Helper()
	binary := buildSluice(t)
	// Insert --db after the first two args (subcommand + action) so that
	// Go's flag package sees it before any positional arguments.
	var fullArgs []string
	if len(args) >= 2 {
		fullArgs = append(fullArgs, args[0], args[1], "--db", proc.DBPath)
		fullArgs = append(fullArgs, args[2:]...)
	} else {
		fullArgs = append(args, "--db", proc.DBPath)
	}
	cmd := exec.Command(binary, fullArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sluice %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// tryHTTPGetViaSOCKS5 attempts an HTTP GET through the SOCKS5 proxy and
// returns the status code, body, and any error. Unlike httpGetViaSOCKS5 it
// does not call t.Fatalf on failure so callers can assert on the error.
func tryHTTPGetViaSOCKS5(t *testing.T, proxyAddr, url string) (int, string, error) {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.StatusCode, "", readErr
	}
	return resp.StatusCode, string(body), nil
}

// sendSIGHUP sends SIGHUP to a running sluice process to trigger a policy
// reload from the SQLite store.
func sendSIGHUP(t *testing.T, proc *SluiceProcess) {
	t.Helper()
	if err := proc.Cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	// Give the process time to reload.
	time.Sleep(500 * time.Millisecond)
}

// echoServerAddr returns the host:port of an httptest.Server suitable for
// use in SOCKS5 proxy connections (strips the http:// scheme prefix).
func echoServerAddr(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	addr := strings.TrimPrefix(srv.URL, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	return addr
}

// verdictServer is a test HTTP server that returns a sequence of verdicts
// in response to webhook approval requests. It records all received
// request bodies for inspection. When the verdict sequence is exhausted
// it defaults to "deny". Non-approval requests (cancel, notification)
// are recorded but do not consume a verdict from the sequence.
type verdictServer struct {
	mu            sync.Mutex
	verdicts      []string
	calls         int // total POST calls (all types)
	approvalCalls int // POST calls with type=approval only
	requests      []map[string]interface{}
}

// Calls returns the total number of webhook calls received so far
// (all types including cancel and notification).
func (v *verdictServer) Calls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// ApprovalCalls returns the number of approval-type webhook calls received.
func (v *verdictServer) ApprovalCalls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.approvalCalls
}

// Requests returns a copy of all recorded request bodies.
func (v *verdictServer) Requests() []map[string]interface{} {
	v.mu.Lock()
	defer v.mu.Unlock()
	cp := make([]map[string]interface{}, len(v.requests))
	copy(cp, v.requests)
	return cp
}

// ServeHTTP handles POST webhook requests by returning the next verdict
// in the configured sequence. Only approval-type requests consume a
// verdict from the sequence. Cancel and notification requests are
// recorded but answered with an empty 200 OK.
func (v *verdictServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusInternalServerError)
		return
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	v.mu.Lock()
	v.requests = append(v.requests, parsed)
	v.calls++

	// Only approval requests consume a verdict from the sequence.
	// Cancel and notification requests are recorded but do not advance
	// the verdict index.
	reqType, _ := parsed["type"].(string)
	if reqType != "approval" {
		v.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	idx := v.approvalCalls
	v.approvalCalls++

	verdict := "deny"
	if idx < len(v.verdicts) {
		verdict = v.verdicts[idx]
	}
	v.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"verdict": verdict})
}

// startVerdictServer starts an httptest.Server backed by a verdictServer
// that returns the given verdicts in order. The server is automatically
// closed when the test finishes.
func startVerdictServer(t *testing.T, verdicts ...string) (*httptest.Server, *verdictServer) {
	t.Helper()
	vs := &verdictServer{verdicts: verdicts}
	srv := httptest.NewServer(vs)
	t.Cleanup(srv.Close)
	return srv, vs
}

// sluiceWithWebhook starts a sluice process with the given policy TOML
// and an HTTP webhook channel pointing at webhookURL. It adds the channel
// to the DB before starting sluice so the broker is initialized at startup.
func sluiceWithWebhook(t *testing.T, policyTOML, webhookURL string) *SluiceProcess {
	t.Helper()

	binary := buildSluice(t)
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "sluice.db")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	// Write the policy config TOML for seeding.
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(policyTOML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Seed the DB with policy rules via `sluice policy import`.
	// This also creates the DB file and runs migrations.
	importCmd := exec.Command(binary, "policy", "import", "--db", dbPath, configPath)
	if out, err := importCmd.CombinedOutput(); err != nil {
		t.Fatalf("seed policy: %v\n%s", err, out)
	}

	// Add the HTTP webhook channel to the pre-seeded DB.
	channelCmd := exec.Command(binary, "channel", "add",
		"--type", "http",
		"--url", webhookURL,
		"--db", dbPath,
	)
	if out, err := channelCmd.CombinedOutput(); err != nil {
		t.Fatalf("add webhook channel: %v\n%s", err, out)
	}

	// Start sluice with the pre-populated DB (no --config since DB is
	// already seeded and seedStoreFromConfig skips non-empty DBs).
	proxyPort := freePort(t)
	healthPort := freePort(t)

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	healthAddr := fmt.Sprintf("127.0.0.1:%d", healthPort)

	args := []string{
		"--listen", proxyAddr,
		"--db", dbPath,
		"--audit", auditPath,
		"--health-addr", healthAddr,
		"--runtime", "none",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sluice: %v", err)
	}

	proc := &SluiceProcess{
		Cmd:       cmd,
		ProxyAddr: proxyAddr,
		HealthURL: fmt.Sprintf("http://%s/healthz", healthAddr),
		DBPath:    dbPath,
		AuditPath: auditPath,
		ConfigDir: tmpDir,
		cancel:    cancel,
	}

	t.Cleanup(func() {
		stopSluice(t, proc)
	})

	waitForHealthy(t, proc.HealthURL, 10*time.Second)
	return proc
}
