//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
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
var buildOnce sync.Once
var builtBinary string
var buildErr error

// SluiceOpts configures a sluice process for testing.
type SluiceOpts struct {
	// ConfigTOML is optional TOML content written to a temp file and passed
	// as --config to sluice for DB seeding.
	ConfigTOML string

	// ExtraArgs are additional CLI flags passed to the sluice binary.
	ExtraArgs []string

	// RuntimeNone disables container management (--runtime none). Defaults to true.
	RuntimeNone bool
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

// stopSluice terminates a running sluice process.
func stopSluice(t *testing.T, proc *SluiceProcess) {
	t.Helper()
	if proc.cancel != nil {
		proc.cancel()
	}
	// Wait for process to exit (ignore error from signal).
	_ = proc.Cmd.Wait()
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
func runSluiceCLI(t *testing.T, proc *SluiceProcess, args ...string) string {
	t.Helper()
	binary := buildSluice(t)
	fullArgs := append(args, "--db", proc.DBPath)
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
