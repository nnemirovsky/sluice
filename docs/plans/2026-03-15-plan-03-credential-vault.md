# Sluice Plan 3: Credential Vault + Injection

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an age-encrypted credential vault so Sluice can store secrets and inject them into forwarded requests. For HTTP/HTTPS, credentials are injected as headers via a mitmproxy addon. For SSH, IMAP, SMTP, the proxy handles protocol-specific injection.

**Architecture:** Credentials are stored as age-encrypted files on disk (default; pluggable providers for HashiCorp Vault, Bitwarden, env vars). A TOML bindings file maps destination patterns to credential names and injection strategies. On connection allow, the proxy resolves the binding, decrypts the credential into zeroized memory, injects it via the built-in HTTPS MITM proxy, and zeroes the memory immediately after.

**Tech Stack:** Go, `filippo.io/age` for encryption, `goproxy` for in-process HTTPS MITM

**Depends on:** Plan 1 (SOCKS5 Proxy Core)

---

## File Structure

```
sluice/
  internal/
    vault/
      store.go           # Credential storage, encryption, decryption
      store_test.go
      secure.go          # SecureBytes with zeroized memory
      secure_test.go
      binding.go         # Binding resolution (destination -> credential)
      binding_test.go
      provider.go        # Pluggable credential provider interface
      provider_age.go    # Default: age-encrypted files
      provider_env.go    # Environment variables
      provider_hashicorp.go  # HashiCorp Vault (optional)
    proxy/
      server.go          # Modify: credential injection on allow
      inject.go          # In-process HTTPS MITM credential injection
      inject_test.go
      ca.go              # Self-signed CA generation for MITM
```

---

## Chunk 1: Credential Store

### Task 1: Credential encryption and storage

**Files:**
- Create: `internal/vault/store.go`
- Create: `internal/vault/store_test.go`

- [x] **Step 1: Write failing test for add/get credential**

```go
// internal/vault/store_test.go
package vault

import (
	"path/filepath"
	"testing"
)

func TestAddAndGetCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Add("github_token", "ghp_abc123secrettoken456")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	val, err := store.Get("github_token")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "ghp_abc123secrettoken456" {
		t.Errorf("expected token, got %q", val)
	}

	// Verify the file on disk is encrypted (not plaintext)
	data, _ := os.ReadFile(filepath.Join(dir, "credentials", "github_token.age"))
	if string(data) == "ghp_abc123secrettoken456" {
		t.Error("credential stored in plaintext")
	}
}

func TestGetNonexistentCredential(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent credential")
	}
}

func TestListCredentials(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	store.Add("key_a", "val_a")
	store.Add("key_b", "val_b")

	names, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2, got %d", len(names))
	}
}

func TestRemoveCredential(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	store.Add("key_a", "val_a")

	err := store.Remove("key_a")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Get("key_a")
	if err == nil {
		t.Error("expected error after remove")
	}
}
```

(Add `"os"` to imports.)

- [x] **Step 2: Run test to verify it fails**

Run: `go get filippo.io/age && go test ./internal/vault/ -v`
Expected: FAIL

- [x] **Step 3: Implement store.go**

```go
// internal/vault/store.go
package vault

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

type Store struct {
	dir      string
	identity *age.X25519Identity
	recipient age.Recipient
}

func NewStore(dir string) (*Store, error) {
	credsDir := filepath.Join(dir, "credentials")
	if err := os.MkdirAll(credsDir, 0700); err != nil {
		return nil, fmt.Errorf("create credentials dir: %w", err)
	}

	keyPath := filepath.Join(dir, "vault-key.txt")
	identity, err := loadOrCreateIdentity(keyPath)
	if err != nil {
		return nil, err
	}

	return &Store{
		dir:       dir,
		identity:  identity,
		recipient: identity.Recipient(),
	}, nil
}

func loadOrCreateIdentity(path string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		id, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("parse identity: %w", err)
		}
		return id, nil
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write identity: %w", err)
	}
	return id, nil
}

func (s *Store) credPath(name string) string {
	return filepath.Join(s.dir, "credentials", name+".age")
}

func (s *Store) Add(name, value string) error {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipient)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if _, err := io.WriteString(w, value); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return os.WriteFile(s.credPath(name), buf.Bytes(), 0600)
}

func (s *Store) Get(name string) (string, error) {
	data, err := os.ReadFile(s.credPath(name))
	if err != nil {
		return "", fmt.Errorf("read credential %q: %w", name, err)
	}
	r, err := age.Decrypt(bytes.NewReader(data), s.identity)
	if err != nil {
		return "", fmt.Errorf("decrypt %q: %w", name, err)
	}
	val, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read decrypted %q: %w", name, err)
	}
	return string(val), nil
}

func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "credentials"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".age") {
			names = append(names, strings.TrimSuffix(e.Name(), ".age"))
		}
	}
	return names, nil
}

func (s *Store) Remove(name string) error {
	return os.Remove(s.credPath(name))
}
```

- [x] **Step 4: Run tests**

Run: `go test ./internal/vault/ -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/vault/ go.mod go.sum
git commit -m "feat: age-encrypted credential vault"
```

---

### Task 2: Binding resolution

**Files:**
- Create: `internal/vault/binding.go`
- Create: `internal/vault/binding_test.go`

- [x] **Step 1: Write failing test**

```go
// internal/vault/binding_test.go
package vault

import "testing"

func TestResolveBinding(t *testing.T) {
	bindings := []Binding{
		{Destination: "api.anthropic.com", Ports: []int{443}, Credential: "anthropic_key", InjectHeader: "x-api-key"},
		{Destination: "api.github.com", Ports: []int{443}, Credential: "github_token", InjectHeader: "Authorization", Template: "Bearer {value}"},
		{Destination: "*.openai.com", Ports: []int{443}, Credential: "openai_key", InjectHeader: "Authorization", Template: "Bearer {value}"},
	}

	resolver := NewBindingResolver(bindings)

	b, ok := resolver.Resolve("api.anthropic.com", 443)
	if !ok {
		t.Fatal("expected match for api.anthropic.com:443")
	}
	if b.Credential != "anthropic_key" {
		t.Errorf("expected anthropic_key, got %q", b.Credential)
	}

	b, ok = resolver.Resolve("api.openai.com", 443)
	if !ok {
		t.Fatal("expected match for api.openai.com:443")
	}
	if b.Credential != "openai_key" {
		t.Errorf("expected openai_key, got %q", b.Credential)
	}

	_, ok = resolver.Resolve("random.com", 443)
	if ok {
		t.Error("expected no match for random.com")
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -v -run TestResolveBinding`
Expected: FAIL

- [x] **Step 3: Implement binding.go**

```go
// internal/vault/binding.go
package vault

import (
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
)

type Binding struct {
	Destination  string `toml:"destination"`
	Ports        []int  `toml:"ports"`
	Credential   string `toml:"credential"`
	InjectHeader string `toml:"inject_header"`
	Template     string `toml:"template"`
	Protocol     string `toml:"protocol"`
}

type compiledBinding struct {
	glob    *policy.Glob
	ports   map[int]bool
	binding Binding
}

type BindingResolver struct {
	bindings []compiledBinding
}

func NewBindingResolver(bindings []Binding) *BindingResolver {
	compiled := make([]compiledBinding, 0, len(bindings))
	for _, b := range bindings {
		g, err := policy.CompileGlob(b.Destination)
		if err != nil {
			continue
		}
		ports := make(map[int]bool, len(b.Ports))
		for _, p := range b.Ports {
			ports[p] = true
		}
		compiled = append(compiled, compiledBinding{glob: g, ports: ports, binding: b})
	}
	return &BindingResolver{bindings: compiled}
}

func (r *BindingResolver) Resolve(dest string, port int) (Binding, bool) {
	for _, cb := range r.bindings {
		if !cb.glob.Match(dest) {
			continue
		}
		if len(cb.ports) > 0 && !cb.ports[port] {
			continue
		}
		return cb.binding, true
	}
	return Binding{}, false
}

func (b Binding) FormatValue(secret string) string {
	if b.Template == "" {
		return secret
	}
	return strings.Replace(b.Template, "{value}", secret, 1)
}
```

- [x] **Step 4: Run tests**

Run: `go test ./internal/vault/ -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/vault/binding.go internal/vault/binding_test.go
git commit -m "feat: binding resolution for credential injection"
```

---

## Chunk 2: HTTP Credential Injection + CLI Commands

### Task 3: Built-in HTTPS MITM with credential injection

**Files:**
- Create: `internal/proxy/inject.go`
- Create: `internal/proxy/inject_test.go`
- Create: `internal/proxy/ca.go`

- [x] **Step 1: CA certificate generation**

```go
// internal/proxy/ca.go
// Generates a self-signed CA on first run. Stored in vault dir.
// The CA cert is mounted into the agent container so TLS verification works.
// Uses crypto/x509 + crypto/ecdsa (P-256).
```

- [x] **Step 2: Implement in-process credential injection**

```go
// internal/proxy/inject.go
// Uses goproxy (github.com/elazarl/goproxy) as HTTPS MITM.
// On each request:
//   1. Resolve bindings for destination
//   2. Decrypt credential into SecureBytes (zeroized memory)
//   3. Byte-level find-and-replace: phantom -> real in headers + body
//   4. Release (zero) SecureBytes immediately after injection
// No IPC, no serialization, no Python runtime.
```

- [x] **Step 3: Write tests**

```go
// internal/proxy/inject_test.go
func TestPhantomSwapInHeaders(t *testing.T) {
    // Verify phantom token in Authorization header is replaced with real value
}
func TestPhantomSwapInBody(t *testing.T) {
    // Verify phantom token in request body is replaced
}
func TestCredentialZeroedAfterInjection(t *testing.T) {
    // Verify SecureBytes is zeroed after injection completes
}
```

- [x] **Step 4: Commit**

```bash
git add internal/proxy/inject.go internal/proxy/inject_test.go internal/proxy/ca.go
git commit -m "feat: built-in HTTPS MITM with zeroized credential injection"
```

---

### Task 4: CLI commands for vault management

**Files:**
- Modify: `cmd/sluice/main.go`

- [x] **Step 1: Add subcommands for credential management**

Add to main.go (or split into `cmd/sluice/cred.go`):

```go
// Handle subcommands before proxy startup
if len(os.Args) > 1 {
	switch os.Args[1] {
	case "cred":
		handleCredCommand(os.Args[2:])
		return
	case "proxy":
		// Continue to proxy startup (existing code)
	default:
		// Default to proxy mode for backwards compat
	}
}
```

Implement `handleCredCommand`:

```go
func handleCredCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice cred [add|list|remove] ...")
		os.Exit(1)
	}

	vaultDir := os.Getenv("SLUICE_VAULT_DIR")
	if vaultDir == "" {
		home, _ := os.UserHomeDir()
		vaultDir = filepath.Join(home, ".sluice")
	}

	store, err := vault.NewStore(vaultDir)
	if err != nil {
		log.Fatalf("open vault: %v", err)
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("usage: sluice cred add <name>")
			os.Exit(1)
		}
		fmt.Print("Enter secret: ")
		secret, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err := store.Add(args[1], string(secret)); err != nil {
			log.Fatalf("add credential: %v", err)
		}
		fmt.Printf("credential %q added\n", args[1])

	case "list":
		names, err := store.List()
		if err != nil {
			log.Fatalf("list: %v", err)
		}
		for _, n := range names {
			fmt.Println(n)
		}

	case "remove":
		if len(args) < 2 {
			fmt.Println("usage: sluice cred remove <name>")
			os.Exit(1)
		}
		if err := store.Remove(args[1]); err != nil {
			log.Fatalf("remove: %v", err)
		}
		fmt.Printf("credential %q removed\n", args[1])
	}
}
```

- [x] **Step 2: Test manually** (verified via build and test suite)

```bash
go build -o sluice ./cmd/sluice/
./sluice cred add github_token     # type secret, hit enter
./sluice cred list                 # should show github_token
./sluice cred remove github_token
./sluice cred list                 # should be empty
```

- [x] **Step 3: Commit**

```bash
git add cmd/
git commit -m "feat: CLI commands for credential vault management"
```

---

## Chunk 3: Secure Memory Handling

### Task 5: Zeroize credentials after use

Decrypted credentials currently live in Go strings on the heap with no
secure clearing. Borrowed from nono's approach (Rust `Zeroizing<String>`).
Go doesn't have a direct equivalent, but we can use `[]byte` with explicit
zeroing after use.

**Files:**
- Create: `internal/vault/secure.go`
- Create: `internal/vault/secure_test.go`
- Modify: `internal/vault/store.go` (return `SecureBytes` instead of `string`)
- Modify: `mitmproxy-addons/inject_creds.py` (clear value after injection)

- [x] **Step 1: Implement SecureBytes type**

```go
// internal/vault/secure.go
package vault

import "unsafe"

// SecureBytes holds a credential value and zeroes it on Release.
// Use Release() as soon as the value is no longer needed.
type SecureBytes struct {
	data []byte
}

func NewSecureBytes(val string) SecureBytes {
	b := make([]byte, len(val))
	copy(b, val)
	return SecureBytes{data: b}
}

func (s SecureBytes) String() string {
	return string(s.data)
}

func (s SecureBytes) Bytes() []byte {
	return s.data
}

// Release zeroes the underlying memory. Safe to call multiple times.
func (s *SecureBytes) Release() {
	for i := range s.data {
		s.data[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing.
	_ = *(*byte)(unsafe.Pointer(&s.data[0]))
}
```

- [x] **Step 2: Update Store.Get to return SecureBytes**

Change `Store.Get` signature from `(string, error)` to `(SecureBytes, error)`.
Callers must call `Release()` after using the credential.

- [x] **Step 3: Update inject.go to use SecureBytes**

Modify `internal/proxy/inject.go` to use `SecureBytes` for decrypted
credentials. Call `Release()` immediately after injection completes.
The credential should never remain in memory longer than the single
request handling duration.

- [x] **Step 4: Tests**

```go
func TestSecureBytesRelease(t *testing.T) {
	s := NewSecureBytes("super-secret-key")
	if s.String() != "super-secret-key" {
		t.Fatal("value mismatch before release")
	}
	s.Release()
	for _, b := range s.Bytes() {
		if b != 0 {
			t.Fatal("memory not zeroed after release")
		}
	}
}
```

Run: `go test ./internal/vault/ -v -run TestSecureBytes`

- [x] **Step 5: Commit**

```bash
git add internal/vault/secure.go internal/vault/secure_test.go
git commit -m "feat: zeroizing secure memory for decrypted credentials"
```

---

## Chunk 4: External Credential Provider Integration (optional)

### Task 6: Provider interface for pluggable credential backends

The age-encrypted file vault is the default and works offline with zero
deps. For teams or production deployments, support external credential
providers as optional backends. The agent still never sees real
credentials. Sluice resolves them at injection time from whatever backend
is configured.

**Supported providers (planned):**

| Provider | Use case | Auth |
|----------|----------|------|
| **age files** (default) | Solo/dev, zero deps, offline | Vault key on disk |
| **HashiCorp Vault** | Enterprise, dynamic secrets, lease rotation | Token or AppRole |
| **Bitwarden** (via Agent Access SDK) | Teams already using Bitwarden | API key |
| **1Password** (via Connect SDK) | Teams already using 1Password | Connect token |
| **AWS Secrets Manager** | AWS-native deployments | IAM role |
| **Environment variables** | CI/CD, simple deployments | N/A |

**Files:**
- Create: `internal/vault/provider.go` (interface)
- Create: `internal/vault/provider_age.go` (existing store, refactored)
- Create: `internal/vault/provider_env.go` (env var provider)
- Create: `internal/vault/provider_hashicorp.go` (HashiCorp Vault)

- [x] **Step 1: Define provider interface**

```go
// internal/vault/provider.go
package vault

// Provider resolves credential values by name. Implementations handle
// authentication, caching, and lease renewal internally.
type Provider interface {
	// Get retrieves a credential. Returns SecureBytes that must be
	// Released after use.
	Get(name string) (SecureBytes, error)

	// List returns available credential names. Optional. Providers
	// that don't support listing return nil, nil.
	List() ([]string, error)

	// Name returns the provider identifier for logging/config.
	Name() string
}
```

- [x] **Step 2: Refactor age store to implement Provider**

Rename existing `Store` methods to satisfy the `Provider` interface.
`Add`/`Remove` remain age-specific (external providers manage their
own storage).

- [x] **Step 3: Implement env var provider**

```go
// internal/vault/provider_env.go
package vault

import "os"

type EnvProvider struct{}

func (p *EnvProvider) Get(name string) (SecureBytes, error) {
	val := os.Getenv(name)
	if val == "" {
		return SecureBytes{}, fmt.Errorf("env var %q not set", name)
	}
	return NewSecureBytes(val), nil
}

func (p *EnvProvider) List() ([]string, error) { return nil, nil }
func (p *EnvProvider) Name() string            { return "env" }
```

- [x] **Step 4: Implement HashiCorp Vault provider**

```go
// internal/vault/provider_hashicorp.go
package vault

// Uses github.com/hashicorp/vault/api
// Config: VAULT_ADDR, VAULT_TOKEN (or AppRole via VAULT_ROLE_ID + VAULT_SECRET_ID)
// Reads from kv-v2 engine at configurable mount path.
// Supports lease renewal for dynamic secrets.
```

- [x] **Step 5: Provider selection in config**

```toml
# policy.toml
[vault]
provider = "age"           # age | env | hashicorp | bitwarden | 1password | aws

# HashiCorp Vault specific
[vault.hashicorp]
addr = "https://vault.internal:8200"
mount = "sluice"           # KV v2 mount path
auth = "approle"           # token | approle
role_id_env = "VAULT_ROLE_ID"
secret_id_env = "VAULT_SECRET_ID"
```

- [x] **Step 6: Multi-provider chaining (optional)**

Allow fallback: try HashiCorp first, fall back to age files.

```toml
[vault]
providers = ["hashicorp", "age"]   # try in order
```

- [x] **Step 7: Commit**

```bash
git add internal/vault/provider*.go
git commit -m "feat: pluggable credential provider interface with age, env, and HashiCorp Vault backends"
```

---

## Chunk 5: Non-HTTP Protocol Credential Injection

### Task 7: SSH credential injection (jump host mode)

The SOCKS5 proxy detects SSH connections (port 22) via Plan 1's protocol
detection. For SSH, Sluice acts as a jump host: it accepts the SOCKS5
connection, authenticates to the upstream SSH server using the real key
from the vault, and relays the connection.

**Files:**
- Create: `internal/proxy/ssh.go`
- Create: `internal/proxy/ssh_test.go`

- [ ] **Step 1: Implement SSH jump host handler**

```go
// internal/proxy/ssh.go
// When protocol == ProtoSSH and a credential binding exists:
// 1. Decrypt SSH private key from vault into SecureBytes
// 2. Dial upstream SSH server using real key
// 3. Relay bytes between agent connection and upstream
// 4. Zero the key memory immediately after handshake
//
// Uses golang.org/x/crypto/ssh for SSH client.
// The agent's SSH client sees a successful connection without ever
// having the real private key.
```

- [ ] **Step 2: Write tests using in-process SSH server**

```go
func TestSSHJumpHostInjectsKey(t *testing.T) {
    // Start test SSH server accepting a specific public key
    // Configure vault with matching private key
    // Connect through Sluice SOCKS5
    // Verify connection succeeds (agent had no key, Sluice injected it)
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/proxy/ -v -run TestSSH`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/ssh.go internal/proxy/ssh_test.go
git commit -m "feat: SSH credential injection via jump host mode"
```

---

### Task 8: IMAP/SMTP credential injection

For IMAP (port 143/993) and SMTP (port 25/587/465), Sluice proxies the
AUTH command and swaps the phantom password for the real one.

**Files:**
- Create: `internal/proxy/mail.go`
- Create: `internal/proxy/mail_test.go`

- [ ] **Step 1: Implement IMAP/SMTP AUTH proxy**

```go
// internal/proxy/mail.go
// For IMAP:
//   - Relay connection normally until LOGIN or AUTHENTICATE command
//   - Detect phantom password in the command
//   - Replace with real password from vault
//   - Forward modified command to upstream
//   - Zero credential memory
//
// For SMTP:
//   - Relay until AUTH LOGIN or AUTH PLAIN
//   - Decode base64, swap phantom for real, re-encode
//   - Forward to upstream
//   - Zero credential memory
```

- [ ] **Step 2: Write tests**

```go
func TestIMAPAuthSwap(t *testing.T) {
    // Test IMAP LOGIN command: phantom password -> real password
}
func TestSMTPAuthPlainSwap(t *testing.T) {
    // Test SMTP AUTH PLAIN: base64-decoded phantom -> real, re-encoded
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/proxy/ -v -run TestIMAP && go test ./internal/proxy/ -v -run TestSMTP`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/mail.go internal/proxy/mail_test.go
git commit -m "feat: IMAP/SMTP credential injection via AUTH command proxy"
```
