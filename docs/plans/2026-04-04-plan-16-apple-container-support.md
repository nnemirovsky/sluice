# Plan 16: Apple Container Support

## Overview

Add Apple Container (macOS Virtualization.framework micro-VMs) as a deployment target alongside Docker. This enables running OpenClaw with access to native Apple infrastructure (Reminders, iMessage, Calls, Shortcuts) while sluice governs all network access, credentials, and MCP tools.

**Problem:** Docker containers run Linux. They cannot access Apple frameworks (EventKit, Messages, CallKit). Users who want an AI agent with Apple ecosystem integration must run OpenClaw on macOS, losing sluice's governance. Apple Container (WWDC 2025) runs macOS-compatible micro-VMs with sub-second boot, but sluice has no support for this runtime.

**Solution:** Add an Apple Container backend that manages VMs via the `container` CLI, routes VM traffic through sluice using macOS pf rules + tun2proxy on the host, and handles credential injection via shared volumes + `container exec`.

**Depends on:** Plan 9 (Channel interface, store), Plan 14 (MCP auto-injection). Core proxy functionality (Plans 8, 11) should be done first.

## Context

**Architecture comparison:**

```
Docker:
  OpenClaw container -> tun2proxy container -> SOCKS5 -> sluice container -> internet
  (shared network namespace, all in containers)

Apple Container:
  OpenClaw micro-VM (bridge100) -> pf route-to -> tun2proxy on host -> SOCKS5 -> sluice on host -> internet
  (pf rules on host bridge interface, tun2proxy + sluice run natively)
```

**Key research findings (2026-04-04):**
- `/dev/net/tun` NOT supported inside Apple Container guests. tun2proxy must run on host.
- `container exec` works for running commands inside VMs (like docker exec)
- VMs get unique IPs on `bridge100` interface visible to host
- macOS pf `route-to` rules can redirect VM traffic to a TUN device
- Volumes via VirtioFS (`-v` flag)
- Env vars via `-e` flag
- No Go SDK. CLI wrapping via `os/exec` is the standard approach.

**Files that will change:**
- Create: `internal/container/apple.go` -- Apple Container backend (CLI wrapper)
- Create: `internal/container/apple_test.go`
- Create: `internal/container/types.go` -- shared types for Docker and Apple backends
- Create: `scripts/apple-container-setup.sh` -- pf rules + tun2proxy setup
- Modify: `internal/docker/manager.go` -- extract ContainerRuntime interface
- Modify: `internal/proxy/protocol.go` -- add ProtoAPNS for Apple Push Notification port 5223
- Modify: `cmd/sluice/main.go` -- runtime selection (docker vs apple)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: CLI wrapper with mock exec, pf rule generation.
- **Integration tests**: Require macOS host with Apple Container installed. Marked with build tag `//go:build darwin`.

## Implementation Steps

### Task 1: Extract ContainerRuntime interface from Docker manager

Refactor the existing Docker-specific Manager into a shared interface that both Docker and Apple Container backends can implement.

**Files:**
- Create: `internal/container/types.go`
- Modify: `internal/docker/manager.go`
- Modify: `cmd/sluice/main.go`

```go
// internal/container/types.go
type Runtime int

const (
    RuntimeDocker Runtime = 0
    RuntimeApple  Runtime = 1
)

type ContainerManager interface {
    // Credential management
    ReloadSecrets(ctx context.Context, phantomDir string, phantomEnv map[string]string) error
    RestartWithEnv(ctx context.Context, env map[string]string) error
    
    // MCP injection
    InjectMCPConfig(phantomDir, sluiceURL string) error
    
    // Lifecycle
    Status(ctx context.Context) (ContainerStatus, error)
    Stop(ctx context.Context) error
    
    // Runtime info
    Runtime() Runtime
}
```

- [x] Create `internal/container/types.go` with `Runtime` enum, `ContainerManager` interface, and `ContainerStatus` struct
- [x] Refactor `internal/docker/manager.go` to implement `container.ContainerManager`
- [x] Update `cmd/sluice/main.go` to use `container.ContainerManager` interface instead of `*docker.Manager`
- [x] Update all callers (Telegram commands, etc.) to use the interface
- [x] Write tests verifying Docker manager satisfies the interface
- [x] Run tests: `go test ./... -v -timeout 30s`

### Task 2: Apple Container CLI wrapper

Wrap the `container` CLI for managing Apple Container micro-VMs.

**Files:**
- Create: `internal/container/apple.go`
- Create: `internal/container/apple_test.go`

- [x] Implement `AppleManager` struct wrapping `container` CLI via `os/exec`
- [x] Implement `container run -e KEY=VAL -v /host:/guest <image>` for starting VMs
- [x] Implement `container exec <name> <cmd>` for running commands inside VMs
- [x] Implement `container stop <name>` and `container rm <name>`
- [x] Implement `container inspect <name>` parsing JSON output for status, IP address, mounts
- [x] Implement `container ls` for listing running VMs
- [x] Check if `container` binary exists on creation (return clear error if not installed)
- [x] Write tests with mock exec (capture commands, return canned responses)
- [x] Write tests for error cases (binary not found, VM not running, exec failure)
- [x] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 3: Implement ContainerManager for Apple Container

Wire the CLI wrapper into the ContainerManager interface. Handle credential injection via shared volume + exec.

**Files:**
- Modify: `internal/container/apple.go`
- Modify: `internal/container/apple_test.go`

- [x] Implement `ReloadSecrets`: write phantom token files to shared volume, run `container exec <name> openclaw secrets reload`
- [x] Implement `RestartWithEnv`: stop VM, remove, recreate with new env vars (fallback if exec fails)
- [x] Implement `InjectMCPConfig`: write mcp-servers.json to shared volume, run `container exec <name> openclaw mcp reload`
- [x] Implement `Status`: run `container inspect`, parse running state, IP, health
- [x] Implement `Stop`: run `container stop`
- [x] Implement `Runtime()`: return `RuntimeApple`
- [x] Write tests for each method with mock exec
- [x] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 4: Network routing via pf + tun2proxy on host

Create a setup script and Go helper to configure macOS pf rules that redirect Apple Container VM traffic through sluice's SOCKS5 proxy.

**Files:**
- Create: `scripts/apple-container-setup.sh`
- Create: `internal/container/network_darwin.go`
- Create: `internal/container/network_darwin_test.go`

**pf routing flow:**
```
1. Apple Container VM gets IP on bridge100 (e.g., 192.168.64.2)
2. tun2proxy runs on host: tun2proxy --proxy socks5://127.0.0.1:1080 --tun utun3
3. pf rule: pass in on bridge100 route-to utun3 from 192.168.64.0/24 to any
4. All VM traffic goes: bridge100 -> utun3 -> tun2proxy -> SOCKS5 -> sluice
```

- [x] Implement `SetupNetworkRouting(vmIP, sluiceAddr string) error` that generates and loads pf anchor rules
- [x] Implement `TeardownNetworkRouting() error` that removes pf rules
- [x] Create `scripts/apple-container-setup.sh` for manual setup (detect bridge interface, start tun2proxy, apply pf rules, enable IP forwarding)
- [x] Handle `sudo` requirement for pf rules (script must run as root or with sudo)
- [x] Detect the bridge interface dynamically (bridge100, bridge101, etc.) from `container inspect` network info
- [x] Add `ProtoAPNS Protocol = "apns"` to protocol enum for Apple Push Notification Service (port 5223). Enables rules like `[[allow]] destination = "*.push.apple.com" ports = [5223] protocols = ["apns"]`
- [x] Write tests for pf rule generation (verify correct anchor syntax)
- [x] Write test for APNS protocol detection on port 5223
- [x] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 5: CA certificate injection for Apple Container

Inject sluice's MITM CA cert into the Apple Container VM's trust store. Different path than Docker volume mount.

**Files:**
- Modify: `internal/container/apple.go`

- [x] On VM startup: copy sluice's CA cert to VM via shared volume
- [x] Run `container exec <name> update-ca-certificates` (or equivalent for the VM's OS)
- [x] Set `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` env vars pointing to the cert
- [x] Verify HTTPS connections from within the VM trust sluice's CA
- [x] Write tests for cert injection flow
- [x] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 6: Runtime selection in main.go and CLI

Add `--runtime docker|apple` flag. Auto-detect based on available tools.

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/main_test.go`

- [x] Add `--runtime` flag with values `docker`, `apple`, `auto` (default: auto)
- [x] Auto-detection: check if `container` binary exists (Apple), check if Docker socket exists (Docker). Prefer Apple on macOS if both available.
- [x] Pass the selected `ContainerManager` to Telegram commands and MCP auto-injection
- [x] Add `--container-name` flag (default: "openclaw") shared by both runtimes
- [x] Add `--vm-image` flag for Apple Container (the OCI image to run)
- [x] Write tests for auto-detection logic
- [x] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 7: Sluice native mode (no container runtime)

Support running sluice as a standalone proxy on macOS without any container runtime. Useful for development or when the user runs OpenClaw directly on the host.

**Files:**
- Modify: `cmd/sluice/main.go`

- [x] When `--runtime none`: skip container manager initialization entirely
- [x] Sluice runs as SOCKS5 proxy + MCP gateway only
- [x] User manually configures `ALL_PROXY=socks5://localhost:1080` in their shell
- [x] Credential injection still works (MITM proxy runs, just no automatic container management)
- [x] MCP gateway still works (stdio upstreams as child processes)
- [x] Write tests for standalone mode startup
- [x] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 8: Verify acceptance criteria

- [x] Verify Apple Container VM starts with correct env vars and volumes
- [x] Verify pf rules redirect VM traffic through tun2proxy to sluice SOCKS5
- [x] Verify HTTPS MITM works (CA cert trusted by VM)
- [x] Verify credential hot-reload via shared volume + container exec
- [x] Verify MCP auto-injection works (mcp-servers.json in shared volume)
- [x] Verify APNS protocol detected on port 5223 and rules with `protocols = ["apns"]` match
- [x] Verify Apple service traffic (iCloud, iMessage signaling) routes through sluice
- [x] Verify Docker backend still works (no regression)
- [x] Verify auto-detection picks correct runtime
- [x] Verify standalone mode (no container runtime) works
- [x] Run full test suite: `go test ./... -v -timeout 60s`
- [x] Run linter: `go vet ./...`

### Task 9: [Final] Update documentation

- [ ] Update CLAUDE.md: document Apple Container support, runtime selection, pf routing
- [ ] Update CLAUDE.md: document standalone mode
- [ ] Create `docs/apple-container-quickstart.md` with setup instructions
- [ ] Update CONTRIBUTING.md: note macOS-specific build tags and testing requirements
- [ ] Update README.md: mention Apple Container as a deployment option

## Technical Details

### pf anchor rules

```pf
# /etc/pf.anchors/sluice
vm_bridge = "bridge100"
proxy_tun = "utun3"

# Route all VM traffic through tun2proxy
pass in on $vm_bridge route-to ($proxy_tun 192.168.64.1) from 192.168.64.0/24 to any

# Allow return traffic
pass out on $vm_bridge from any to 192.168.64.0/24
```

### Host-side setup sequence

```
1. Start sluice: sluice --listen 127.0.0.1:1080 --runtime apple --container-name openclaw
2. Sluice starts SOCKS5 on :1080, MCP gateway on :3000
3. Sluice starts tun2proxy: tun2proxy --proxy socks5://127.0.0.1:1080 --tun utun3
4. Sluice applies pf rules to redirect bridge100 traffic to utun3
5. Sluice starts Apple Container VM:
   container run --name openclaw \
     -e SSL_CERT_FILE=/certs/sluice-ca.crt \
     -v ~/.sluice/ca:/certs:ro \
     -v ~/.sluice/phantoms:/phantoms:ro \
     openclaw/openclaw:latest
6. Sluice injects MCP config to /phantoms/mcp-servers.json
7. Sluice triggers: container exec openclaw openclaw mcp reload
8. OpenClaw connects to sluice:3000/mcp (routed through pf -> tun2proxy -> SOCKS5)
9. All OpenClaw network traffic is governed by sluice
```

### Runtime comparison

| Feature | Docker | Apple Container | Standalone |
|---------|--------|----------------|------------|
| Container isolation | Linux namespaces | Hypervisor micro-VM | None |
| Network routing | tun2proxy container + shared NS | pf rules + tun2proxy on host | Manual ALL_PROXY |
| Credential reload | docker exec + shared volume | container exec + shared volume | N/A |
| Apple frameworks | No | Yes (EventKit, Messages, CallKit) | Yes (host native) |
| APNS protocol | N/A (no Apple services) | Yes (port 5223 detection) | Yes |
| Platform | Linux, macOS (Docker Desktop) | macOS only | Any |
| Setup complexity | Low (docker compose up) | Medium (pf rules, sudo) | Low |

### ContainerManager implementations

```
container.ContainerManager (interface)
  |
  +-- docker.Manager (existing, wraps Docker socket API)
  |
  +-- container.AppleManager (new, wraps `container` CLI)
```

Both implement the same interface. Telegram commands, MCP injection, and credential management code doesn't change. Only the runtime selection in main.go differs.

## Post-Completion

**Manual verification (requires macOS with Apple Container):**
- Install Apple Container runtime
- Run sluice with `--runtime apple`
- Verify OpenClaw VM starts and all traffic routes through sluice
- Test Apple framework access from within the VM (Reminders, Messages)
- Verify credential injection and MCP auto-injection work
- Test pf rule cleanup on sluice shutdown

**Future considerations:**
- Multiple VMs (agent pool) managed by sluice
- Apple Container Compose-like orchestration (if Apple ships one)
- Rosetta 2 support for running x86 MCP servers in ARM VMs
- Integration with macOS Shortcuts for agent automation
