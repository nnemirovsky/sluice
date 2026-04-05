# macOS VM Backend via tart

## Overview

Add a macOS VM backend using `tart` CLI for running OpenClaw in a macOS guest VM with access to Apple frameworks (iMessage, EventKit, Keychain, Shortcuts). This is the third container backend alongside Docker and Apple Container (Linux). The macOS VM runs OpenClaw with full Apple ecosystem access while sluice governs all network traffic through pf rules + tun2proxy.

**Problem:** Apple Container (Plan 16) runs Linux containers. They cannot access Apple frameworks. For AI agents that need to interact with iMessage, Calendar, Reminders, FaceTime, or other Apple services, a macOS guest VM is required.

**Solution:** Add a `TartManager` implementing the existing `ContainerManager` interface, wrapping the `tart` CLI. Sluice can run anywhere (host, Docker, Apple Container). tun2proxy runs on the host. pf rules redirect macOS VM traffic through tun2proxy to sluice's SOCKS5 proxy.

**Architecture:**
```
Host (macOS):
  tun2proxy (native)     -- creates TUN device, routes to SOCKS5
  pf rules               -- redirect VM bridge traffic to TUN device

Docker / Apple Container / host:
  sluice                 -- SOCKS5 proxy + MCP gateway + API

macOS VM (tart):
  OpenClaw               -- has iMessage, EventKit, Keychain, etc.
  Traffic: bridge100 -> pf -> tun2proxy -> SOCKS5 -> sluice -> internet
```

**EULA note:** macOS EULA allows 2 additional macOS VM instances per Apple-branded host. Only OpenClaw runs in a macOS VM. sluice and tun2proxy are host processes or Linux containers and do not count.

## Context (from discovery)

**Existing infrastructure to reuse:**
- `container.ContainerManager` interface (Plan 16) -- TartManager implements this
- `container.NetworkRouter` for pf rules (Plan 16) -- same bridge routing
- VirtioFS volume sharing for phantom tokens and CA certs
- `container exec` pattern maps directly to `tart exec`

**Files/components involved:**
- `internal/container/types.go` -- Runtime enum, ContainerManager interface
- `internal/container/tart.go` -- new: TartManager
- `internal/container/network.go` -- reuse pf routing (NetworkRouter, SetupNetworkRouting)
- `cmd/sluice/main.go` -- runtime selection
- `e2e/macos_vm_test.go` -- macOS VM e2e tests (separate from apple_test.go)

**Dependencies:**
- `tart` CLI (Homebrew: `brew install cirruslabs/cli/tart`)
- macOS with Apple Silicon (M1+)
- tun2proxy on host

**tart CLI mapping:**
```
tart clone <image> <name>     -- create VM from OCI image (can take minutes for macOS images)
tart run <name> --dir=... --no-graphics  -- start VM (BLOCKING: runs until VM shuts down, must use cmd.Start not cmd.Run)
tart exec <name> -- <cmd>     -- run command inside VM (requires tart agent in guest)
tart stop <name>              -- stop VM
tart delete <name>            -- remove VM
tart list --format json       -- list VMs as JSON
tart ip <name>                -- get VM IP address
```

**tart agent requirement:** `tart exec` requires the tart helper agent running inside the guest VM. The `--vm-image` should be an OCI image with the tart agent pre-installed (e.g., images from cirruslabs).

**tun2proxy lifecycle:** Sluice does NOT manage tun2proxy. The user must start tun2proxy on the host before running `--runtime macos`. Create `scripts/macos-vm-setup.sh` that starts tun2proxy, applies pf rules, and enables IP forwarding. Sluice logs a warning if tun2proxy is not reachable.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task
- Do NOT create new migration files. Edit 000001_init.up.sql if schema changes needed (they shouldn't be).
- Reuse existing `ContainerManager` interface and `NetworkRouter` from Plan 16.

## Testing Strategy

- **Unit tests**: TartManager with mock exec (CommandRunner interface from Apple Container backend). All tests run on any platform.
- **E2e tests**: `//go:build e2e && darwin` tag. Skip if `tart` not installed.

## Solution Overview

TartManager wraps the `tart` CLI the same way AppleManager wraps the `container` CLI. Both use the `CommandRunner` interface for testability. The `--runtime macos` flag selects TartManager. Network routing reuses the same pf + tun2proxy approach from Plan 16 since macOS VMs also use a bridge interface.

Key difference from Apple Container: macOS VMs need `security add-trusted-cert` for CA injection (Keychain-based trust) instead of `update-ca-certificates` (Linux cert bundle).

## Technical Details

### Runtime comparison

| Feature | Docker | Apple Container | macOS VM (tart) |
|---------|--------|----------------|-----------------|
| Guest OS | Linux | Linux | macOS |
| Isolation | Namespaces | Hypervisor micro-VM | Hypervisor VM |
| Boot time | ~1s | Sub-second | 2-4 seconds |
| Memory | ~50MB | ~50MB | 1.5-2GB |
| Apple frameworks | No | No | Yes |
| CLI tool | docker | container | tart |
| Network routing | tun2proxy container | pf + tun2proxy host | pf + tun2proxy host |
| EULA limit | Unlimited | Unlimited | 2 macOS VMs |

### Volume sharing

```bash
# tart VirtioFS
tart run openclaw \
  --dir=phantoms:/path/to/phantoms \
  --dir=ca:/path/to/ca \
  --no-graphics
```

### CA cert injection (macOS guest)

```bash
tart exec openclaw -- security add-trusted-cert \
  -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  /Volumes/ca/sluice-ca.crt
```

## Implementation Steps

### Task 1: Add RuntimeMacOS to enum and detect tart

**Files:**
- Modify: `internal/container/types.go`
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/main_test.go`

- [ ] Add `RuntimeMacOS Runtime = 3` to the Runtime enum with `String()` returning `"macos"` (value 2 is already RuntimeNone)
- [ ] Add `"macos"` to `--runtime` flag accepted values in main.go
- [ ] Update `detectRuntime`: add `tartAvailable bool` parameter. Auto-detection priority: `apple` > `docker` (unchanged). `macos` (tart) is explicit-only via `--runtime macos` because macOS VMs are heavyweight (2-4s boot, 1.5GB+ RAM) and auto-selecting them would be surprising. Update all `detectRuntime` call sites.
- [ ] Add `--vm-image` flag for specifying the OCI image for tart (e.g., `ghcr.io/cirruslabs/macos-sequoia-base:latest`)
- [ ] Write tests for runtime detection with tart available / not available
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 2: Implement TartManager CLI wrapper

**Files:**
- Create: `internal/container/tart.go`
- Create: `internal/container/tart_test.go`

- [ ] Implement `TartManager` struct using the existing `CommandRunner` interface for testability (same pattern as `AppleManager`)
- [ ] Implement `tart clone` for creating VM from OCI image
- [ ] Implement `tart run` with `--dir` flags for VirtioFS volumes and `--no-graphics` for headless. IMPORTANT: `tart run` is a BLOCKING command (unlike `container run`). Must use `cmd.Start()` (not `cmd.Run()`) and manage the process in a background goroutine. Add a `StartBackground(name string, args ...string) (*exec.Cmd, error)` method to CommandRunner or use a separate launch path.
- [ ] Implement `tart exec` for running commands inside the VM (requires tart agent in guest image)
- [ ] Implement `tart stop` and `tart delete` for lifecycle management
- [ ] Implement `tart list --format json` and `tart ip` for status and IP retrieval (parse JSON output, not table)
- [ ] Check if `tart` binary exists on creation (clear error if not installed)
- [ ] Write tests with mock CommandRunner (capture commands, return canned output)
- [ ] Write tests for error cases (binary not found, VM not running, exec failure)
- [ ] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 3: Implement ContainerManager interface

**Files:**
- Modify: `internal/container/tart.go`
- Modify: `internal/container/tart_test.go`

- [ ] Implement `ReloadSecrets`: write phantom token files to VirtioFS shared directory, run `tart exec <name> -- openclaw secrets reload`
- [ ] Implement `RestartWithEnv`: stop VM, then re-run with new env (NOT delete+clone, which takes minutes for macOS images). tart VMs persist state across stop/run cycles.
- [ ] Implement `InjectMCPConfig`: write mcp-servers.json to VirtioFS shared directory, run `tart exec <name> -- openclaw mcp reload`
- [ ] Implement `Status`: run `tart list`, parse VM state and IP
- [ ] Implement `Stop`: run `tart stop`
- [ ] Implement `Runtime()`: return `RuntimeMacOS`
- [ ] Write tests for each ContainerManager method with mock CommandRunner
- [ ] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 4: CA cert injection for macOS VM

**Files:**
- Modify: `internal/container/tart.go`
- Modify: `internal/container/tart_test.go`

- [ ] Add `InjectCACert(ctx context.Context, hostCertPath, guestCertDir string) error` to the `ContainerManager` interface. Implement no-op on `DockerManager` (Docker handles CA via compose volumes). Implement on `AppleManager` using `update-ca-certificates`. Implement on `TartManager` using `security add-trusted-cert`.
- [ ] TartManager.InjectCACert: copy CA cert to VirtioFS shared volume, run `tart exec <name> -- security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /Volumes/ca/sluice-ca.crt`
- [ ] Set `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` env vars as fallback for tools that don't use Keychain
- [ ] Call `containerMgr.InjectCACert()` after VM/container startup in main.go (works for all backends via interface)
- [ ] Write tests for cert injection command generation
- [ ] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 5: Network routing for macOS VM

**Files:**
- Modify: `internal/container/tart.go`
- Modify: `internal/container/network.go` (refactor DefaultBridgeInterface to accept generic IP getter)
- Create: `scripts/macos-vm-setup.sh`

- [ ] After VM starts, get its IP via `tart ip <name>`
- [ ] Refactor `DefaultBridgeInterface` to accept a function `func() (string, error)` for getting VM IP instead of requiring `*AppleCLI`. This allows both AppleManager and TartManager to use the same routing code.
- [ ] Call `NetworkRouter.SetupNetworkRouting(ctx, vmIP, bridgeIface, tunGateway)` with correct signature (4 params, not 2)
- [ ] On shutdown, call `TeardownNetworkRouting()` to clean up pf rules
- [ ] Create `scripts/macos-vm-setup.sh` that starts tun2proxy on the host, enables IP forwarding, and documents the required setup
- [ ] Log warning if tun2proxy is not running on host (check if TUN device exists)
- [ ] Write tests for routing setup with mock VM IP
- [ ] Run tests: `go test ./internal/container/ -v -timeout 30s`

### Task 6: Wire TartManager into main.go startup

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/main_test.go`

- [ ] When `--runtime macos`: create `TartManager`. Startup sequence: (1) `tart list --format json` to check if VM exists, (2) if not, `tart clone <--vm-image> <--container-name>` (warn user this may take minutes for macOS images), (3) `tart run` in background goroutine, (4) wait for VM IP via `tart ip`, (5) set up pf routing, (6) inject CA cert via `InjectCACert`.
- [ ] Pass `TartManager` as `ContainerManager` to Telegram commands, API server, MCP auto-injection
- [ ] On shutdown: stop VM, tear down pf rules
- [ ] Write tests for macos runtime startup path (mock tart CLI)
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 7: Verify acceptance criteria

- [ ] Verify `--runtime macos` starts a macOS VM via tart
- [ ] Verify VM gets its own IP and pf rules are applied
- [ ] Verify traffic from macOS VM routes through tun2proxy -> sluice SOCKS5
- [ ] Verify CA cert is trusted by the macOS VM (Keychain-based)
- [ ] Verify credential hot-reload works (phantom files + tart exec)
- [ ] Verify MCP auto-injection works (mcp-servers.json + tart exec)
- [ ] Verify Docker and Apple Container backends still work (no regression)
- [ ] Verify `--runtime macos` requires explicit flag (not auto-detected)
- [ ] Verify Docker and Apple Container regressions: `go test ./internal/container/ -v -timeout 30s`
- [ ] Run full test suite: `go test ./... -v -timeout 60s`
- [ ] Run linter: `go vet ./...`

### Task 8: [Final] Update documentation

- [ ] Update CLAUDE.md: document macOS VM backend, tart CLI, --runtime macos
- [ ] Update CLAUDE.md: correct Apple framework access claims (macOS VM only, not Apple Container)
- [ ] Update CLAUDE.md: add RuntimeMacOS to runtime comparison table
- [ ] Update CONTRIBUTING.md: note tart requirement for macOS VM testing
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification (requires macOS with tart installed):**
- Clone a macOS base image and run OpenClaw in it
- Verify Apple framework access (open Messages.app, create a Reminder)
- Verify sluice governs all network traffic from the VM
- Verify credential injection and MCP auto-injection work
- Test pf rule cleanup on sluice shutdown

**Future considerations:**
- Snapshot and restore macOS VMs for fast startup
- Pre-built OpenClaw macOS OCI images in a registry
- Multiple macOS VMs (agent pool) within EULA limits
- Host-to-VM communication via virtio-vsock for low-latency MCP
