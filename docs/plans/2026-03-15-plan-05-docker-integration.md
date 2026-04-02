# Sluice Plan 5: Docker Integration

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a production-ready docker-compose setup that runs OpenClaw + tun2proxy + Sluice, with all traffic transparently intercepted. Include example policy, vault setup script, and documentation.

**Architecture:** Three containers sharing a network namespace via `network_mode: "service:sluice"`. tun2proxy creates a TUN interface routing all TCP to Sluice's SOCKS5 port. OpenClaw runs with phantom tokens. Sluice container has access to both internal (agent) and external (internet) networks.

**Tech Stack:** Docker, docker-compose, shell scripts

**Depends on:** Plans 1-4

---

## File Structure

```
sluice/
  Dockerfile
  docker-compose.yml
  docker-compose.dev.yml     # Development overrides
  scripts/
    setup-vault.sh           # Interactive credential setup
    gen-phantom-env.sh       # Generate phantom token env file
  examples/
    policy.toml              # Example policy for OpenClaw
    openclaw-config/         # Minimal OpenClaw config
```

---

## Chunk 1: Docker Setup

### Task 1: Dockerfile for Sluice

**Files:**
- Create: `Dockerfile`

- [x] **Step 1: Write multi-stage Dockerfile**

```dockerfile
FROM golang:1.22-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sluice ./cmd/sluice/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /bin/bash sluice
COPY --from=builder /sluice /usr/local/bin/sluice
USER sluice
WORKDIR /home/sluice
EXPOSE 1080 3000
ENTRYPOINT ["sluice"]
CMD ["proxy"]
```

- [x] **Step 2: Build and verify**

```bash
docker build -t sluice:dev .
docker run --rm sluice:dev --help
```

- [x] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat: multi-stage Dockerfile"
```

---

### Task 2: docker-compose.yml

**Files:**
- Create: `docker-compose.yml`
- Create: `examples/policy.toml`

- [ ] **Step 1: Create example policy**

```toml
# examples/policy.toml
[policy]
default = "ask"
timeout_sec = 120

[telegram]
bot_token_env = "TELEGRAM_BOT_TOKEN"
chat_id_env = "TELEGRAM_CHAT_ID"

# AI model APIs
[[allow]]
destination = "api.anthropic.com"
ports = [443]
inject_header = "x-api-key"
credential = "anthropic_api_key"

[[allow]]
destination = "api.openai.com"
ports = [443]
inject_header = "Authorization"
credential = "openai_api_key"
template = "Bearer {value}"

# Telegram (needed for OpenClaw bot)
[[allow]]
destination = "*.telegram.org"
ports = [443]

# Block cloud metadata
[[deny]]
destination = "169.254.169.254"
[[deny]]
destination = "100.100.100.200"

# Tool policies
[[tool_allow]]
tool = "github__list_*"
tool = "github__get_*"

[[tool_ask]]
tool = "github__create_*"
tool = "github__update_*"
tool = "github__delete_*"
tool = "filesystem__write_*"

[[tool_deny]]
tool = "exec__*"
```

- [ ] **Step 2: Create docker-compose.yml**

```yaml
# docker-compose.yml
services:
  sluice:
    build: .
    command: ["proxy", "-policy", "/etc/sluice/policy.toml", "-audit", "/var/log/sluice/audit.jsonl"]
    environment:
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
      - TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
      - SLUICE_VAULT_DIR=/home/sluice/.sluice
    volumes:
      - ./examples/policy.toml:/etc/sluice/policy.toml:ro
      - sluice-vault:/home/sluice/.sluice
      - sluice-audit:/var/log/sluice
    networks: [internal, external]

  tun2proxy:
    image: ghcr.io/tun2proxy/tun2proxy-ubuntu:latest
    cap_add: [NET_ADMIN]
    volumes: ["/dev/net/tun:/dev/net/tun"]
    command: ["--proxy", "socks5://sluice:1080"]
    networks: [internal]
    depends_on: [sluice]

  openclaw:
    image: openclaw/openclaw:latest
    network_mode: "service:tun2proxy"
    env_file: .env.phantom
    volumes:
      - openclaw-data:/root/.openclaw
    depends_on: [tun2proxy]

networks:
  internal:
    internal: true
  external: {}

volumes:
  sluice-vault:
  sluice-audit:
  openclaw-data:
```

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml examples/
git commit -m "feat: docker-compose with OpenClaw + tun2proxy + Sluice"
```

---

### Task 3: Setup scripts

**Files:**
- Create: `scripts/setup-vault.sh`
- Create: `scripts/gen-phantom-env.sh`

- [ ] **Step 1: Create phantom env generator**

```bash
#!/usr/bin/env bash
# scripts/gen-phantom-env.sh
# Generates .env.phantom with fake tokens for the OpenClaw container
set -euo pipefail

cat > .env.phantom << 'EOF'
# Phantom tokens. These are NOT real credentials.
# Sluice proxy injects real credentials on the wire.
ANTHROPIC_API_KEY=sk-ant-phantom-not-real-00000000000000000000
OPENAI_API_KEY=sk-phantom-not-real-00000000000000000000000000
GITHUB_TOKEN=ghp_phantom0000000000000000000000000000
EOF

echo "Generated .env.phantom"
echo "These are fake tokens. Real credentials live in the Sluice vault."
```

- [ ] **Step 2: Create vault setup script**

```bash
#!/usr/bin/env bash
# scripts/setup-vault.sh
# Interactive credential setup for Sluice vault
set -euo pipefail

SLUICE=${SLUICE:-./sluice}

echo "=== Sluice Vault Setup ==="
echo ""

read -p "Add Anthropic API key? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  read -sp "Anthropic API key: " key; echo
  echo "$key" | $SLUICE cred add anthropic_api_key
fi

read -p "Add OpenAI API key? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  read -sp "OpenAI API key: " key; echo
  echo "$key" | $SLUICE cred add openai_api_key
fi

read -p "Add GitHub token? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  read -sp "GitHub token: " key; echo
  echo "$key" | $SLUICE cred add github_token
fi

echo ""
echo "Vault contents:"
$SLUICE cred list
echo ""
echo "Done. Run 'docker compose up' to start."
```

- [ ] **Step 3: Make scripts executable**

```bash
chmod +x scripts/setup-vault.sh scripts/gen-phantom-env.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/ .gitignore
git commit -m "feat: setup scripts for vault and phantom env"
```

---

### Task 4: End-to-end test

- [ ] **Step 1: Build everything**

```bash
docker compose build
```

- [ ] **Step 2: Generate phantom env**

```bash
./scripts/gen-phantom-env.sh
```

- [ ] **Step 3: Start the stack**

```bash
docker compose up -d
```

- [ ] **Step 4: Verify Sluice proxy is listening**

```bash
docker compose logs sluice | grep "listening"
```

Expected: "sluice SOCKS5 proxy listening on 0.0.0.0:1080"

- [ ] **Step 5: Verify OpenClaw has no direct internet**

```bash
docker compose exec openclaw curl -s --connect-timeout 5 https://api.anthropic.com/ || echo "blocked (expected)"
```

Expected: blocked or routed through Sluice

- [ ] **Step 6: Check audit log**

```bash
docker compose exec sluice cat /var/log/sluice/audit.jsonl
```

Expected: JSON lines showing connection attempts

- [ ] **Step 7: Commit and tag**

```bash
git add .
git commit -m "feat: end-to-end docker integration"
git tag v0.1.0
```

---

## Chunk 3: Docker Socket Credential Rotation

### Task 5: Auto-restart agent container on credential changes

When credentials are added/rotated/removed via the Telegram bot, Sluice
needs to restart the OpenClaw container with updated phantom token
environment variables. This happens via the Docker socket.

**Files:**
- Create: `internal/docker/manager.go`
- Create: `internal/docker/manager_test.go`
- Modify: `internal/telegram/commands.go` (call manager on cred changes)

- [ ] **Step 1: Implement Docker container manager**

```go
// internal/docker/manager.go
// Uses Docker Engine API (github.com/docker/docker/client)

type Manager struct {
    client        *client.Client
    containerName string // e.g. "openclaw"
}

// RestartWithEnv recreates the container with updated environment variables.
// 1. Inspect current container to get config
// 2. Stop and remove current container
// 3. Create new container with same config + updated env
// 4. Start new container
func (m *Manager) RestartWithEnv(envUpdates map[string]string) error

// Status returns container health information.
func (m *Manager) Status() (ContainerStatus, error)

// Stop stops the agent container.
func (m *Manager) Stop() error
```

- [ ] **Step 2: Implement phantom env generation**

```go
// GeneratePhantomEnv takes the vault's credential list and generates
// a map of env var name -> phantom token value.
// Phantom tokens match the format of real tokens (same length, same prefix)
// so SDKs don't reject them.
func GeneratePhantomEnv(store *vault.Store) (map[string]string, error)
```

Format-matching logic:
- `sk-ant-*` -> `sk-ant-phantom-<random>`
- `ghp_*` -> `ghp_phantom<random>`
- `sk-*` (OpenAI) -> `sk-phantom-<random>`
- Unknown format -> random alphanumeric of same length

- [ ] **Step 3: Wire into Telegram /cred commands**

When `/cred add`, `/cred rotate`, or `/cred remove` completes:
1. Regenerate phantom env map
2. Call `manager.RestartWithEnv(phantomEnv)`
3. Send confirmation to Telegram: "Credential updated. Agent container restarted."

- [ ] **Step 4: Write tests**

```go
func TestGeneratePhantomEnv(t *testing.T) {
    // Verify phantom tokens match real token format/length
}
func TestPhantomTokenFormatMatching(t *testing.T) {
    // "sk-ant-api03-real..." -> "sk-ant-phantom-<same-length-random>"
    // "ghp_realtoken123456" -> "ghp_phantom<same-length-random>"
}
```

Docker manager tests use a mock Docker client (interface-based).

- [ ] **Step 5: Add Docker client dependency**

```bash
go get github.com/docker/docker/client
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/docker/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/docker/ internal/telegram/commands.go
git commit -m "feat: docker socket credential rotation with phantom env generation"
```

---

### Task 6: Sluice CA cert injection into agent container

The built-in HTTPS MITM needs the agent container to trust Sluice's CA.
This task ensures the CA cert is generated and mounted correctly.

**Files:**
- Modify: `docker-compose.yml` (add CA cert volume)
- Modify: `Dockerfile` (include CA cert generation on first run)
- Modify: `scripts/setup-vault.sh` (generate CA if not exists)

- [ ] **Step 1: Add CA cert generation to setup script**

```bash
# scripts/setup-vault.sh
# If CA cert doesn't exist, generate it:
if [ ! -f "$VAULT_DIR/ca.crt" ]; then
    sluice cert generate --out "$VAULT_DIR"
fi
```

- [ ] **Step 2: Add CA cert volume to docker-compose.yml**

The agent container mounts the CA cert as a trusted root:
```yaml
openclaw:
  volumes:
    - sluice-ca:/usr/local/share/ca-certificates/sluice:ro
```

Add `update-ca-certificates` to agent container entrypoint if needed.

- [ ] **Step 3: Implement `sluice cert generate` CLI command**

```go
// Generates self-signed CA cert + key using crypto/ecdsa P-256.
// Stores ca.crt and ca.key in vault directory.
// ca.crt is public (mounted into agent container).
// ca.key is private (used by MITM proxy, never leaves Sluice).
```

- [ ] **Step 4: Test end-to-end HTTPS through Sluice**

```bash
# From inside agent container:
curl https://api.anthropic.com/v1/models
# Should succeed with Sluice CA trusted
# Audit log should show the connection
```

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml Dockerfile scripts/ cmd/
git commit -m "feat: CA cert generation and injection for HTTPS MITM"
```
