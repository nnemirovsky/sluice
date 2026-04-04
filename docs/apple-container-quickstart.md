# Apple Container Quickstart

Run OpenClaw inside an Apple Container micro-VM with sluice governing all network traffic, credentials, and MCP tools. Requires macOS with Apple Container runtime installed.

## Prerequisites

- macOS with Apple Container runtime (`container` CLI in PATH)
- Go 1.22+ (to build sluice from source)
- Root/sudo access (required for pf rules)
- tun2proxy installed on the host

## 1. Build sluice

```bash
go build -o sluice ./cmd/sluice/
```

## 2. Generate a CA certificate

Sluice's MITM proxy needs a CA cert to intercept HTTPS traffic.

```bash
./sluice cert generate
```

This creates the CA in `~/.sluice/ca/`.

## 3. Add credentials

```bash
./sluice cred add anthropic_api_key --destination api.anthropic.com --ports 443 --header x-api-key
```

Follow the prompt to enter the real API key. Sluice encrypts it and generates a phantom token.

## 4. Seed the policy database

```bash
./sluice policy import examples/config.toml
```

## 5. Start sluice with Apple Container runtime

```bash
./sluice \
  --runtime apple \
  --container-name openclaw \
  --listen 127.0.0.1:1080 \
  --db sluice.db \
  --phantom-dir ~/.sluice/phantoms
```

Sluice will start the SOCKS5 proxy on :1080 and create an AppleManager for credential hot-reload via `container exec`. You still need to set up pf routing and start the VM separately. See the next section.

## 6. Set up networking and start the VM

Use the setup script to configure pf routing and tun2proxy:

```bash
# Set up pf routing (requires root)
sudo scripts/apple-container-setup.sh

# Start the VM with CA cert and phantom tokens mounted
container run --name openclaw \
  -e SSL_CERT_FILE=/certs/sluice-ca.crt \
  -e REQUESTS_CA_BUNDLE=/certs/sluice-ca.crt \
  -e NODE_EXTRA_CA_CERTS=/certs/sluice-ca.crt \
  -v ~/.sluice/ca:/certs:ro \
  -v ~/.sluice/phantoms:/phantoms:ro \
  openclaw/openclaw:latest
```

Alternatively, use `--runtime none` and set `ALL_PROXY=socks5://127.0.0.1:1080` in the VM manually.

## Runtime comparison

| Feature | Docker | Apple Container | Standalone |
|---------|--------|----------------|------------|
| Container isolation | Linux namespaces | Hypervisor micro-VM | None |
| Network routing | tun2proxy container + shared NS | pf rules + tun2proxy on host | Manual ALL_PROXY |
| Credential reload | docker exec + shared volume | container exec + shared volume | N/A |
| Apple frameworks | No | Yes (EventKit, Messages, CallKit) | Yes (host native) |
| APNS protocol | N/A | Yes (port 5223 detection) | Yes |
| Platform | Linux, macOS (Docker Desktop) | macOS only | Any |
| Setup complexity | Low (docker compose up) | Medium (pf rules, sudo) | Low |

## Verifying traffic routing

All VM traffic should route through sluice. Test with:

```bash
# From inside the VM
container exec openclaw curl -v https://api.anthropic.com/
```

Check sluice's audit log to confirm the connection was intercepted:

```bash
./sluice audit verify
tail -1 audit.jsonl | python3 -m json.tool
```

## Troubleshooting

**VM has no network access:**
Check pf rules are loaded: `sudo pfctl -a sluice -sr`. Verify tun2proxy is running and sluice is listening on the SOCKS5 port.

**HTTPS certificate errors inside the VM:**
Verify the CA cert is mounted: `container exec openclaw cat /certs/sluice-ca.crt`. Check that `SSL_CERT_FILE` points to the correct path.

**container CLI not found:**
Install Apple Container runtime. The `container` binary must be in PATH.

**Permission denied on pfctl:**
pf rules require root. Run sluice with sudo or use the setup script with sudo.
