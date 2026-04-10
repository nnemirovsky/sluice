FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags='-s -w -linkmode external -extldflags "-static"' -o /sluice ./cmd/sluice/

FROM alpine:3.21
# Runtimes installed so sluice can spawn common stdio MCP servers:
#   nodejs + npm -> npx for JavaScript/TypeScript MCPs
#   python3 + uv -> uvx for Python MCPs
# uv is downloaded as a static binary from astral.sh to avoid Python
# packaging headaches on Alpine (musl + PEP 668).
# ca-certificates/wget are for sluice itself.
RUN apk add --no-cache ca-certificates wget nodejs npm python3 && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64)  UV_ARCH=x86_64-unknown-linux-musl ;; \
        aarch64) UV_ARCH=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported arch for uv: $ARCH" && exit 1 ;; \
    esac && \
    wget -qO- "https://github.com/astral-sh/uv/releases/latest/download/uv-${UV_ARCH}.tar.gz" | \
        tar xz -C /tmp && \
    mv "/tmp/uv-${UV_ARCH}/uv" /usr/local/bin/uv && \
    mv "/tmp/uv-${UV_ARCH}/uvx" /usr/local/bin/uvx && \
    rm -rf "/tmp/uv-${UV_ARCH}" && \
    adduser -D -h /home/sluice sluice && \
    mkdir -p /home/sluice/ca /home/sluice/.sluice /home/sluice/data /var/log/sluice /etc/sluice && \
    chown sluice:sluice /home/sluice/ca /home/sluice/.sluice /home/sluice/data /var/log/sluice /etc/sluice
COPY --from=builder /sluice /usr/local/bin/sluice
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
USER sluice
WORKDIR /home/sluice
EXPOSE 1080 3000
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://localhost:3000/healthz || exit 1
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["-listen", "0.0.0.0:1080", "-health-addr", "0.0.0.0:3000", "-mcp-base-url", "http://sluice:3000", "-db", "data/sluice.db", "-config", "/etc/sluice/config.toml", "-audit", "/var/log/sluice/audit.jsonl"]
