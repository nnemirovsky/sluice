FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags='-s -w -linkmode external -extldflags "-static"' -o /sluice ./cmd/sluice/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget && \
    adduser -D -h /home/sluice sluice && \
    mkdir -p /home/sluice/ca /home/sluice/.sluice /home/sluice/data /home/sluice/phantoms /var/log/sluice /etc/sluice && \
    chown sluice:sluice /home/sluice/ca /home/sluice/.sluice /home/sluice/data /home/sluice/phantoms /var/log/sluice /etc/sluice
COPY --from=builder /sluice /usr/local/bin/sluice
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
USER sluice
WORKDIR /home/sluice
EXPOSE 1080 3000
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://localhost:3000/healthz || exit 1
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["-listen", "0.0.0.0:1080", "-health-addr", "0.0.0.0:3000", "-mcp-base-url", "http://sluice:3000", "-db", "data/sluice.db", "-config", "/etc/sluice/config.toml", "-audit", "/var/log/sluice/audit.jsonl", "-phantom-dir", "/home/sluice/phantoms"]
