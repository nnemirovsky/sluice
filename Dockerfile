FROM golang:1.26-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sluice ./cmd/sluice/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /bin/bash sluice
COPY --from=builder /sluice /usr/local/bin/sluice
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
USER sluice
WORKDIR /home/sluice
EXPOSE 1080 3000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["-listen", "0.0.0.0:1080"]
