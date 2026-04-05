.PHONY: build test test-coverage test-e2e test-e2e-docker test-e2e-linux test-e2e-macos lint fmt tidy install clean release release-snapshot generate lint-api help

# Build
build:
	go build -o bin/sluice ./cmd/sluice

# Run
run:
	go run ./cmd/sluice $(ARGS)

# Install
install:
	go install ./cmd/...

# Test
test:
	go test ./... -v -count=1

test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# E2e tests (local, all platforms)
test-e2e:
	go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s

# E2e tests via Docker Compose (Linux)
test-e2e-docker:
	docker compose -f compose.e2e.yml up --build --abort-on-container-exit --exit-code-from test-runner; \
	rc=$$?; \
	docker compose -f compose.e2e.yml down -v || { echo "WARNING: docker compose down -v failed, resources may be left behind" >&2; [ $$rc -eq 0 ] && rc=1; }; \
	exit $$rc

# E2e tests (Linux, runs Go tests with linux build tag)
test-e2e-linux:
	go test -tags="e2e linux" ./e2e/ -v -count=1 -timeout=300s

# E2e tests (macOS with Apple Container)
test-e2e-macos:
	go test -tags="e2e darwin" ./e2e/ -v -count=1 -timeout=300s

# Lint
lint:
	golangci-lint run ./...

# Format
fmt:
	gofumpt -w .

# Tidy
tidy:
	go mod tidy

# Release (dry run)
release-snapshot:
	goreleaser release --snapshot --clean

# Release
release:
	goreleaser release --clean

# Generate API code from OpenAPI spec
generate:
	cd internal/api && oapi-codegen --config config.yaml ../../api/openapi.yaml

# Lint OpenAPI spec
lint-api:
	npx @redocly/cli lint api/openapi.yaml

# Clean
clean:
	rm -rf bin/ coverage.out coverage.html dist/

# Help
help:
	@echo "Build & Run"
	@echo "  make build              Build sluice binary"
	@echo "  make run ARGS='...'     Run with arguments"
	@echo "  make install            Install to GOPATH"
	@echo ""
	@echo "Test & Lint"
	@echo "  make test               Run all tests"
	@echo "  make test-coverage      Generate coverage report"
	@echo "  make test-e2e           Run all e2e tests locally (all platforms)"
	@echo "  make test-e2e-docker    Run Linux e2e tests via Docker Compose"
	@echo "  make test-e2e-linux     Run Linux e2e tests (go test with linux tag)"
	@echo "  make test-e2e-macos     Run macOS e2e tests (Apple Container)"
	@echo "  make lint               Run golangci-lint"
	@echo "  make fmt                Format with gofumpt"
	@echo "  make tidy               Run go mod tidy"
	@echo ""
	@echo "API Development"
	@echo "  make generate           Regenerate Go code from api/openapi.yaml"
	@echo "  make lint-api           Lint OpenAPI spec with Redocly"
	@echo ""
	@echo "Release"
	@echo "  make release-snapshot   Dry run release"
	@echo "  make release            Build and publish release"
	@echo ""
	@echo "  make clean              Remove build artifacts"
