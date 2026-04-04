.PHONY: build test test-coverage lint fmt tidy install clean release release-snapshot generate lint-api

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
