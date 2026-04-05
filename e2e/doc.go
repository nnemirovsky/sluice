//go:build e2e

// Package e2e contains end-to-end tests for sluice. These tests start a
// real sluice binary, configure policies, make connections through the proxy,
// and verify credential injection, MCP gateway flows, and audit log integrity.
//
// Run with: go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s
//
// Build tags:
//   - e2e: all e2e tests (required)
//   - linux: Docker-specific tests (compose-based)
//   - darwin: Apple Container tests (macOS only)
package e2e
