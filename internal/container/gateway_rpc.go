package container

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// gatewayRPCScript is the Node.js client that connects to the openclaw
// gateway WebSocket, performs the full device-signed connect handshake,
// and invokes a JSON-RPC method. It is embedded at build time so sluice
// can inject it into the agent container via `docker exec node -e`.
//
// Supported invocations:
//
//	secrets.reload
//	config.patch '{"raw":"...","baseHash":"..."}'
//	wire-mcp <name> <url>        (chains config.get + config.patch)
//
// See scripts/openclaw-gateway-rpc.js for the full source.
//
//go:embed gateway_rpc.js
var gatewayRPCScript string

// GatewayRPCNodeCommand returns the argv slice (for ExecInContainer) that
// runs the embedded gateway RPC script with the given arguments. The
// script is passed to `node -e`, so it runs inside the agent container
// without needing a shared volume.
//
// Example:
//
//	cmd := GatewayRPCNodeCommand("secrets.reload")
//	cmd := GatewayRPCNodeCommand("wire-mcp", "sluice", "http://sluice:3000/mcp")
func GatewayRPCNodeCommand(scriptArgs ...string) []string {
	// Build: node -e <script> -- <scriptArgs...>
	// Node treats args after "-e" and "--" as process.argv entries
	// starting at index 2 (index 0 is "node", index 1 is the script).
	// Actually, without a separator, `node -e "code" foo bar` gives
	// process.argv = ["node", "[eval]", "foo", "bar"] which is what
	// the script expects.
	cmd := []string{"node", "-e", gatewayRPCScript}
	cmd = append(cmd, scriptArgs...)
	return cmd
}

// BuildConfigPatchParams returns a JSON string suitable as the params
// argument for a direct config.patch RPC invocation. This is exposed
// for callers that need to call config.patch outside the wire-mcp
// convenience mode.
func BuildConfigPatchParams(raw string, baseHash string) (string, error) {
	b, err := json.Marshal(map[string]string{"raw": raw, "baseHash": baseHash})
	if err != nil {
		return "", fmt.Errorf("marshal config.patch params: %w", err)
	}
	return string(b), nil
}
