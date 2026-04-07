package vault

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// GeneratePhantomToken creates a phantom token value matching the expected
// format for the given credential name. SDKs validate token prefixes, so
// phantom tokens must pass basic format checks. This is used by the MITM
// injector to generate phantom values for credential bindings.
func GeneratePhantomToken(credName string) string {
	rnd := randomHex(20)
	switch {
	case strings.Contains(credName, "anthropic"):
		return "sk-ant-phantom-" + rnd
	case strings.Contains(credName, "openai"):
		return "sk-phantom-" + rnd
	case strings.Contains(credName, "github"):
		return "ghp_phantom" + rnd
	default:
		return "phantom-" + rnd
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
