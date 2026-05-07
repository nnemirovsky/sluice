package container

import (
	"strings"
	"testing"
)

func TestProfileFromName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPath  string
		wantError bool
	}{
		{"openclaw", "openclaw", ".openclaw/.env", false},
		{"hermes", "hermes", ".hermes/.env", false},
		{"unknown", "claude", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ProfileFromName(tt.input)
			if (err != nil) != tt.wantError {
				t.Fatalf("err = %v, wantError = %v", err, tt.wantError)
			}
			if err == nil && p.EnvFileRelPath != tt.wantPath {
				t.Errorf("EnvFileRelPath = %q, want %q", p.EnvFileRelPath, tt.wantPath)
			}
		})
	}
}

func TestBuildEnvInjectionScriptForProfile_Hermes(t *testing.T) {
	envMap := map[string]string{"OPENAI_API_KEY": "sk-phantom-xyz"}
	script, err := BuildEnvInjectionScriptForProfile(HermesProfile, envMap, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(script, ".hermes/.env") {
		t.Errorf("script should reference .hermes/.env, got: %s", script)
	}
	if strings.Contains(script, ".openclaw") {
		t.Errorf("script should not reference .openclaw for hermes profile: %s", script)
	}
	if !strings.Contains(script, "OPENAI_API_KEY") {
		t.Errorf("script should contain env var name: %s", script)
	}
}

func TestBuildEnvInjectionScript_DefaultsToOpenclaw(t *testing.T) {
	script, err := BuildEnvInjectionScript(map[string]string{"FOO": "bar"}, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(script, ".openclaw/.env") {
		t.Errorf("default script should target .openclaw/.env, got: %s", script)
	}
}

func TestOpenclawProfile_ReloadAndWireCommands(t *testing.T) {
	if OpenclawProfile.ReloadCmd == nil {
		t.Fatal("openclaw should have a reload command")
	}
	cmd := OpenclawProfile.ReloadCmd()
	if len(cmd) < 3 || cmd[0] != "node" || cmd[1] != "-e" {
		t.Errorf("reload should be node -e <script> ..., got: %v", cmd)
	}
	if cmd[len(cmd)-1] != "secrets.reload" {
		t.Errorf("reload last arg should be secrets.reload, got: %v", cmd)
	}

	if OpenclawProfile.WireMCPCmd == nil {
		t.Fatal("openclaw should have a wire MCP command")
	}
	wcmd := OpenclawProfile.WireMCPCmd("sluice", "http://sluice:3000/mcp")
	if wcmd[0] != "node" {
		t.Errorf("wire mcp should be node-based, got: %v", wcmd)
	}
}

func TestHermesProfile_ReloadIsNil(t *testing.T) {
	if HermesProfile.ReloadCmd != nil {
		t.Error("hermes profile should have nil ReloadCmd (no in-place reload documented)")
	}
}

func TestHermesProfile_WireMCPUsesPython(t *testing.T) {
	if HermesProfile.WireMCPCmd == nil {
		t.Fatal("hermes should have a wire MCP command")
	}
	cmd := HermesProfile.WireMCPCmd("sluice", "http://sluice:3000/mcp")
	if cmd[0] != "python3" {
		t.Errorf("hermes wire MCP should use python3, got: %v", cmd[:1])
	}
	if cmd[1] != "-c" {
		t.Errorf("hermes wire MCP should use -c, got: %v", cmd[:2])
	}
	if cmd[len(cmd)-2] != "sluice" || cmd[len(cmd)-1] != "http://sluice:3000/mcp" {
		t.Errorf("hermes wire MCP last args should be name and url, got: %v", cmd[len(cmd)-2:])
	}
	if !strings.Contains(cmd[2], "mcp_servers") {
		t.Error("hermes wire MCP script should target mcp_servers key")
	}
	if !strings.Contains(cmd[2], "yaml.safe_load") {
		t.Error("hermes wire MCP script should parse yaml safely")
	}
}

func TestResolveProfile_NilDefaultsToOpenclaw(t *testing.T) {
	if resolveProfile(nil) != OpenclawProfile {
		t.Error("nil profile should default to OpenclawProfile")
	}
	if resolveProfile(HermesProfile) != HermesProfile {
		t.Error("non-nil profile should be returned as-is")
	}
}
