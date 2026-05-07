package container

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestHermesProfile_WireMCPUsesVenvWrapper(t *testing.T) {
	if HermesProfile.WireMCPCmd == nil {
		t.Fatal("hermes should have a wire MCP command")
	}
	cmd := HermesProfile.WireMCPCmd("sluice", "http://sluice:3000/mcp")
	// The wire script is invoked through a sh wrapper that activates the
	// container's bundled venv (where PyYAML lives) before exec'ing python3.
	if cmd[0] != "sh" || cmd[1] != "-c" {
		t.Fatalf("hermes wire MCP should be invoked via sh -c, got: %v", cmd[:2])
	}
	if !strings.Contains(cmd[2], "/opt/hermes/.venv/bin/activate") {
		t.Error("hermes wire MCP wrapper should activate the bundled venv when present")
	}
	if !strings.Contains(cmd[2], "exec python3") {
		t.Error("hermes wire MCP wrapper should exec python3 after optional venv activation")
	}
	if cmd[len(cmd)-2] != "sluice" || cmd[len(cmd)-1] != "http://sluice:3000/mcp" {
		t.Errorf("hermes wire MCP last args should be name and url, got: %v", cmd[len(cmd)-2:])
	}
	// The python script is the 4th positional argument (script body).
	script := cmd[3]
	if !strings.Contains(script, "mcp_servers") {
		t.Error("hermes wire MCP script should target mcp_servers key")
	}
	if !strings.Contains(script, "yaml.safe_load") {
		t.Error("hermes wire MCP script should parse yaml safely")
	}
}

func TestProfileFromName_ErrorListsKnownSorted(t *testing.T) {
	_, err := ProfileFromName("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	msg := err.Error()
	// "hermes" must appear before "openclaw" alphabetically when the list is sorted.
	hi := strings.Index(msg, "hermes")
	oi := strings.Index(msg, "openclaw")
	if hi < 0 || oi < 0 || hi > oi {
		t.Errorf("error message %q should list known profiles in sorted order (hermes before openclaw)", msg)
	}
}

func TestValidateEnvFileRelPath(t *testing.T) {
	good := []string{
		".openclaw/.env",
		".hermes/.env",
		"home/agent/.env",
		"a-b_c.env",
	}
	for _, p := range good {
		if err := validateEnvFileRelPath(p); err != nil {
			t.Errorf("expected %q to be accepted, got: %v", p, err)
		}
	}
	bad := []string{
		"",
		"/abs/path",
		"../escape",
		"a/../b",
		`a"; rm -rf /`,
		"a$(whoami)",
		"a b",
		"a;b",
		"a\nb",
	}
	for _, p := range bad {
		if err := validateEnvFileRelPath(p); err == nil {
			t.Errorf("expected %q to be rejected", p)
		}
	}
}

func TestBuildEnvInjectionScriptForProfile_RejectsUnsafePath(t *testing.T) {
	bad := &AgentProfile{Name: "evil", EnvFileRelPath: `evil"; touch /tmp/pwned`}
	_, err := BuildEnvInjectionScriptForProfile(bad, map[string]string{"K": "v"}, false, false)
	if err == nil {
		t.Fatal("expected error for unsafe EnvFileRelPath")
	}
}

// TestBuildEnvInjectionScript_QuotesValuesForSourcing executes the
// generated script against a real shell, then re-reads the resulting
// env file via `set -a; . file; set +a` and confirms every value
// round-trips byte-for-byte. The intent is to catch any future
// regression where unquoted values would be subjected to shell
// expansion (parameter, command substitution, glob) when sourced,
// since the production deployment uses `. ~/.hermes/.env` to load
// phantom tokens.
func TestBuildEnvInjectionScript_QuotesValuesForSourcing(t *testing.T) {
	tmp := t.TempDir()
	// Use a profile whose env file lives in $HOME so the script's
	// `$HOME/<rel>` resolves under our temp dir.
	profile := &AgentProfile{
		Name:           "test-quoting",
		EnvFileRelPath: ".test-agent/.env",
	}

	// Values that would each break a different way under unquoted
	// shell expansion if we wrote `KEY=raw-value` without quotes.
	envMap := map[string]string{
		"PLAIN":        "hello",
		"WITH_SPACE":   "two words",
		"WITH_DOLLAR":  "lit$$value$HOME$(whoami)",
		"WITH_QUOTE":   "it's a quote",
		"WITH_TICKS":   "back`tick`run",
		"WITH_GLOB":    "/etc/*",
		"WITH_NEWLINE": "no\\nnewline-but-backslash-n",
	}

	script, err := BuildEnvInjectionScriptForProfile(profile, envMap, false, true)
	if err != nil {
		t.Fatalf("build script: %v", err)
	}

	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "HOME="+tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run script: %v\noutput: %s\nscript:\n%s", err, out, script)
	}

	envPath := filepath.Join(tmp, ".test-agent", ".env")
	body, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	t.Logf("env file:\n%s", body)

	// Source the file and dump every key=value pair.
	dump := exec.Command("sh", "-c", `set -a; . "$1"; set +a; env`, "sh", envPath)
	dumpOut, err := dump.Output()
	if err != nil {
		t.Fatalf("source env file: %v", err)
	}

	resolved := map[string]string{}
	for _, line := range strings.Split(string(dumpOut), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		resolved[k] = v
	}

	for k, want := range envMap {
		got, ok := resolved[k]
		if !ok {
			t.Errorf("key %q missing after source", k)
			continue
		}
		if got != want {
			t.Errorf("key %q round-trip mismatch:\n  want: %q\n   got: %q", k, want, got)
		}
	}
}

func TestBuildEnvInjectionScript_ChownsEnvFileToDirOwner(t *testing.T) {
	// Sluice's docker exec runs as the image's USER (root for the
	// upstream openclaw and hermes images), so the awk rename and
	// heredoc append leave the file root-owned. The agent runtime
	// runs as a non-root user, so without a chown back to the dir
	// owner the agent cannot run `hermes claw migrate` or in-agent
	// secret edits. Verify the script emits a chown step.
	for _, hasValues := range []bool{true, false} {
		envMap := map[string]string{}
		if hasValues {
			envMap["KEY"] = "value"
		}
		script, err := BuildEnvInjectionScript(envMap, false, true)
		if err != nil {
			t.Fatalf("hasValues=%v: build script: %v", hasValues, err)
		}
		if !strings.Contains(script, `stat -c '%u:%g'`) {
			t.Errorf("hasValues=%v: script must stat the parent dir to derive owner: %s", hasValues, script)
		}
		if !strings.Contains(script, `chown "$DIR_OWNER" "$ENV_FILE"`) {
			t.Errorf("hasValues=%v: script must chown the env file to dir owner: %s", hasValues, script)
		}
	}
}

func TestBuildEnvInjectionScript_RejectsNewlineInValue(t *testing.T) {
	// A newline in the value would split the env-file entry across two
	// lines. The second line would either be silently lost or interpreted
	// as a separate KEY=VALUE assignment when the file is sourced.
	for _, bad := range []string{
		"line1\nline2",
		"trailing\n",
		"carriage\rreturn",
		"contains \x00 nul",
	} {
		_, err := BuildEnvInjectionScript(map[string]string{"K": bad}, false, false)
		if err == nil {
			t.Errorf("expected error for value %q", bad)
		}
	}
}

func TestBuildEnvInjectionScript_NeverTruncatesForeignKeys(t *testing.T) {
	// The script must never invoke `: > "$ENV_FILE"` (full truncate).
	// Foreign keys (set by the agent or by `hermes claw migrate`) must
	// survive every injection. Sluice only manages the fenced block.
	for _, full := range []bool{false, true} {
		script, err := BuildEnvInjectionScript(map[string]string{"K": "v"}, false, full)
		if err != nil {
			t.Fatalf("fullReplace=%v: unexpected error: %v", full, err)
		}
		if strings.Contains(script, ": > \"$ENV_FILE\"") {
			t.Errorf("fullReplace=%v: script must not truncate the file: %s", full, script)
		}
		if !strings.Contains(script, "BEGIN sluice-managed") || !strings.Contains(script, "END sluice-managed") {
			t.Errorf("fullReplace=%v: script must reopen the marker block: %s", full, script)
		}
	}
}

func TestBuildEnvInjectionScript_EmptyMapStillRebuildsBlock(t *testing.T) {
	// Even when there are no managed keys, the script must remove any
	// previous sluice-managed block. Otherwise stale phantom values
	// from the previous run would remain in the file.
	script, err := BuildEnvInjectionScript(map[string]string{}, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(script, "BEGIN sluice-managed") {
		t.Errorf("script should reference the marker even when the new block is empty: %s", script)
	}
	if strings.Contains(script, "echo '") && strings.Contains(script, "=") {
		t.Errorf("empty envMap should not echo any KEY=value lines: %s", script)
	}
}

func TestBuildEnvInjectionScript_KeysAreSorted(t *testing.T) {
	// Stable order keeps the env file diff-friendly across runs and
	// makes test assertions robust against Go map iteration randomness.
	script, err := BuildEnvInjectionScript(map[string]string{
		"ZED":    "z",
		"ALPHA":  "a",
		"MIDDLE": "m",
	}, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idxA := strings.Index(script, "ALPHA=")
	idxM := strings.Index(script, "MIDDLE=")
	idxZ := strings.Index(script, "ZED=")
	if idxA < 0 || idxM < 0 || idxZ < 0 {
		t.Fatalf("expected all three keys in script: %s", script)
	}
	if idxA >= idxM || idxM >= idxZ {
		t.Errorf("keys should be sorted (ALPHA < MIDDLE < ZED), got positions %d %d %d", idxA, idxM, idxZ)
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
