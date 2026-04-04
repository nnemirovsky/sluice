package store

import (
	"os"
	"testing"
)

func TestImportTOMLNetworkRules(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "deny"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
destination = "*.github.com"
ports = [443, 80]

[[deny]]
destination = "169.254.169.254"

[[deny]]
destination = "*.crypto-mining.example"

[[ask]]
destination = "*.openai.com"
ports = [443]
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.RulesInserted != 5 {
		t.Errorf("expected 5 rules inserted, got %d", res.RulesInserted)
	}
	if res.RulesSkipped != 0 {
		t.Errorf("expected 0 rules skipped, got %d", res.RulesSkipped)
	}

	// Verify rules in DB.
	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}

	// Verify first allow rule.
	r := rules[0]
	if r.Verdict != "allow" || r.Destination != "api.anthropic.com" {
		t.Errorf("unexpected rule[0]: %+v", r)
	}
	if len(r.Ports) != 1 || r.Ports[0] != 443 {
		t.Errorf("expected ports [443], got %v", r.Ports)
	}
	if r.Source != "seed" {
		t.Errorf("expected source 'seed', got %q", r.Source)
	}

	// Verify config.
	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.DefaultVerdict != "deny" {
		t.Errorf("expected default_verdict 'deny', got %q", cfg.DefaultVerdict)
	}
}

func TestImportTOMLToolRules(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"

[[allow]]
tool = "github__list_*"

[[deny]]
tool = "exec__*"

[[ask]]
tool = "filesystem__write_*"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.RulesInserted != 3 {
		t.Errorf("expected 3 rules inserted, got %d", res.RulesInserted)
	}

	rules, err := s.ListRules(RuleFilter{Type: "tool"})
	if err != nil {
		t.Fatalf("ListRules(tool): %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 tool rules, got %d", len(rules))
	}

	// Check verdicts.
	if rules[0].Verdict != "allow" || rules[0].Tool != "github__list_*" {
		t.Errorf("unexpected tool rule[0]: %+v", rules[0])
	}
	if rules[1].Verdict != "deny" || rules[1].Tool != "exec__*" {
		t.Errorf("unexpected tool rule[1]: %+v", rules[1])
	}
	if rules[2].Verdict != "ask" || rules[2].Tool != "filesystem__write_*" {
		t.Errorf("unexpected tool rule[2]: %+v", rules[2])
	}
}

func TestImportTOMLContentRules(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"

[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
name = "api_key_leak"

[[redact]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
replacement = "[REDACTED_API_KEY]"
name = "api_key_in_response"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.RulesInserted != 2 {
		t.Errorf("expected 2 rules inserted, got %d", res.RulesInserted)
	}

	// Block rules are stored as verdict="deny" with pattern set.
	block, err := s.ListRules(RuleFilter{Verdict: "deny", Type: "pattern"})
	if err != nil {
		t.Fatalf("ListRules block: %v", err)
	}
	if len(block) != 1 {
		t.Fatalf("expected 1 block rule, got %d", len(block))
	}
	if block[0].Name != "api_key_leak" {
		t.Errorf("expected name 'api_key_leak', got %q", block[0].Name)
	}

	redact, err := s.ListRules(RuleFilter{Verdict: "redact", Type: "pattern"})
	if err != nil {
		t.Fatalf("ListRules redact: %v", err)
	}
	if len(redact) != 1 {
		t.Fatalf("expected 1 redact rule, got %d", len(redact))
	}
	if redact[0].Replacement != "[REDACTED_API_KEY]" {
		t.Errorf("expected replacement '[REDACTED_API_KEY]', got %q", redact[0].Replacement)
	}
}

func TestImportTOMLConfig(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"
timeout_sec = 60
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.ConfigSet != 2 {
		t.Errorf("expected 2 config values set, got %d", res.ConfigSet)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.DefaultVerdict != "ask" {
		t.Errorf("default_verdict = %q, want ask", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec != 60 {
		t.Errorf("timeout_sec = %d, want 60", cfg.TimeoutSec)
	}
}

func TestImportTOMLBindings(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"

[[binding]]
destination = "api.anthropic.com"
ports = [443]
credential = "anthropic_api_key"
header = "x-api-key"

[[binding]]
destination = "api.openai.com"
ports = [443]
credential = "openai_api_key"
header = "Authorization"
template = "Bearer {value}"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.BindingsInserted != 2 {
		t.Errorf("expected 2 bindings inserted, got %d", res.BindingsInserted)
	}

	bindings, err := s.ListBindings()
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
	if bindings[0].Credential != "anthropic_api_key" || bindings[0].Header != "x-api-key" {
		t.Errorf("unexpected binding[0]: %+v", bindings[0])
	}
	if bindings[1].Template != "Bearer {value}" {
		t.Errorf("expected template 'Bearer {value}', got %q", bindings[1].Template)
	}
}

func TestImportTOMLMCPUpstreams(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"

[[mcp_upstream]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
timeout_sec = 60

[[mcp_upstream]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.UpstreamsInserted != 2 {
		t.Errorf("expected 2 upstreams inserted, got %d", res.UpstreamsInserted)
	}

	ups, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatalf("ListMCPUpstreams: %v", err)
	}
	if len(ups) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(ups))
	}
	if ups[0].Name != "github" || ups[0].TimeoutSec != 60 {
		t.Errorf("unexpected upstream[0]: %+v", ups[0])
	}
	if ups[1].Name != "filesystem" || ups[1].TimeoutSec != 120 {
		t.Errorf("unexpected upstream[1] (default timeout expected): %+v", ups[1])
	}
}

func TestImportTOMLMergeSkipsDuplicates(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "deny"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
tool = "github__list_*"

[[binding]]
destination = "api.anthropic.com"
ports = [443]
credential = "anthropic_api_key"
header = "x-api-key"

[[mcp_upstream]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[[deny]]
pattern = "\\d{3}-\\d{2}-\\d{4}"
name = "Block SSNs"
`)

	// First import.
	res1, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("first ImportTOML: %v", err)
	}
	if res1.RulesInserted != 3 {
		t.Errorf("first import: expected 3 rules inserted, got %d", res1.RulesInserted)
	}
	if res1.BindingsInserted != 1 {
		t.Errorf("first import: expected 1 binding inserted, got %d", res1.BindingsInserted)
	}
	if res1.UpstreamsInserted != 1 {
		t.Errorf("first import: expected 1 upstream inserted, got %d", res1.UpstreamsInserted)
	}

	// Second import (same data). Everything should be skipped.
	res2, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("second ImportTOML: %v", err)
	}
	if res2.RulesInserted != 0 {
		t.Errorf("expected 0 rules inserted on second import, got %d", res2.RulesInserted)
	}
	if res2.RulesSkipped != 3 {
		t.Errorf("expected 3 rules skipped on second import, got %d", res2.RulesSkipped)
	}
	if res2.BindingsInserted != 0 {
		t.Errorf("expected 0 bindings inserted on second import, got %d", res2.BindingsInserted)
	}
	if res2.BindingsSkipped != 1 {
		t.Errorf("expected 1 binding skipped on second import, got %d", res2.BindingsSkipped)
	}
	if res2.UpstreamsInserted != 0 {
		t.Errorf("expected 0 upstreams inserted on second import, got %d", res2.UpstreamsInserted)
	}
	if res2.UpstreamsSkipped != 1 {
		t.Errorf("expected 1 upstream skipped on second import, got %d", res2.UpstreamsSkipped)
	}

	// Verify DB has no duplicates.
	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("ListRules(network): %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 network rule total, got %d", len(rules))
	}
	toolRules, err := s.ListRules(RuleFilter{Type: "tool"})
	if err != nil {
		t.Fatalf("ListRules(tool): %v", err)
	}
	if len(toolRules) != 1 {
		t.Errorf("expected 1 tool rule total, got %d", len(toolRules))
	}
	patternRules, err := s.ListRules(RuleFilter{Type: "pattern"})
	if err != nil {
		t.Fatalf("ListRules(pattern): %v", err)
	}
	if len(patternRules) != 1 {
		t.Errorf("expected 1 pattern rule total, got %d", len(patternRules))
	}
}

func TestImportTOMLMalformedReturnsError(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`this is not valid TOML [[[`)

	res, err := s.ImportTOML(data)
	if err == nil {
		t.Fatalf("expected error for malformed TOML, got result: %+v", res)
	}
}

func TestImportTOMLMalformedNoPartialWrites(t *testing.T) {
	s := newTestStore(t)

	// Valid enough to parse but has valid data.
	data := []byte(`
[policy]
default = "deny"

[[allow]]
destination = "api.anthropic.com"
ports = [443]
`)
	// First, import valid data.
	_, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("valid import: %v", err)
	}

	// Now try to import data that won't parse at all.
	badData := []byte(`not_a_valid = [toml structure for policy`)
	_, err = s.ImportTOML(badData)
	if err == nil {
		t.Fatal("expected error for bad TOML")
	}

	// Original data should still be there.
	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (no partial write), got %d", len(rules))
	}
}

func TestImportTOMLWithExistingTestdataFiles(t *testing.T) {
	fixtures := []string{
		"../../testdata/policy_mixed.toml",
		"../../testdata/policy_with_telegram.toml",
		"../../testdata/policy_with_tools.toml",
		"../../testdata/policy_with_inspect.toml",
		"../../testdata/policy_allow_all.toml",
		"../../testdata/policy_deny_all.toml",
	}

	for _, path := range fixtures {
		t.Run(path, func(t *testing.T) {
			s := newTestStore(t)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			res, err := s.ImportTOML(data)
			if err != nil {
				t.Fatalf("ImportTOML(%s): %v", path, err)
			}
			// Just verify it doesn't error. Check at least some rules were processed.
			t.Logf("result: %+v", res)
		})
	}
}

func TestImportTOMLExampleConfigFile(t *testing.T) {
	s := newTestStore(t)

	data, err := os.ReadFile("../../examples/config.toml")
	if err != nil {
		t.Skipf("examples/config.toml not found: %v", err)
	}

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}

	// The example config has:
	// - 3 network allow rules (anthropic, openai, telegram)
	// - 2 network deny rules (metadata endpoints)
	// - 1 UDP deny rule (block all UDP by default)
	// - 1 UDP/DNS allow rule (Google DNS)
	// - 2 tool allow rules (github list/get)
	// - 4 tool ask rules (github create/update/delete, filesystem write)
	// - 1 tool deny rule (exec)
	// - 1 content deny rule (api key pattern)
	// - 1 redact rule (api key in responses)
	// Total: 16 rules
	if res.RulesInserted != 16 {
		t.Errorf("expected 16 rules inserted, got %d", res.RulesInserted)
	}
	if res.BindingsInserted != 2 {
		t.Errorf("expected 2 bindings, got %d inserted", res.BindingsInserted)
	}
	// Config: default=ask, timeout=120, vault provider=age
	if res.ConfigSet < 3 {
		t.Errorf("expected at least 3 config values, got %d set", res.ConfigSet)
	}

	// Verify config.
	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.DefaultVerdict != "ask" {
		t.Errorf("expected default_verdict 'ask', got %q", cfg.DefaultVerdict)
	}
}

func TestImportTOMLRuleProtocolsAndName(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "deny"

[[allow]]
destination = "github.com"
ports = [22]
protocols = ["ssh"]
name = "Git SSH access"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.RulesInserted != 1 {
		t.Fatalf("expected 1 rule inserted, got %d", res.RulesInserted)
	}

	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].Protocols) != 1 || rules[0].Protocols[0] != "ssh" {
		t.Errorf("expected protocols [ssh], got %v", rules[0].Protocols)
	}
	if rules[0].Name != "Git SSH access" {
		t.Errorf("expected name 'Git SSH access', got %q", rules[0].Name)
	}
}

func TestImportTOMLMCPUpstreamWithEnv(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"

[[mcp_upstream]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
timeout_sec = 60

[mcp_upstream.env]
GITHUB_TOKEN = "phantom-token-abc123"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.UpstreamsInserted != 1 {
		t.Errorf("expected 1 upstream inserted, got %d", res.UpstreamsInserted)
	}

	ups, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatalf("ListMCPUpstreams: %v", err)
	}
	if len(ups) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(ups))
	}
	if ups[0].Env["GITHUB_TOKEN"] != "phantom-token-abc123" {
		t.Errorf("expected env GITHUB_TOKEN, got %v", ups[0].Env)
	}
}

func TestImportTOMLMutualExclusivityRejectsMultipleFields(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[[allow]]
destination = "api.example.com"
tool = "github__list_*"
`)

	_, err := s.ImportTOML(data)
	if err == nil {
		t.Fatal("expected error for rule with both destination and tool")
	}
}

func TestImportTOMLRedactWithoutPattern(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[[redact]]
replacement = "[REDACTED]"
name = "missing pattern"
`)

	_, err := s.ImportTOML(data)
	if err == nil {
		t.Fatal("expected error for redact rule without pattern")
	}
}

func TestImportTOMLMixedRuleTypes(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[policy]
default = "ask"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
tool = "github__list_*"
name = "read-only github"

[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
name = "api key leak"

[[redact]]
pattern = "(?i)(password)"
replacement = "[REDACTED]"
name = "password redact"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.RulesInserted != 4 {
		t.Errorf("expected 4 rules inserted, got %d", res.RulesInserted)
	}

	// Verify each type.
	network, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("ListRules(network): %v", err)
	}
	if len(network) != 1 {
		t.Errorf("expected 1 network rule, got %d", len(network))
	}
	tools, err := s.ListRules(RuleFilter{Type: "tool"})
	if err != nil {
		t.Fatalf("ListRules(tool): %v", err)
	}
	if len(tools) != 1 {
		t.Errorf("expected 1 tool rule, got %d", len(tools))
	}
	patterns, err := s.ListRules(RuleFilter{Type: "pattern"})
	if err != nil {
		t.Fatalf("ListRules(pattern): %v", err)
	}
	if len(patterns) != 2 {
		t.Errorf("expected 2 pattern rules, got %d", len(patterns))
	}
}

func TestImportTOMLVaultOnePasswordConfig(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[vault]
provider = "1password"

[vault.1password]
token = "ops_test_token_123"
vault = "my-vault"
field = "password"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.ConfigSet != 4 {
		t.Errorf("expected 4 config values set, got %d", res.ConfigSet)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.VaultProvider != "1password" {
		t.Errorf("expected vault_provider '1password', got %q", cfg.VaultProvider)
	}
	if cfg.Vault1PasswordToken != "ops_test_token_123" {
		t.Errorf("expected token, got %q", cfg.Vault1PasswordToken)
	}
	if cfg.Vault1PasswordVault != "my-vault" {
		t.Errorf("expected vault 'my-vault', got %q", cfg.Vault1PasswordVault)
	}
	if cfg.Vault1PasswordField != "password" {
		t.Errorf("expected field 'password', got %q", cfg.Vault1PasswordField)
	}
}

func TestImportTOMLVaultBitwardenConfig(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[vault]
provider = "bitwarden"

[vault.bitwarden]
token = "bws_test_token_456"
org_id = "org-uuid-123"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.ConfigSet != 3 {
		t.Errorf("expected 3 config values set, got %d", res.ConfigSet)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.VaultProvider != "bitwarden" {
		t.Errorf("expected vault_provider 'bitwarden', got %q", cfg.VaultProvider)
	}
	if cfg.VaultBitwardenToken != "bws_test_token_456" {
		t.Errorf("expected token, got %q", cfg.VaultBitwardenToken)
	}
	if cfg.VaultBitwardenOrgID != "org-uuid-123" {
		t.Errorf("expected org_id, got %q", cfg.VaultBitwardenOrgID)
	}
}

func TestImportTOMLVaultKeePassConfig(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[vault]
provider = "keepass"

[vault.keepass]
path = "/data/creds.kdbx"
key_file = "/data/keyfile.key"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.ConfigSet != 3 {
		t.Errorf("expected 3 config values set, got %d", res.ConfigSet)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.VaultProvider != "keepass" {
		t.Errorf("expected vault_provider 'keepass', got %q", cfg.VaultProvider)
	}
	if cfg.VaultKeePassPath != "/data/creds.kdbx" {
		t.Errorf("expected path, got %q", cfg.VaultKeePassPath)
	}
	if cfg.VaultKeePassKeyFile != "/data/keyfile.key" {
		t.Errorf("expected key_file, got %q", cfg.VaultKeePassKeyFile)
	}
}

func TestImportTOMLVaultGopassConfig(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[vault]
provider = "gopass"

[vault.gopass]
store = "/home/user/.gopass"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.ConfigSet != 2 {
		t.Errorf("expected 2 config values set, got %d", res.ConfigSet)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.VaultProvider != "gopass" {
		t.Errorf("expected vault_provider 'gopass', got %q", cfg.VaultProvider)
	}
	if cfg.VaultGopassStore != "/home/user/.gopass" {
		t.Errorf("expected store path, got %q", cfg.VaultGopassStore)
	}
}

func TestImportTOMLVaultChainProviders(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[vault]
providers = ["1password", "age"]

[vault.1password]
vault = "sluice-creds"
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.ConfigSet != 2 {
		t.Errorf("expected 2 config values set, got %d", res.ConfigSet)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if len(cfg.VaultProviders) != 2 || cfg.VaultProviders[0] != "1password" || cfg.VaultProviders[1] != "age" {
		t.Errorf("expected providers [1password, age], got %v", cfg.VaultProviders)
	}
	if cfg.Vault1PasswordVault != "sluice-creds" {
		t.Errorf("expected vault 'sluice-creds', got %q", cfg.Vault1PasswordVault)
	}
}

func TestImportTOMLBindingWithProtocols(t *testing.T) {
	s := newTestStore(t)

	data := []byte(`
[[binding]]
destination = "github.com"
ports = [22]
credential = "github_ssh_key"
protocols = ["ssh"]
`)

	res, err := s.ImportTOML(data)
	if err != nil {
		t.Fatalf("ImportTOML: %v", err)
	}
	if res.BindingsInserted != 1 {
		t.Errorf("expected 1 binding inserted, got %d", res.BindingsInserted)
	}

	bindings, err := s.ListBindings()
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if len(bindings[0].Protocols) != 1 || bindings[0].Protocols[0] != "ssh" {
		t.Errorf("expected protocols [ssh], got %v", bindings[0].Protocols)
	}
}
