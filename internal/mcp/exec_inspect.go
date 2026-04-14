package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
)

// DefaultExecToolPatterns are glob patterns matched against tool names
// to decide which tools should be subject to exec inspection. These
// cover the common naming conventions for shell and exec-capable tools.
//
// The patterns are anchored to the MCP namespace separator (`__`) so
// only tools that follow the `upstream__exec`/`upstream__shell` shape
// match. Bare exact names (`shell`, `bash`, `exec`) are also accepted
// for unprefixed tools. The earlier substring globs (`*exec*`,
// `*shell*`) caught lint/syntax tools like `shellcheck`,
// `shellharden`, and `vim__shellharden`, whose inputs legitimately
// contain shell metacharacters (`$`, `|`, `;`) and produced false
// positives in the metacharacter scan. ShouldInspect now returns
// false for those tools entirely so the metachar path never runs.
// Operators can override via NewExecInspector(customPatterns) when
// their deployment uses a different naming convention.
var DefaultExecToolPatterns = []string{
	"*__exec*",
	"*__shell",
	"*__bash",
	"*__run_command*",
	"*__terminal*",
	"shell",
	"bash",
	"exec",
}

// ExecInspectionResult holds the outcome of inspecting an exec-like
// tool call for dangerous patterns.
type ExecInspectionResult struct {
	Blocked  bool
	Reason   string
	Category string // "trampoline", "metachar", "dangerous_cmd", "env_override"
	Match    string // matched substring (for audit and debugging)
}

// shellToolPatternGlobs compile the substrings that identify a dedicated
// shell tool (e.g. "sandbox__shell", "host__bash"). Metacharacter checks
// are skipped for these tools because a shell tool is expected to receive
// commands containing $, |, etc. (e.g. `echo $HOME`). Trampoline and
// dangerous-command checks still run for shell tools.
//
// The globs are anchored after the MCP namespace separator (`__`) so only
// tools literally named `shell`/`bash` under their upstream match. This
// prevents false positives for tools whose names merely contain those
// substrings elsewhere: `github__shellcheck`, `github__bashrc`,
// `vim__shellharden`, and `vim__bashsyntax` will NOT be treated as shell
// tools. Tradeoff: tools with a suffix after the shell word (e.g.
// `host__shell_v2`) are also NOT matched. The project convention is
// `upstream__shell` / `upstream__bash` for dedicated shell tools, so
// the tighter anchor is a net win. Operators can opt into the looser
// behavior by passing a custom pattern list to NewExecInspector.
var shellToolPatternGlobs = []string{"*__shell", "*__bash", "shell", "bash"}

// ExecInspector detects trampoline interpreters, shell metacharacters,
// dangerous command invocations, and environment overrides in the
// arguments of exec-like MCP tools. It is configured with glob patterns
// that select which tool names are subject to inspection.
type ExecInspector struct {
	toolPatterns   []*policy.Glob
	shellPatterns  []*policy.Glob
	trampolines    []*regexp.Regexp
	metacharRe     *regexp.Regexp
	dangerousCmds  []*regexp.Regexp
	rmVerbRe       *regexp.Regexp
	rmRecursiveRe  *regexp.Regexp
	rmForceRe      *regexp.Regexp
	rmRootTargetRe *regexp.Regexp
	envBlacklist   []string
}

// NewExecInspector builds an inspector from the given tool name glob
// patterns. If toolPatterns is empty, DefaultExecToolPatterns is used.
// Trampoline, metacharacter, and dangerous-command regexes are fixed
// defaults that can be tuned later via the policy store.
func NewExecInspector(toolPatterns []string) (*ExecInspector, error) {
	if len(toolPatterns) == 0 {
		toolPatterns = DefaultExecToolPatterns
	}
	ei := &ExecInspector{}
	for _, p := range toolPatterns {
		g, err := policy.CompileGlob(p)
		if err != nil {
			return nil, fmt.Errorf("compile exec tool pattern %q: %w", p, err)
		}
		ei.toolPatterns = append(ei.toolPatterns, g)
	}
	for _, p := range shellToolPatternGlobs {
		g, err := policy.CompileGlob(p)
		if err != nil {
			return nil, fmt.Errorf("compile shell tool pattern %q: %w", p, err)
		}
		ei.shellPatterns = append(ei.shellPatterns, g)
	}

	// Trampoline patterns: interpreter invoked with a short flag to run
	// inline code. Matching is case-insensitive and requires whitespace
	// around the flag so that "exec -cat" does not trigger. Combined
	// into a single regex with three top-level alternatives so the
	// hot-path Inspect loop only runs one FindString per command
	// instead of three.
	//
	// The `-c` and `-e` flags may appear combined with other short
	// flags (POSIX allows `bash -ce 'cmd'` or `bash -ec 'cmd'`, which
	// are equivalent to `bash -c -e 'cmd'` and still execute inline
	// code). We match a single `-` followed by a run of [a-z]
	// characters that contains the relevant flag letter anywhere in
	// the run. The bounding `\b` on either side of the interpreter
	// name prevents matches inside longer tokens like `mybash`.
	trampolineRe, err := regexp.Compile(
		`(?i)\b(?:(?:bash|sh|zsh|fish|dash|ash|ksh)\s+-[a-z]*c[a-z]*|(?:python[23]?|ruby|perl)\s+-[a-z]*[ce][a-z]*|(?:node|nodejs)\s+-[a-z]*e[a-z]*)\b`,
	)
	if err != nil {
		return nil, fmt.Errorf("compile trampoline pattern: %w", err)
	}
	ei.trampolines = []*regexp.Regexp{trampolineRe}

	// Shell metacharacters that imply command chaining or substitution.
	// We treat them as indicators of attempted shell behavior from a
	// supposedly simple exec tool. A dedicated shell tool is caught
	// by the trampoline layer instead.
	//
	// Character class covers:
	//   `|` pipe, `;` command separator, `&` background/and,
	//   `$` variable expansion, backtick command substitution,
	//   `>` output redirect, `<` input redirect.
	// We avoid repeating `$(` and `||` since those are already covered
	// by `$` and `|` in the class. The old pattern had them as redundant
	// alternations.
	metacharRe, err := regexp.Compile(`[|;&$<>` + "`" + `]`)
	if err != nil {
		return nil, fmt.Errorf("compile metachar pattern: %w", err)
	}
	ei.metacharRe = metacharRe

	dangerousPatterns := []string{
		// chmod 777 or chmod 0777 (octal form), with optional -R flag.
		// Also catches setuid/setgid/sticky bit variants including all
		// combined-bit forms (1777, 2777, 3777, 4777, 5777, 6777, 7777)
		// plus 0-prefixed forms like 04777. The leading 0 is optional
		// and the first special-bit digit is any of [0-7]. Using the
		// wider [0-7] range (instead of the old [1246]) closes a hole
		// where attackers could set "setuid + sticky" (5777) or
		// "setgid + sticky" (3777) to escape the check. \b after 777
		// still matches a non-word boundary (space, slash, end of
		// string).
		`(?i)\bchmod\s+(-R\s+)?0?[0-7]?777\b`,
		// curl|wget piping to a language interpreter. Covers sh family
		// (sh/bash/zsh/dash/ash/ksh/fish) and common scripting languages
		// (python, perl, ruby, node, php) because any of these is a
		// viable target for remote code execution. The `fish` variant
		// is listed separately (not in the sh-prefix alternation)
		// because it does not share the sh/zsh/dash/ash/ksh prefix.
		`(?i)\b(curl|wget|fetch)\b[^|]*\|\s*((ba|z|da|a|k)?sh|fish|python[23]?|ruby|perl|node|php)\b`,
		`(?i)\bdd\s+if=/dev/`,
		`(?i)\bmkfs(\.[a-z0-9]+)?\b`,
		`(?i):\(\)\s*\{\s*:\|:`, // fork bomb
	}
	for _, p := range dangerousPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compile dangerous pattern %q: %w", p, err)
		}
		ei.dangerousCmds = append(ei.dangerousCmds, re)
	}

	// `rm -rf /` detection uses 4 separate regexes combined with AND
	// logic instead of a single mega-regex. The previous single-regex
	// approach (`\brm\s+-[a-z]*[rf][a-z]*\s+/`) missed common evasions:
	// flags split across separate tokens (`rm -r -f /`), the POSIX
	// end-of-options separator (`rm -rf -- /`), long-form flags inserted
	// between (`rm -rf --no-preserve-root /`), and mixed case (`rm -R
	// -f /`). Composing the check from independent matchers is far more
	// readable than the equivalent single regex, which would need to
	// handle arbitrary interleavings of short and long flags around the
	// recursive/force letters and the optional `--` separator.
	rmVerbRe, err := regexp.Compile(`(?i)\brm\b`)
	if err != nil {
		return nil, fmt.Errorf("compile rm verb pattern: %w", err)
	}
	ei.rmVerbRe = rmVerbRe
	// Recursive flag: a short cluster `-...r...` (any letters around r/R,
	// including standalone `-r`/`-R` and combined like `-rf`/`-Rfv`), or
	// the long form `--recursive`. Anchored to whitespace boundaries so
	// `-r` inside a path does not match.
	rmRecursiveRe, err := regexp.Compile(`(?i)(?:^|\s)-[a-zA-Z]*[rR][a-zA-Z]*(?:\s|$)|--recursive\b`)
	if err != nil {
		return nil, fmt.Errorf("compile rm recursive pattern: %w", err)
	}
	ei.rmRecursiveRe = rmRecursiveRe
	// Force flag: same shape as recursive, looking for f/F.
	rmForceRe, err := regexp.Compile(`(?i)(?:^|\s)-[a-zA-Z]*[fF][a-zA-Z]*(?:\s|$)|--force\b`)
	if err != nil {
		return nil, fmt.Errorf("compile rm force pattern: %w", err)
	}
	ei.rmForceRe = rmForceRe
	// Root target: a `/` argument that is exactly `/` (whitespace on both
	// sides, or end of string). Avoids matching `/tmp/foo`, `/etc`, etc.,
	// which are not whole-disk wipes. The `--` separator is not part of
	// this regex because flag tokens do not interfere with the `/` match
	// once whitespace boundaries are required.
	rmRootTargetRe, err := regexp.Compile(`(?:^|\s)/(?:\s|$)`)
	if err != nil {
		return nil, fmt.Errorf("compile rm root target pattern: %w", err)
	}
	ei.rmRootTargetRe = rmRootTargetRe

	// Environment variables that can be used to hijack credentialed
	// subprocess invocations (e.g. git fetch over SSH).
	//
	// TODO: expose this via a NewExecInspector option so operators can
	// add site-specific blacklisted env keys (e.g. HTTP_PROXY overrides
	// used to attack outbound proxies) without a code change. For now
	// the fixed list covers the primary attack classes: SSH command
	// override (GIT_SSH_COMMAND) and dynamic-linker hijacking
	// (LD_PRELOAD, LD_LIBRARY_PATH, DYLD_*).
	ei.envBlacklist = []string{
		"GIT_SSH_COMMAND",
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
	}

	return ei, nil
}

// ShouldInspect reports whether the given tool name matches any of the
// configured glob patterns.
func (ei *ExecInspector) ShouldInspect(toolName string) bool {
	if ei == nil {
		return false
	}
	return matchAnyGlob(ei.toolPatterns, toolName)
}

// isShellTool reports whether the tool is a dedicated shell-style tool for
// which shell metacharacters in arguments are expected and benign (e.g.
// `echo $HOME`). Trampoline and dangerous-command checks still apply to
// shell tools: the concern is only that metacharacter scanning would
// false-positive on every shell invocation.
func (ei *ExecInspector) isShellTool(toolName string) bool {
	return matchAnyGlob(ei.shellPatterns, toolName)
}

// matchAnyGlob returns true when the name matches at least one compiled
// glob in the list. Extracted so ShouldInspect and isShellTool do not
// duplicate the iteration loop.
func matchAnyGlob(globs []*policy.Glob, name string) bool {
	for _, g := range globs {
		if g.Match(name) {
			return true
		}
	}
	return false
}

// Inspect scans the arguments of an exec-like tool for dangerous
// patterns and returns the first finding (or a zero-value result if
// none matched). Arguments are parsed as JSON so that unicode-escaped
// payloads are decoded before pattern matching.
func (ei *ExecInspector) Inspect(toolName string, args json.RawMessage) ExecInspectionResult {
	if ei == nil || len(args) == 0 {
		return ExecInspectionResult{}
	}

	// Parse the JSON once so that we can walk it for both command
	// strings and env-override keys.
	var parsed interface{}
	if err := json.Unmarshal(args, &parsed); err != nil {
		return ExecInspectionResult{
			Blocked:  true,
			Reason:   fmt.Sprintf("exec argument inspection failed: %v", err),
			Category: "json_parse",
		}
	}

	// Check env overrides first. The env slot on exec-style tools is
	// typically a map of string -> string, but may also surface as a
	// list of "KEY=VALUE" strings. We recursively walk the parsed JSON
	// so nested shapes like {"config":{"env":{"GIT_SSH_COMMAND":"..."}}}
	// are also scanned.
	if res := ei.checkEnv(parsed); res.Blocked {
		return res
	}

	// Collect command-like strings. extractCommandStrings applies a
	// field-scoped scan over preferred command slots (command, cmd,
	// script, code, args, arguments, argv) and, when any of those are
	// present, known smuggle slots (input, stdin, body, data, payload).
	// Prose fields (description, notes, comment, etc.) are never
	// scanned to avoid flagging tool metadata that mentions dangerous
	// commands as example text.
	commandStrings := extractCommandStrings(parsed)

	skipMetachar := ei.isShellTool(toolName)
	for _, cmd := range commandStrings {
		if res := ei.inspectCommand(cmd, skipMetachar); res.Blocked {
			return res
		}
	}

	return ExecInspectionResult{}
}

// inspectCommand runs all command-level checks on a single string and
// returns the first matching result. When skipMetachar is true (dedicated
// shell tool), metacharacter scanning is skipped because shell commands
// legitimately contain `|`, `$`, `;`, etc.
func (ei *ExecInspector) inspectCommand(cmd string, skipMetachar bool) ExecInspectionResult {
	for _, re := range ei.trampolines {
		if m := re.FindString(cmd); m != "" {
			return ExecInspectionResult{
				Blocked:  true,
				Reason:   fmt.Sprintf("trampoline interpreter detected: %q", m),
				Category: "trampoline",
				Match:    m,
			}
		}
	}
	if res := ei.inspectRmRoot(cmd); res.Blocked {
		return res
	}
	for _, re := range ei.dangerousCmds {
		if m := re.FindString(cmd); m != "" {
			return ExecInspectionResult{
				Blocked:  true,
				Reason:   fmt.Sprintf("dangerous command detected: %q", m),
				Category: "dangerous_cmd",
				Match:    m,
			}
		}
	}
	if skipMetachar {
		return ExecInspectionResult{}
	}
	if m := ei.metacharRe.FindString(cmd); m != "" {
		return ExecInspectionResult{
			Blocked:  true,
			Reason:   fmt.Sprintf("shell metacharacter %q in exec arguments", m),
			Category: "metachar",
			Match:    m,
		}
	}
	return ExecInspectionResult{}
}

// inspectRmRoot returns a blocked result when cmd looks like an `rm`
// invocation that recursively force-removes `/`. The check requires all
// four signals together (verb, recursive flag, force flag, root target)
// because any one alone is benign (`rm file.txt`, `rm -r dir`, `rm -f
// file`, `cd /`). Whitespace is normalized to a single space before
// matching so spread-out flag tokens (`rm -rf -- /`) are detected the
// same way as the canonical form. The combined match catches every
// variant flagged by codex iter 5: split flags (`rm -r -f /`),
// end-of-options separator (`rm -rf -- /`), interspersed long flags
// (`rm -rf --no-preserve-root /`), uppercase form (`rm -R -f /`), and
// the canonical form. Returns ExecInspectionResult{} when any signal is
// missing.
func (ei *ExecInspector) inspectRmRoot(cmd string) ExecInspectionResult {
	if ei.rmVerbRe == nil {
		return ExecInspectionResult{}
	}
	// Normalize whitespace so a tab between flags or doubled spaces does
	// not break the boundary anchors in the regexes.
	normalized := strings.Join(strings.Fields(cmd), " ")
	if !ei.rmVerbRe.MatchString(normalized) {
		return ExecInspectionResult{}
	}
	if !ei.rmRecursiveRe.MatchString(normalized) {
		return ExecInspectionResult{}
	}
	if !ei.rmForceRe.MatchString(normalized) {
		return ExecInspectionResult{}
	}
	if !ei.rmRootTargetRe.MatchString(normalized) {
		return ExecInspectionResult{}
	}
	return ExecInspectionResult{
		Blocked:  true,
		Reason:   fmt.Sprintf("dangerous command detected: %q", normalized),
		Category: "dangerous_cmd",
		Match:    normalized,
	}
}

// envSlotNames lists the nested keys that are conventionally used to
// hold environment variable overrides on exec-style tools. Any of these
// names on a map trigger checkEnvSlot. Matching is case-insensitive
// (we lowercase the key before membership check) because agents and
// middleware often normalize case. Covers the bare names, a few common
// plural/verbose forms (`environment_variables`, `env_vars`), and the
// short `vars` alias that some tools expose.
var envSlotNames = map[string]struct{}{
	"env":                   {},
	"envs":                  {},
	"env_vars":              {},
	"envvars":               {},
	"environment":           {},
	"environments":          {},
	"environment_variables": {},
	"environmentvariables":  {},
	"vars":                  {},
}

// checkEnv walks the arguments recursively and returns a blocked result
// if any blacklisted environment variable name appears in an env slot.
// Keys are matched case-insensitively (strings.EqualFold) because an
// attacker can exploit case-mangling middleware to smuggle
// git_ssh_command past a case-sensitive check. Real-world env resolution
// is often case-normalized before execve. Nested shapes such as
// {"config":{"env":{"GIT_SSH_COMMAND":"..."}}} are handled by walking
// the full parsed tree.
//
// The env-slot detection is separate from extractCommandStrings' field
// scoping because env overrides can hide in any nested object (agents
// often accept nested task config), whereas command-string scanning
// needs a tighter scope to avoid false positives on prose fields.
func (ei *ExecInspector) checkEnv(parsed interface{}) ExecInspectionResult {
	var walk func(x interface{}) ExecInspectionResult
	walk = func(x interface{}) ExecInspectionResult {
		switch v := x.(type) {
		case map[string]interface{}:
			for k, child := range v {
				lowerKey := strings.ToLower(k)
				if _, ok := envSlotNames[lowerKey]; ok {
					if res := ei.checkEnvSlot(child); res.Blocked {
						return res
					}
					// Continue descending: the env slot might itself
					// contain a nested struct we should scan.
				}
				if res := walk(child); res.Blocked {
					return res
				}
			}
		case []interface{}:
			for _, child := range v {
				if res := walk(child); res.Blocked {
					return res
				}
			}
		}
		return ExecInspectionResult{}
	}
	return walk(parsed)
}

// checkEnvSlot inspects a single env slot value. The slot can surface in
// any of four shapes:
//
//  1. Flat map: `{"GIT_SSH_COMMAND":"..."}`
//  2. List of "KEY=VALUE" strings: `["HOME=/tmp","LD_PRELOAD=/tmp/evil.so"]`
//  3. List of `{"name":..., "value":...}` objects (Docker/Kubernetes
//     style and many MCP tool schemas).
//  4. List of `{"key":..., "val":...}` objects (less common but seen
//     in agent toolkits and CLI wrappers).
//
// Field-name matching for shapes 3 and 4 is case-insensitive
// (`name`/`Name`/`NAME`, `value`/`Value`/`VALUE`) so a Go struct
// without explicit json tags or a CamelCase MCP schema is not silently
// missed. Without these alternative shapes, a payload like
// `{"env":[{"name":"GIT_SSH_COMMAND","value":"/tmp/evil"}]}` would
// bypass the blacklist entirely and the SSH-command override would
// reach the subprocess.
func (ei *ExecInspector) checkEnvSlot(v interface{}) ExecInspectionResult {
	switch env := v.(type) {
	case map[string]interface{}:
		for key := range env {
			// Trim surrounding whitespace for the same reason as the
			// list-of-strings branch below. A JSON object key like
			// " GIT_SSH_COMMAND " is unusual but a trivial mistake or
			// deliberate evasion. TrimSpace handles both.
			trimmed := strings.TrimSpace(key)
			if ei.isBlacklistedEnvKey(trimmed) {
				return ExecInspectionResult{
					Blocked:  true,
					Reason:   fmt.Sprintf("env override detected: %q", trimmed),
					Category: "env_override",
					Match:    trimmed,
				}
			}
		}
	case []interface{}:
		for _, item := range env {
			switch entry := item.(type) {
			case string:
				if idx := strings.IndexByte(entry, '='); idx > 0 {
					// Trim surrounding whitespace so an attacker cannot
					// pad the key with spaces to bypass EqualFold (e.g.
					// " GIT_SSH_COMMAND =..."). Real env var names have
					// no whitespace, so stripping it is always safe and
					// blocks the bypass.
					key := strings.TrimSpace(entry[:idx])
					if ei.isBlacklistedEnvKey(key) {
						return ExecInspectionResult{
							Blocked:  true,
							Reason:   fmt.Sprintf("env override detected: %q", key),
							Category: "env_override",
							Match:    key,
						}
					}
				}
			case map[string]interface{}:
				// Structured list-of-objects shape. Pull the key field
				// (name/Name/NAME or key/Key/KEY/k/K) and check it
				// against the blacklist. The value field is inspected
				// only as part of paired-shape detection: if a non-key
				// field is present, the entry is treated as a key/val
				// pair and the key is matched. Otherwise (e.g. a free
				// map nested inside the env list), fall through.
				envKey := pickEnvObjectKey(entry)
				if envKey == "" {
					continue
				}
				trimmed := strings.TrimSpace(envKey)
				if ei.isBlacklistedEnvKey(trimmed) {
					return ExecInspectionResult{
						Blocked:  true,
						Reason:   fmt.Sprintf("env override detected: %q", trimmed),
						Category: "env_override",
						Match:    trimmed,
					}
				}
			}
		}
	}
	return ExecInspectionResult{}
}

// pickEnvObjectKey returns the env variable name from a structured env
// list entry such as `{"name":"GIT_SSH_COMMAND","value":"/tmp/evil"}`
// or `{"key":"LD_PRELOAD","val":"/tmp/evil.so"}`. Returns "" when no
// recognized key/value pair is present so the caller can fall through.
//
// The function looks for the key field (name, key, k) and confirms a
// paired value field (value, val, v) exists on the same object. This
// requirement prevents matching free-form objects nested inside the
// env list that happen to have a `name` field but are not env entries
// (e.g. a tool-config object). Both lookups are case-insensitive.
//
// String values are returned as-is. Non-string key fields (e.g. a
// nested object) are treated as no match because env names must be
// strings on every realistic platform.
func pickEnvObjectKey(entry map[string]interface{}) string {
	keyFields := []string{"name", "key", "k"}
	valueFields := []string{"value", "val", "v"}

	var keyVal string
	keyFound := false
	for k, v := range entry {
		lk := strings.ToLower(k)
		for _, kf := range keyFields {
			if lk == kf {
				if s, ok := v.(string); ok {
					keyVal = s
					keyFound = true
				}
				break
			}
		}
		if keyFound {
			break
		}
	}
	if !keyFound {
		return ""
	}

	// Confirm the entry has a paired value field. A bare `{"name":"X"}`
	// is ambiguous (could be a metadata object) and we do not want to
	// false-positive on it. Requiring the paired field anchors the
	// match to the env-entry shape.
	for k := range entry {
		lk := strings.ToLower(k)
		for _, vf := range valueFields {
			if lk == vf {
				return keyVal
			}
		}
	}
	return ""
}

func (ei *ExecInspector) isBlacklistedEnvKey(key string) bool {
	// Case-insensitive match so variants like git_ssh_command or
	// Git_Ssh_Command are caught. POSIX env var names are case-sensitive,
	// but agents will often normalize or mangle case before forwarding
	// the key, and we want to catch the underlying intent regardless of
	// surface formatting.
	for _, banned := range ei.envBlacklist {
		if strings.EqualFold(key, banned) {
			return true
		}
	}
	return false
}

// preferredCommandSlots lists the argument keys that are conventionally
// populated with executable command text. These are scanned first, and
// their presence also enables scanning of smuggleSlots below. Matching
// is case-insensitive via strings.EqualFold so payloads using
// PascalCase (`"Command"`) or SHOUTY_CASE (`"COMMAND"`) keys are not
// missed. Go structs without explicit json tags serialize as PascalCase,
// which is the most common bypass vector if matching were strict.
//
// Vocabulary covers the conventional names (`command`, `cmd`, `script`,
// `code`, `args`, `arguments`, `argv`) plus the alternative interpreter
// names exposed by Docker, Kubernetes, and a number of MCP tool schemas
// (`program`, `programname`, `executable`, `binary`, `interpreter`) and
// the full-command-line variants (`commandline`, `command_line`,
// `shellcommand`, `shell_command`, `bashcommand`, `bash_command`).
// Without these alternatives, a payload like
// `{"executable":"rm","args":["-rf","/"]}` would not be scanned at all.
var preferredCommandSlots = []string{
	"command", "cmd", "script", "code",
	"args", "arguments", "argv",
	"program", "programname",
	"executable", "binary", "interpreter",
	"commandline", "command_line",
	"shellcommand", "shell_command",
	"bashcommand", "bash_command",
}

// primaryCommandSlots lists the preferred slots that conventionally hold a
// string-valued executable name (e.g. `"command": "bash"`). Used together
// with argsSlots below to reconstruct a full command line when the agent
// splits the interpreter and its flags across slots (e.g.
// `{"command":"bash","args":["-c","id"]}`). Without the combined form,
// neither "bash" alone nor "-c id" alone matches the trampoline regex,
// allowing argv-smuggling bypasses. Case-insensitive match.
//
// Includes the alternative interpreter-name slots (`program`,
// `programname`, `executable`, `binary`, `interpreter`) so payloads
// like `{"executable":"rm","args":["-rf","/"]}` synthesize a combined
// "rm -rf /" candidate. The full-command-line variants
// (`commandline`/`shell_command`/etc.) are intentionally excluded here:
// they already hold the entire command line as a single string, so the
// per-slot scan in Pass 1 catches them and combining them with args
// would just produce a duplicate candidate.
var primaryCommandSlots = []string{
	"command", "cmd", "script", "code",
	"program", "programname",
	"executable", "binary", "interpreter",
}

// argsSlots lists the preferred slots that conventionally hold an
// argv-style array of flag and value elements. When one of these coexists
// with a primary slot on the same object, extractCommandStrings emits an
// additional combined candidate string ("<primary> <joined args>") so the
// trampoline and dangerous-command regexes can match across the boundary.
// Case-insensitive match.
var argsSlots = []string{"args", "arguments", "argv"}

// smuggleSlots lists argument keys that are not primarily meant to hold
// command text, but are known smuggle vectors: an attacker can stash a
// dangerous payload here while putting benign content in the preferred
// slot, then rely on the tool routing the smuggle slot into a shell.
// Two-tier handling:
//
//  1. When a preferred slot is also present at the same level, smuggle
//     slots are scanned alongside it (the conventional case where an
//     exec-style tool exposes both `command` and `stdin`).
//
//  2. When NO preferred slot exists at a level but a smuggle slot IS
//     present, the smuggle slot is scanned as the presumed command.
//     Justification: ShouldInspect already gated us in by tool name
//     (e.g. `shell__exec`, `terminal__run`), so we know the tool's
//     primary interface is exec-related. A schema whose only command
//     field is named `input` (`{"input":"bash -c ..."}`) must not
//     bypass the hard block just because the field name is unusual.
//
// Case-insensitive match.
var smuggleSlots = []string{"input", "stdin", "body", "data", "payload"}

// excludedProseSlots lists argument keys that are conventionally used
// for human-readable prose (tool metadata, free-form notes). Scanning
// these produces false positives because legitimate documentation can
// mention `bash -c` or `rm -rf /` as example or warning text. Never
// scanned by extractCommandStrings. Case-insensitive match: keys are
// already lower-cased before lookup so PascalCase Description and
// SHOUTY_CASE NOTES are excluded.
var excludedProseSlots = map[string]struct{}{
	"description":   {},
	"notes":         {},
	"comment":       {},
	"documentation": {},
	"summary":       {},
	"title":         {},
	"name":          {},
}

// matchesAnySlot returns true when key matches any of the configured
// slot names case-insensitively (via strings.EqualFold). The slot lists
// are short fixed sets, so the linear scan is cheap. Centralizing the
// matching makes it trivial to extend the slot vocabulary later without
// hunting down every call site.
func matchesAnySlot(key string, slots []string) bool {
	for _, s := range slots {
		if strings.EqualFold(key, s) {
			return true
		}
	}
	return false
}

// maxSlotRecursionDepth caps how deep extractCommandStrings recurses
// into wrapped schemas (e.g. {"request":{"command":"..."}} or
// {"params":{"cmd":"..."}}). 8 levels is generous enough to catch
// realistic agent-framework wrappers (tool -> input -> arguments ->
// command pattern is at most 4-5 deep) while preventing stack
// exhaustion on adversarially-crafted deep payloads. The recursion
// also short-circuits on excluded prose slots, so even within the
// budget the scan does not touch description/notes subtrees.
const maxSlotRecursionDepth = 8

// extractCommandStrings returns a deterministic slice of strings to
// inspect. It scans:
//
//  1. All preferred command slots (`command`, `cmd`, `script`, `code`,
//     `args`, `arguments`, `argv`). For array-shaped slots, both each
//     element and a joined form are emitted so the trampoline regex can
//     match across elements (`{"args":["bash","-c","evil"]}` becomes
//     "bash -c evil").
//
//  2. A combined candidate string when both a primary slot (command, cmd,
//     script, code) and an args slot (args, arguments, argv) are present
//     on the same object. The combined form ("<primary> <joined args>")
//     closes the argv-smuggling gap where an attacker splits the
//     interpreter and its flags across slots (`{"command":"bash",
//     "args":["-c","id"]}`). Without the combined form, neither "bash"
//     alone nor "-c id" alone matches the trampoline regex that expects
//     both tokens in the same string.
//
//  3. The known smuggle slots (`input`, `stdin`, `body`, `data`,
//     `payload`) are always scanned when ShouldInspect matched the tool
//     name. Two cases:
//
//     a. Preferred slot present at the same level: smuggle slots are
//     scanned alongside (the conventional `{"command":"cat",
//     "stdin":"bash -c ..."}` smuggling vector).
//
//     b. No preferred slot at this level: smuggle slots are scanned
//     as the presumed command. Tool names that match an exec glob
//     (`shell__exec`, `terminal__run`) are presumed to have an
//     exec-style primary interface, so an unusual schema like
//     `{"input":"bash -c ..."}` must not bypass the hard block.
//
// Slot keys are matched case-insensitively (strings.EqualFold) so
// PascalCase or SHOUTY_CASE keys do not bypass the scanner. Go structs
// without explicit json tags serialize as `Command`/`Args`/`Cmd`, which
// is the common bypass vector if matching were strict.
//
// Wrapped schemas (`{"request":{"command":"..."}}`,
// `{"params":{"cmd":"..."}}`, `{"tool":{"input":{"command":"..."}}}`)
// are caught by recursing into nested maps and reapplying the same
// slot logic at each level. Recursion stops at maxSlotRecursionDepth
// to bound stack usage on adversarial deep payloads, and skips any
// nested map keyed under a prose slot (description, notes, comment,
// documentation, summary, title, name) so legitimate metadata
// referencing dangerous commands does not false-positive.
//
// For non-map payloads (top-level array or string) all leaves are
// scanned because there is no field name to exclude.
//
// The returned slice is sorted so that inspectCommand's first-match
// semantics produce a deterministic category for payloads with
// multiple violations. Without sorting, map-iteration order would
// make the reported category non-deterministic across runs.
func extractCommandStrings(parsed interface{}) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	add := func(s string) {
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// Non-map payloads (top-level array or plain string) have no
	// recognized field names so we scan all leaves. For top-level
	// arrays we also emit a joined form so argv-style payloads like
	// ["bash","-c","evil"] can match the trampoline regex that
	// expects the full "bash -c" token.
	if _, isMap := parsed.(map[string]interface{}); !isMap {
		for _, s := range flattenStrings(parsed) {
			add(s)
		}
		if arr, isArr := parsed.([]interface{}); isArr {
			add(joinArrayStrings(arr))
		}
		sort.Strings(out)
		return out
	}

	scanMapAtDepth(parsed.(map[string]interface{}), 0, add)

	// Sort for deterministic first-match category. Without sorting,
	// iteration order over the map above would be randomized across
	// runs and a payload with multiple violations could report different
	// categories on different runs.
	sort.Strings(out)
	return out
}

// scanMapAtDepth applies the slot-matching logic at one level of a
// JSON object and recurses into eligible nested maps. The depth
// parameter caps recursion at maxSlotRecursionDepth so an adversarially
// deep wrapper (e.g. {"a":{"b":{"c":...}}}) cannot blow the stack.
//
// The same slot logic runs at every depth: preferred command slots,
// combined primary+args reconstruction, and gated smuggle slot scan.
// Nested maps that are NOT keyed under an excluded prose slot are
// recursed into. This means a `Command` field nested under `request`
// or `params` is scanned at the appropriate child depth; a `command`
// field nested under `description` is correctly skipped because the
// recursion stops at the prose boundary.
func scanMapAtDepth(m map[string]interface{}, depth int, add func(string)) {
	// Pass 1: preferred command slots at this level.
	for k, v := range m {
		if !matchesAnySlot(k, preferredCommandSlots) {
			continue
		}
		collectSlotStrings(v, add)

		// For array-shaped preferred slots, also emit a joined form so
		// the trampoline regex can match across elements even when no
		// single element contains the full "bash -c" token.
		if arr, isArr := v.([]interface{}); isArr {
			add(joinArrayStrings(arr))
		}
	}

	// Pass 1b: reconstruct a combined command line across slots to close
	// the argv-smuggling gap. When a payload provides the interpreter in
	// a primary slot and its flags in an args array (the conventional
	// `{"command":"bash","args":["-c","id"]}` shape), neither "bash" nor
	// "-c id" alone matches the trampoline/dangerous regexes, which
	// require both tokens in the same string. By combining them we give
	// the regex a full command line to match against, catching the
	// cross-slot smuggling vector.
	//
	// We collect primary + args candidates first, then synthesize the
	// cartesian product. The resulting set is small in practice because
	// tools use at most one of (command, cmd, script, code) and one of
	// (args, arguments, argv).
	primaries := make([]string, 0, 2)
	argLists := make([][]interface{}, 0, 2)
	for k, v := range m {
		if matchesAnySlot(k, primaryCommandSlots) {
			if s, ok := v.(string); ok && s != "" {
				primaries = append(primaries, s)
			}
		}
		if matchesAnySlot(k, argsSlots) {
			if arr, ok := v.([]interface{}); ok {
				argLists = append(argLists, arr)
			}
		}
	}
	for _, pStr := range primaries {
		for _, arr := range argLists {
			joined := joinArrayStrings(arr)
			if joined == "" {
				add(pStr)
				continue
			}
			add(pStr + " " + joined)
		}
	}

	// Pass 2: smuggle slots are always scanned when ShouldInspect
	// matched the tool name. The previous gating (only when a preferred
	// slot was present) was reversed by codex iter 3 review: ShouldInspect
	// already established the tool's primary interface is exec-related,
	// so a schema whose only command field is named `input` must not
	// bypass the hard block. Both the `command + stdin smuggle` case and
	// the `only-input` case are caught.
	for k, v := range m {
		if !matchesAnySlot(k, smuggleSlots) {
			continue
		}
		collectSlotStrings(v, add)
	}

	// Pass 3: recurse into nested maps to catch wrapped schemas. Skip
	// nested maps keyed under a prose slot (description, notes, comment,
	// etc.) so legitimate documentation that happens to nest objects
	// with a `command` key inside example text is not scanned.
	//
	// We DO recurse into preferred/smuggle slot subtrees when they hold
	// a map. collectSlotStrings already walked the leaves there, but it
	// does not apply slot logic at deeper levels. Without recursing,
	// payloads like {"tool":{"input":{"command":"bash","args":["-c","id"]}}}
	// would miss the combined-candidate reconstruction. The `add`
	// closure deduplicates via the seen set, so re-emitting leaves
	// already added by collectSlotStrings is harmless.
	if depth+1 >= maxSlotRecursionDepth {
		return
	}
	for k, v := range m {
		if _, skip := excludedProseSlots[strings.ToLower(k)]; skip {
			continue
		}
		switch child := v.(type) {
		case map[string]interface{}:
			scanMapAtDepth(child, depth+1, add)
		case []interface{}:
			// Walk array elements: any nested map element gets the same
			// recursive treatment so {"items":[{"command":"bash -c"}]}
			// is also caught.
			for _, item := range child {
				if childMap, isMap := item.(map[string]interface{}); isMap {
					scanMapAtDepth(childMap, depth+1, add)
				}
			}
		}
	}
}

// collectSlotStrings walks a slot value (from a preferred or smuggle
// slot) and emits each string leaf via add. Honors the prose-field
// exclusion list for any nested maps so `{"args":{"description":"rm -rf
// /"}}` still skips the prose leaf even though it lives under a
// scanned top-level slot.
func collectSlotStrings(v interface{}, add func(string)) {
	switch val := v.(type) {
	case string:
		add(val)
	case []interface{}:
		for _, child := range val {
			collectSlotStrings(child, add)
		}
	case map[string]interface{}:
		for k, child := range val {
			if _, skip := excludedProseSlots[strings.ToLower(k)]; skip {
				continue
			}
			collectSlotStrings(child, add)
		}
	}
}

// joinArrayStrings joins the string leaves of a []interface{} with
// spaces so that argv-style arguments can be matched as a single
// command line.
func joinArrayStrings(arr []interface{}) string {
	parts := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			continue
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// flattenStrings walks a JSON-decoded value and returns all string
// leaves, excluding map keys. Delegates to walkJSON with includeKeys=false
// so exec detection does not pick up JSON object keys as command text
// (unlike ContentInspector.extractStrings, which calls walkJSON with
// includeKeys=true because block patterns should match both keys and
// values).
func flattenStrings(v interface{}) []string {
	var out []string
	walkJSON(v, false, func(s string) { out = append(out, s) })
	return out
}
