package telegram

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nemirovsky/sluice/internal/docker"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// Command represents a parsed Telegram command.
type Command struct {
	Name string
	Args []string
}

// ParseCommand parses a Telegram message into a Command.
// Returns nil if the message is not a command (doesn't start with /).
func ParseCommand(text string) *Command {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "/") {
		return nil
	}
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return nil
	}
	name := strings.TrimPrefix(parts[0], "/")
	// Strip @botname suffix (e.g. /policy@mybot -> policy)
	if idx := strings.Index(name, "@"); idx >= 0 {
		name = name[:idx]
	}
	return &Command{
		Name: name,
		Args: parts[1:],
	}
}

// CommandHandler holds the dependencies needed by command handlers.
type CommandHandler struct {
	engine     *atomic.Pointer[policy.Engine]
	reloadMu   *sync.Mutex // shared with proxy; serializes engine swaps and policy mutations
	broker     *ApprovalBroker
	auditPath  string
	vault      *vault.Store
	dockerMgr  *docker.Manager
	store      *store.Store
	phantomDir string // shared volume path for phantom token files
}

// SetVault enables credential management commands.
func (h *CommandHandler) SetVault(store *vault.Store) {
	h.vault = store
}

// SetDockerManager enables automatic container restart on credential changes.
func (h *CommandHandler) SetDockerManager(mgr *docker.Manager) {
	h.dockerMgr = mgr
}

// SetStore enables persistent policy management via SQLite.
func (h *CommandHandler) SetStore(s *store.Store) {
	h.store = s
}

// SetPhantomDir sets the shared volume path for phantom token files.
func (h *CommandHandler) SetPhantomDir(dir string) {
	h.phantomDir = dir
}

// recompileAndSwap rebuilds the policy Engine from the SQLite store and
// atomically swaps it into the shared engine pointer. The caller must hold
// reloadMu.
func (h *CommandHandler) recompileAndSwap() error {
	newEng, err := policy.LoadFromStore(h.store)
	if err != nil {
		return err
	}
	if err := newEng.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	h.engine.Store(newEng)
	return nil
}

// NewCommandHandler creates a command handler that shares the proxy's engine
// pointer and reload mutex. Sharing these prevents split-brain windows during
// SIGHUP reloads: a single mutex serializes engine swaps and policy mutations
// across both the proxy and the bot.
func NewCommandHandler(enginePtr *atomic.Pointer[policy.Engine], reloadMu *sync.Mutex, broker *ApprovalBroker, auditPath string) *CommandHandler {
	return &CommandHandler{
		engine:    enginePtr,
		reloadMu:  reloadMu,
		broker:    broker,
		auditPath: auditPath,
	}
}

// Handle dispatches a command to the appropriate handler and returns the response text.
// Returns empty string if the command is not recognized.
func (h *CommandHandler) Handle(cmd *Command) string {
	switch cmd.Name {
	case "policy":
		return h.handlePolicy(cmd.Args)
	case "cred":
		return h.handleCred(cmd.Args)
	case "status":
		return h.handleStatus()
	case "audit":
		return h.handleAudit(cmd.Args)
	case "help":
		return h.handleHelp()
	default:
		return fmt.Sprintf("Unknown command: /%s\nType /help for available commands.", cmd.Name)
	}
}

func (h *CommandHandler) handlePolicy(args []string) string {
	if len(args) == 0 {
		return "Usage: /policy show | /policy allow <dest> | /policy deny <dest> | /policy remove <id>"
	}
	switch args[0] {
	case "show":
		return h.policyShow()
	case "allow":
		if len(args) < 2 {
			return "Usage: /policy allow <destination>"
		}
		return h.policyAllow(args[1])
	case "deny":
		if len(args) < 2 {
			return "Usage: /policy deny <destination>"
		}
		return h.policyDeny(args[1])
	case "remove":
		if len(args) < 2 {
			return "Usage: /policy remove <id>"
		}
		return h.policyRemove(args[1])
	default:
		return fmt.Sprintf("Unknown policy subcommand: %s", args[0])
	}
}

func (h *CommandHandler) policyShow() string {
	if h.store != nil {
		return h.policyShowFromStore()
	}
	// Fallback to engine snapshot when store is not configured.
	snap := h.engine.Load().Snapshot()
	var b strings.Builder
	b.WriteString("Current policy (default: ")
	b.WriteString(snap.Default.String())
	b.WriteString(")\n\n")

	for _, section := range []struct {
		label string
		rules []policy.Rule
	}{
		{"ALLOW", snap.AllowRules},
		{"DENY", snap.DenyRules},
		{"ASK", snap.AskRules},
	} {
		if len(section.rules) == 0 {
			continue
		}
		b.WriteString(section.label)
		b.WriteString(":\n")
		for _, r := range section.rules {
			b.WriteString("  ")
			b.WriteString(r.Destination)
			if len(r.Ports) > 0 {
				b.WriteString(" ports=")
				b.WriteString(formatPorts(r.Ports))
			}
			b.WriteString("\n")
		}
	}

	if len(snap.AllowRules) == 0 && len(snap.DenyRules) == 0 && len(snap.AskRules) == 0 {
		b.WriteString("No rules configured.")
	}

	return b.String()
}

func (h *CommandHandler) policyShowFromStore() string {
	dv, err := h.store.GetConfig("default_verdict")
	if err != nil {
		return fmt.Sprintf("Failed to read config: %v", err)
	}
	if dv == "" {
		dv = "deny"
	}

	rules, err := h.store.ListRules("")
	if err != nil {
		return fmt.Sprintf("Failed to list rules: %v", err)
	}

	var b strings.Builder
	b.WriteString("Current policy (default: ")
	b.WriteString(dv)
	b.WriteString(")\n\n")

	for _, section := range []struct {
		label   string
		verdict string
	}{
		{"ALLOW", "allow"},
		{"DENY", "deny"},
		{"ASK", "ask"},
	} {
		var sectionRules []store.NetworkRule
		for _, r := range rules {
			if r.Verdict == section.verdict {
				sectionRules = append(sectionRules, r)
			}
		}
		if len(sectionRules) == 0 {
			continue
		}
		b.WriteString(section.label)
		b.WriteString(":\n")
		for _, r := range sectionRules {
			fmt.Fprintf(&b, "  [%d] %s", r.ID, r.Destination)
			if len(r.Ports) > 0 {
				b.WriteString(" ports=")
				b.WriteString(formatPorts(r.Ports))
			}
			b.WriteString("\n")
		}
	}

	if len(rules) == 0 {
		b.WriteString("No rules configured.")
	}

	return b.String()
}

// inMemoryWarning is appended to policy mutation responses to remind operators
// that changes are not persisted to disk and will be lost on SIGHUP or restart.
const inMemoryWarning = "\n(in-memory only, will be lost on reload/restart)"

func (h *CommandHandler) policyAllow(dest string) string {
	if _, err := policy.CompileGlob(dest); err != nil {
		return fmt.Sprintf("Invalid destination pattern: %v", err)
	}

	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	if h.store != nil {
		if _, err := h.store.AddRule("allow", dest, nil, store.RuleOpts{Source: "telegram"}); err != nil {
			return fmt.Sprintf("Failed to add allow rule: %v", err)
		}
		if err := h.recompileAndSwap(); err != nil {
			return fmt.Sprintf("Added allow rule but failed to recompile: %v", err)
		}
		return fmt.Sprintf("Added allow rule: %s", dest)
	}

	// Fallback to in-memory mutation when store is not configured.
	if err := h.engine.Load().AddAllowRule(dest); err != nil {
		return fmt.Sprintf("Failed to add allow rule: %v", err)
	}
	return fmt.Sprintf("Added allow rule: %s%s", dest, inMemoryWarning)
}

func (h *CommandHandler) policyDeny(dest string) string {
	if _, err := policy.CompileGlob(dest); err != nil {
		return fmt.Sprintf("Invalid destination pattern: %v", err)
	}

	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	if h.store != nil {
		if _, err := h.store.AddRule("deny", dest, nil, store.RuleOpts{Source: "telegram"}); err != nil {
			return fmt.Sprintf("Failed to add deny rule: %v", err)
		}
		if err := h.recompileAndSwap(); err != nil {
			return fmt.Sprintf("Added deny rule but failed to recompile: %v", err)
		}
		return fmt.Sprintf("Added deny rule: %s", dest)
	}

	if err := h.engine.Load().AddDenyRule(dest); err != nil {
		return fmt.Sprintf("Failed to add deny rule: %v", err)
	}
	return fmt.Sprintf("Added deny rule: %s%s", dest, inMemoryWarning)
}

func (h *CommandHandler) policyRemove(idStr string) string {
	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	if h.store != nil {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return fmt.Sprintf("Invalid rule ID: %s (must be a number, use /policy show to see IDs)", idStr)
		}
		removed, err := h.store.RemoveRule(id)
		if err != nil {
			return fmt.Sprintf("Failed to remove rule: %v", err)
		}
		if !removed {
			return fmt.Sprintf("No rule found with ID: %d", id)
		}
		if err := h.recompileAndSwap(); err != nil {
			return fmt.Sprintf("Removed rule but failed to recompile: %v", err)
		}
		return fmt.Sprintf("Removed rule ID: %d", id)
	}

	// Fallback to in-memory mutation when store is not configured.
	removed, err := h.engine.Load().RemoveRule(idStr)
	if !removed {
		return fmt.Sprintf("No rule found for: %s", idStr)
	}
	if err != nil {
		return fmt.Sprintf("Failed to remove rule (compile error, rolled back): %v", err)
	}
	return fmt.Sprintf("Removed rule: %s%s", idStr, inMemoryWarning)
}

func (h *CommandHandler) handleCred(args []string) string {
	if len(args) == 0 {
		return "Usage: /cred add <name> <value> | /cred list | /cred rotate <name> <value> | /cred remove <name>"
	}
	if h.vault == nil {
		return "Credential management is not available (vault not configured)."
	}

	switch args[0] {
	case "list":
		return h.credList()
	case "add":
		if len(args) < 3 {
			return "Usage: /cred add <name> <value>"
		}
		return h.credAdd(args[1], strings.Join(args[2:], " "))
	case "rotate":
		if len(args) < 3 {
			return "Usage: /cred rotate <name> <value>"
		}
		return h.credRotate(args[1], strings.Join(args[2:], " "))
	case "remove":
		if len(args) < 2 {
			return "Usage: /cred remove <name>"
		}
		return h.credRemove(args[1])
	default:
		return fmt.Sprintf("Unknown cred subcommand: %s", args[0])
	}
}

func (h *CommandHandler) credList() string {
	names, err := h.vault.List()
	if err != nil {
		return fmt.Sprintf("Failed to list credentials: %v", err)
	}
	if len(names) == 0 {
		return "No credentials stored."
	}
	var b strings.Builder
	b.WriteString("Stored credentials:\n")
	for _, n := range names {
		b.WriteString("  ")
		b.WriteString(n)
		b.WriteString("\n")
	}
	return b.String()
}

func (h *CommandHandler) credAdd(name, value string) string {
	if err := h.vault.Add(name, value); err != nil {
		return fmt.Sprintf("Failed to add credential: %v", err)
	}
	return h.credMutationComplete(fmt.Sprintf("Added credential: %s", name))
}

func (h *CommandHandler) credRotate(name, value string) string {
	existing, err := h.vault.Get(name)
	if err != nil {
		return fmt.Sprintf("Credential %q not found. Use /cred add to create new credentials.", name)
	}
	existing.Release()
	if err := h.vault.Add(name, value); err != nil {
		return fmt.Sprintf("Failed to rotate credential: %v", err)
	}
	return h.credMutationComplete(fmt.Sprintf("Rotated credential: %s", name))
}

func (h *CommandHandler) credRemove(name string) string {
	// Clean up associated bindings and auto-created rules before removing,
	// mirroring the CLI cred remove behavior (cmd/sluice/cred.go).
	if h.store != nil {
		bindings, err := h.store.ListBindingsByCredential(name)
		if err == nil {
			for _, b := range bindings {
				h.store.RemoveRulesByDestinationAndSource(b.Destination, "cred-add")
			}
		}
		h.store.RemoveBindingsByCredential(name)
	}

	if err := h.vault.Remove(name); err != nil {
		return fmt.Sprintf("Failed to remove credential: %v", err)
	}
	return h.credMutationComplete(fmt.Sprintf("Removed credential: %s", name), name)
}

func (h *CommandHandler) credMutationComplete(msg string, removedCreds ...string) string {
	if h.dockerMgr == nil {
		return msg
	}

	names, err := h.vault.List()
	if err != nil {
		return msg + "\nWarning: failed to list credentials for container update: " + err.Error()
	}

	phantomEnv := docker.GeneratePhantomEnv(names)
	// Mark removed credentials with empty values so they are cleaned up.
	for _, removed := range removedCreds {
		envVar := docker.CredNameToEnvVar(removed)
		if _, exists := phantomEnv[envVar]; !exists {
			phantomEnv[envVar] = ""
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Prefer hot-reload via shared volume when phantomDir is configured.
	if h.phantomDir != "" {
		if err := h.dockerMgr.ReloadSecrets(ctx, h.phantomDir, phantomEnv); err != nil {
			return msg + "\nWarning: failed to reload agent secrets: " + err.Error()
		}
		return msg + "\nAgent secrets reloaded."
	}

	// Fallback to full container restart.
	if err := h.dockerMgr.RestartWithEnv(ctx, phantomEnv); err != nil {
		return msg + "\nWarning: failed to restart agent container: " + err.Error()
	}
	return msg + "\nAgent container restarted with updated credentials."
}

func (h *CommandHandler) handleStatus() string {
	snap := h.engine.Load().Snapshot()
	var b strings.Builder
	b.WriteString("Sluice Status\n\n")

	b.WriteString("Policy: ")
	fmt.Fprintf(&b, "%d allow, %d deny, %d ask rules",
		len(snap.AllowRules), len(snap.DenyRules), len(snap.AskRules))
	fmt.Fprintf(&b, " (default: %s)\n", snap.Default)

	if h.broker != nil {
		fmt.Fprintf(&b, "Pending approvals: %d\n", h.broker.PendingCount())
	}

	return b.String()
}

func (h *CommandHandler) handleAudit(args []string) string {
	const maxAuditLines = 50
	count := 10
	if len(args) >= 2 && args[0] == "recent" {
		n, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Sprintf("Invalid count %q: must be a positive integer.", args[1])
		}
		if n < 1 {
			return "Count must be a positive integer."
		}
		count = n
		if count > maxAuditLines {
			count = maxAuditLines
		}
	} else if len(args) >= 1 && args[0] == "recent" {
		// default count
	} else if len(args) > 0 {
		return "Usage: /audit recent [N]"
	}

	if h.auditPath == "" {
		return "Audit log not configured."
	}

	lines, err := readLastLines(h.auditPath, count)
	if err != nil {
		return fmt.Sprintf("Failed to read audit log: %v", err)
	}
	if len(lines) == 0 {
		return "Audit log is empty."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Last %d audit entries:\n\n", len(lines)))
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (h *CommandHandler) handleHelp() string {
	help := `Available commands:

/policy show - List current rules
/policy allow <dest> - Add allow rule
/policy deny <dest> - Add deny rule
/policy remove <id> - Remove rule by ID
/status - Show proxy status
/audit recent [N] - Show last N audit entries
/help - Show this message`

	if h.vault != nil {
		help += `

/cred list - List stored credentials
/cred add <name> <value> - Add credential
/cred rotate <name> <value> - Rotate credential
/cred remove <name> - Remove credential`
	}
	return help
}

// IsAuthorizedChat checks if a message sender's chat ID matches the configured one.
func IsAuthorizedChat(senderChatID, configuredChatID int64) bool {
	return senderChatID == configuredChatID
}

func formatPorts(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ",")
}

// readLastLines reads the last n lines from a file by reading backwards from
// the end, so that I/O cost is proportional to the returned lines rather than
// the total file size. This prevents large audit logs from blocking the caller.
func readLastLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size == 0 {
		return nil, nil
	}

	// Read backwards from end of file in chunks until we have enough
	// newlines to extract n complete lines.
	const chunkSize = 4096
	offset := size
	newlineCount := 0
	var chunks [][]byte

	for offset > 0 {
		readLen := int64(chunkSize)
		if readLen > offset {
			readLen = offset
		}
		offset -= readLen

		chunk := make([]byte, readLen)
		if _, err := f.ReadAt(chunk, offset); err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)

		for _, b := range chunk {
			if b == '\n' {
				newlineCount++
			}
		}
		// n+1 newlines guarantees n complete lines even when file ends with \n.
		if newlineCount > n {
			break
		}
	}

	// Reverse chunks (they were accumulated back-to-front) and concatenate.
	for i, j := 0, len(chunks)-1; i < j; i, j = i+1, j-1 {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	buf := make([]byte, 0, total)
	for _, c := range chunks {
		buf = append(buf, c...)
	}

	lines := strings.Split(string(buf), "\n")
	// Trim empty trailing entry from file ending with \n.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil, nil
	}
	// Take last n lines.
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
