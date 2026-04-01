package telegram

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/nemirovsky/sluice/internal/policy"
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
	engine    atomic.Pointer[policy.Engine]
	broker    *ApprovalBroker
	auditPath string
}

// NewCommandHandler creates a command handler with the given dependencies.
func NewCommandHandler(engine *policy.Engine, broker *ApprovalBroker, auditPath string) *CommandHandler {
	h := &CommandHandler{
		broker:    broker,
		auditPath: auditPath,
	}
	h.engine.Store(engine)
	return h
}

// UpdateEngine replaces the policy engine used by command handlers.
// Called on SIGHUP policy reload to keep the bot in sync with the proxy.
func (h *CommandHandler) UpdateEngine(eng *policy.Engine) {
	h.engine.Store(eng)
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
		return "Usage: /policy show | /policy allow <dest> | /policy deny <dest> | /policy remove <dest>"
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
			return "Usage: /policy remove <destination>"
		}
		return h.policyRemove(args[1])
	default:
		return fmt.Sprintf("Unknown policy subcommand: %s", args[0])
	}
}

func (h *CommandHandler) policyShow() string {
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

// inMemoryWarning is appended to policy mutation responses to remind operators
// that changes are not persisted to disk and will be lost on SIGHUP or restart.
const inMemoryWarning = "\n(in-memory only, will be lost on reload/restart)"

func (h *CommandHandler) policyAllow(dest string) string {
	if err := h.engine.Load().AddAllowRule(dest); err != nil {
		return fmt.Sprintf("Failed to add allow rule: %v", err)
	}
	return fmt.Sprintf("Added allow rule: %s%s", dest, inMemoryWarning)
}

func (h *CommandHandler) policyDeny(dest string) string {
	if err := h.engine.Load().AddDenyRule(dest); err != nil {
		return fmt.Sprintf("Failed to add deny rule: %v", err)
	}
	return fmt.Sprintf("Added deny rule: %s%s", dest, inMemoryWarning)
}

func (h *CommandHandler) policyRemove(dest string) string {
	removed, err := h.engine.Load().RemoveRule(dest)
	if !removed {
		return fmt.Sprintf("No rule found for: %s", dest)
	}
	if err != nil {
		return fmt.Sprintf("Failed to remove rule (compile error, rolled back): %v", err)
	}
	return fmt.Sprintf("Removed rule: %s%s", dest, inMemoryWarning)
}

func (h *CommandHandler) handleCred(args []string) string {
	if len(args) == 0 {
		return "Usage: /cred add <name> | /cred list | /cred rotate <name> | /cred remove <name>"
	}
	return "Credential management is not available (vault not configured)."
}

func (h *CommandHandler) handleStatus() string {
	snap := h.engine.Load().Snapshot()
	var b strings.Builder
	b.WriteString("Sluice Status\n\n")

	b.WriteString("Policy: ")
	b.WriteString(fmt.Sprintf("%d allow, %d deny, %d ask rules",
		len(snap.AllowRules), len(snap.DenyRules), len(snap.AskRules)))
	b.WriteString(fmt.Sprintf(" (default: %s)\n", snap.Default))

	if h.broker != nil {
		b.WriteString(fmt.Sprintf("Pending approvals: %d\n", h.broker.PendingCount()))
	}

	return b.String()
}

func (h *CommandHandler) handleAudit(args []string) string {
	const maxAuditLines = 50
	count := 10
	if len(args) >= 2 && args[0] == "recent" {
		if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
			count = n
			if count > maxAuditLines {
				count = maxAuditLines
			}
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
	return `Available commands:

/policy show - List current rules
/policy allow <dest> - Add allow rule
/policy deny <dest> - Add deny rule
/policy remove <dest> - Remove rule
/status - Show proxy status
/audit recent [N] - Show last N audit entries
/help - Show this message

Planned (not yet available):
/cred add|list|rotate|remove - Credential management`
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

// readLastLines reads the last n lines from a file using a ring buffer
// so that only O(n) memory is used regardless of file size.
func readLastLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ring := make([]string, n)
	idx := 0
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ring[idx%n] = scanner.Text()
		idx++
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if count == 0 {
		return nil, nil
	}
	if count < n {
		return ring[:count], nil
	}
	// Reorder the ring buffer so entries are in chronological order.
	result := make([]string, n)
	start := idx % n
	copy(result, ring[start:])
	copy(result[n-start:], ring[:start])
	return result, nil
}
