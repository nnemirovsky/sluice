package telegram

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

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
	engine    *policy.Engine
	broker    *ApprovalBroker
	auditPath string
}

// NewCommandHandler creates a command handler with the given dependencies.
func NewCommandHandler(engine *policy.Engine, broker *ApprovalBroker, auditPath string) *CommandHandler {
	return &CommandHandler{
		engine:    engine,
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
	var b strings.Builder
	b.WriteString("Current policy (default: ")
	b.WriteString(h.engine.Default.String())
	b.WriteString(")\n\n")

	if len(h.engine.AllowRules) > 0 {
		b.WriteString("ALLOW:\n")
		for _, r := range h.engine.AllowRules {
			b.WriteString("  ")
			b.WriteString(r.Destination)
			if len(r.Ports) > 0 {
				b.WriteString(" ports=")
				b.WriteString(formatPorts(r.Ports))
			}
			b.WriteString("\n")
		}
	}

	if len(h.engine.DenyRules) > 0 {
		b.WriteString("DENY:\n")
		for _, r := range h.engine.DenyRules {
			b.WriteString("  ")
			b.WriteString(r.Destination)
			if len(r.Ports) > 0 {
				b.WriteString(" ports=")
				b.WriteString(formatPorts(r.Ports))
			}
			b.WriteString("\n")
		}
	}

	if len(h.engine.AskRules) > 0 {
		b.WriteString("ASK:\n")
		for _, r := range h.engine.AskRules {
			b.WriteString("  ")
			b.WriteString(r.Destination)
			if len(r.Ports) > 0 {
				b.WriteString(" ports=")
				b.WriteString(formatPorts(r.Ports))
			}
			b.WriteString("\n")
		}
	}

	if len(h.engine.AllowRules) == 0 && len(h.engine.DenyRules) == 0 && len(h.engine.AskRules) == 0 {
		b.WriteString("No rules configured.")
	}

	return b.String()
}

func (h *CommandHandler) policyAllow(dest string) string {
	rule := policy.Rule{Destination: dest}
	h.engine.AllowRules = append(h.engine.AllowRules, rule)
	if err := h.engine.Compile(); err != nil {
		// Roll back
		h.engine.AllowRules = h.engine.AllowRules[:len(h.engine.AllowRules)-1]
		return fmt.Sprintf("Failed to add allow rule: %v", err)
	}
	return fmt.Sprintf("Added allow rule: %s", dest)
}

func (h *CommandHandler) policyDeny(dest string) string {
	rule := policy.Rule{Destination: dest}
	h.engine.DenyRules = append(h.engine.DenyRules, rule)
	if err := h.engine.Compile(); err != nil {
		h.engine.DenyRules = h.engine.DenyRules[:len(h.engine.DenyRules)-1]
		return fmt.Sprintf("Failed to add deny rule: %v", err)
	}
	return fmt.Sprintf("Added deny rule: %s", dest)
}

func (h *CommandHandler) policyRemove(dest string) string {
	removed := false
	h.engine.AllowRules, removed = removeRule(h.engine.AllowRules, dest)
	if r := false; !removed {
		h.engine.DenyRules, r = removeRule(h.engine.DenyRules, dest)
		removed = r
	}
	if r := false; !removed {
		h.engine.AskRules, r = removeRule(h.engine.AskRules, dest)
		removed = r
	}

	if !removed {
		return fmt.Sprintf("No rule found for: %s", dest)
	}
	if err := h.engine.Compile(); err != nil {
		return fmt.Sprintf("Rule removed but recompile failed: %v", err)
	}
	return fmt.Sprintf("Removed rule: %s", dest)
}

func removeRule(rules []policy.Rule, dest string) ([]policy.Rule, bool) {
	for i, r := range rules {
		if r.Destination == dest {
			return append(rules[:i], rules[i+1:]...), true
		}
	}
	return rules, false
}

func (h *CommandHandler) handleCred(args []string) string {
	if len(args) == 0 {
		return "Usage: /cred add <name> | /cred list | /cred rotate <name> | /cred remove <name>"
	}
	return "Credential management is not available (vault not configured)."
}

func (h *CommandHandler) handleStatus() string {
	var b strings.Builder
	b.WriteString("Sluice Status\n\n")

	b.WriteString("Policy: ")
	b.WriteString(fmt.Sprintf("%d allow, %d deny, %d ask rules",
		len(h.engine.AllowRules), len(h.engine.DenyRules), len(h.engine.AskRules)))
	b.WriteString(fmt.Sprintf(" (default: %s)\n", h.engine.Default))

	if h.broker != nil {
		h.broker.mu.Lock()
		pending := len(h.broker.waiters)
		h.broker.mu.Unlock()
		b.WriteString(fmt.Sprintf("Pending approvals: %d\n", pending))
	}

	return b.String()
}

func (h *CommandHandler) handleAudit(args []string) string {
	count := 10
	if len(args) >= 2 && args[0] == "recent" {
		if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
			count = n
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
/cred add <name> - Add credential
/cred list - List credential names
/cred rotate <name> - Rotate credential
/cred remove <name> - Remove credential
/status - Show proxy status
/audit recent [N] - Show last N audit entries
/help - Show this message`
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

// readLastLines reads the last n lines from a file.
func readLastLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
