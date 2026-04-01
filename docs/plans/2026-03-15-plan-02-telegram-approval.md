# Sluice Plan 2: Telegram Approval Bot

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Telegram bot integration so that when a connection matches an "ask" policy rule, Sluice sends an inline keyboard message to the user's Telegram chat and blocks the connection until the user taps Allow Once, Always Allow, or Deny.

**Architecture:** A long-running Telegram bot goroutine polls for callback queries. The SOCKS5 proxy's policyRuleSet sends approval requests to a channel, the bot goroutine picks them up, sends to Telegram, and returns the user's decision. "Always Allow" dynamically adds an allow rule to the running policy.

**Tech Stack:** Go, `github.com/go-telegram-bot-api/telegram-bot-api/v5`

**Depends on:** Plan 1 (SOCKS5 Proxy Core)

---

## File Structure

```
sluice/
  internal/
    telegram/
      bot.go             # Telegram bot lifecycle, message sending
      bot_test.go
      approval.go        # Approval request/response types, channel-based flow
      approval_test.go
    proxy/
      server.go          # Modify: integrate approval flow for Ask verdicts
```

---

## Chunk 1: Approval Request/Response Types and Flow

### Task 1: Approval types and in-memory channel flow

**Files:**
- Create: `internal/telegram/approval.go`
- Create: `internal/telegram/approval_test.go`

- [x] **Step 1: Write failing test for approval flow**

```go
// internal/telegram/approval_test.go
package telegram

import (
	"testing"
	"time"
)

func TestApprovalFlowAllowOnce(t *testing.T) {
	broker := NewApprovalBroker()

	go func() {
		// Simulate user responding after 10ms
		time.Sleep(10 * time.Millisecond)
		req := <-broker.Pending()
		broker.Resolve(req.ID, ResponseAllowOnce)
	}()

	resp, err := broker.Request("evil.com", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp != ResponseAllowOnce {
		t.Errorf("expected AllowOnce, got %v", resp)
	}
}

func TestApprovalFlowTimeout(t *testing.T) {
	broker := NewApprovalBroker()

	resp, err := broker.Request("evil.com", 443, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error, got response %v", resp)
	}
}

func TestApprovalFlowDeny(t *testing.T) {
	broker := NewApprovalBroker()

	go func() {
		time.Sleep(10 * time.Millisecond)
		req := <-broker.Pending()
		broker.Resolve(req.ID, ResponseDeny)
	}()

	resp, err := broker.Request("evil.com", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp != ResponseDeny {
		t.Errorf("expected Deny, got %v", resp)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/telegram/ -v -timeout 10s`
Expected: FAIL

- [x] **Step 3: Implement approval.go**

```go
// internal/telegram/approval.go
package telegram

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Response int

const (
	ResponseAllowOnce Response = iota
	ResponseAlwaysAllow
	ResponseDeny
)

func (r Response) String() string {
	switch r {
	case ResponseAllowOnce:
		return "allow_once"
	case ResponseAlwaysAllow:
		return "always_allow"
	case ResponseDeny:
		return "deny"
	default:
		return "unknown"
	}
}

type ApprovalRequest struct {
	ID          string
	Destination string
	Port        int
	CreatedAt   time.Time
}

type ApprovalBroker struct {
	mu       sync.Mutex
	pending  chan ApprovalRequest
	waiters  map[string]chan Response
	nextID   atomic.Int64
}

func NewApprovalBroker() *ApprovalBroker {
	return &ApprovalBroker{
		pending: make(chan ApprovalRequest, 100),
		waiters: make(map[string]chan Response),
	}
}

func (b *ApprovalBroker) Pending() <-chan ApprovalRequest {
	return b.pending
}

func (b *ApprovalBroker) Request(dest string, port int, timeout time.Duration) (Response, error) {
	id := fmt.Sprintf("req_%d", b.nextID.Add(1))
	ch := make(chan Response, 1)

	b.mu.Lock()
	b.waiters[id] = ch
	b.mu.Unlock()

	b.pending <- ApprovalRequest{
		ID:          id,
		Destination: dest,
		Port:        port,
		CreatedAt:   time.Now(),
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		b.mu.Lock()
		delete(b.waiters, id)
		b.mu.Unlock()
		return ResponseDeny, fmt.Errorf("approval timeout after %v", timeout)
	}
}

func (b *ApprovalBroker) Resolve(id string, resp Response) {
	b.mu.Lock()
	ch, ok := b.waiters[id]
	if ok {
		delete(b.waiters, id)
	}
	b.mu.Unlock()

	if ok {
		ch <- resp
	}
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `go test ./internal/telegram/ -v -timeout 10s`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/telegram/
git commit -m "feat: approval broker with request/response channel flow"
```

---

### Task 2: Telegram bot integration

**Files:**
- Create: `internal/telegram/bot.go`
- Create: `internal/telegram/bot_test.go`

- [x] **Step 1: Write test for message formatting**

```go
// internal/telegram/bot_test.go
package telegram

import "testing"

func TestFormatApprovalMessage(t *testing.T) {
	msg := FormatApprovalMessage("api.evil.com", 443)
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
	// Should contain the destination
	if !strings.Contains(msg, "api.evil.com") {
		t.Error("message should contain destination")
	}
	if !strings.Contains(msg, "443") {
		t.Error("message should contain port")
	}
}
```

(Add `"strings"` to imports.)

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/telegram/ -v -run TestFormatApprovalMessage`
Expected: FAIL

- [x] **Step 3: Implement bot.go**

```go
// internal/telegram/bot.go
package telegram

import (
	"fmt"
	"log"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type BotConfig struct {
	Token      string
	ChatID     int64
	TimeoutSec int
}

type Bot struct {
	api    *tgbotapi.BotAPI
	chatID int64
	broker *ApprovalBroker
}

func FormatApprovalMessage(dest string, port int) string {
	return fmt.Sprintf("Agent wants to connect to:\n\n`%s:%d`\n\nAllow this connection?", dest, port)
}

func NewBot(cfg BotConfig, broker *ApprovalBroker) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("telegram bot init: %w", err)
	}
	log.Printf("telegram bot authorized as @%s", api.Self.UserName)

	return &Bot{api: api, chatID: cfg.ChatID, broker: broker}, nil
}

func (b *Bot) Run() {
	// Start callback query handler
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	updates := b.api.GetUpdatesChan(u)

	// Process pending approval requests (send to Telegram)
	go b.sendApprovalRequests()

	// Process callback queries (user tapped a button)
	for update := range updates {
		if update.CallbackQuery == nil {
			continue
		}
		b.handleCallback(update.CallbackQuery)
	}
}

func (b *Bot) sendApprovalRequests() {
	for req := range b.broker.Pending() {
		msg := tgbotapi.NewMessage(b.chatID, FormatApprovalMessage(req.Destination, req.Port))
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("Allow Once", req.ID+"|allow_once"),
				tgbotapi.NewInlineKeyboardButtonData("Always Allow", req.ID+"|always_allow"),
				tgbotapi.NewInlineKeyboardButtonData("Deny", req.ID+"|deny"),
			),
		)
		if _, err := b.api.Send(msg); err != nil {
			log.Printf("telegram send error: %v", err)
			// On send failure, auto-deny
			b.broker.Resolve(req.ID, ResponseDeny)
		}
	}
}

func (b *Bot) handleCallback(cq *tgbotapi.CallbackQuery) {
	parts := strings.SplitN(cq.Data, "|", 2)
	if len(parts) != 2 {
		return
	}
	reqID, action := parts[0], parts[1]

	var resp Response
	var label string
	switch action {
	case "allow_once":
		resp = ResponseAllowOnce
		label = "Allowed (once)"
	case "always_allow":
		resp = ResponseAlwaysAllow
		label = "Always allowed"
	case "deny":
		resp = ResponseDeny
		label = "Denied"
	default:
		return
	}

	b.broker.Resolve(reqID, resp)

	// Update the message to show the decision
	callback := tgbotapi.NewCallback(cq.ID, label)
	b.api.Request(callback)

	edit := tgbotapi.NewEditMessageText(b.chatID, cq.Message.MessageID,
		cq.Message.Text+fmt.Sprintf("\n\n*%s* at %s", label, time.Now().UTC().Format("15:04:05")))
	edit.ParseMode = "Markdown"
	b.api.Send(edit)
}

func (b *Bot) Stop() {
	b.api.StopReceivingUpdates()
}
```

- [x] **Step 4: Add telegram dependency**

```bash
go get github.com/go-telegram-bot-api/telegram-bot-api/v5
```

- [x] **Step 5: Run test to verify it passes**

Run: `go test ./internal/telegram/ -v -run TestFormatApprovalMessage`
Expected: PASS

- [x] **Step 6: Commit**

```bash
git add internal/telegram/ go.mod go.sum
git commit -m "feat: Telegram bot with inline keyboard approval"
```

---

## Chunk 2: Integrate Approval into Proxy

### Task 3: Wire approval broker into SOCKS5 proxy

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `cmd/sluice/main.go`

- [x] **Step 1: Update proxy Config to accept ApprovalBroker**

Add to `proxy.Config`:

```go
Broker *telegram.ApprovalBroker
```

Update `policyRuleSet` to use it:

```go
type policyRuleSet struct {
	engine *policy.Engine
	audit  *audit.FileLogger
	broker *telegram.ApprovalBroker
}
```

Modify the `Allow` method's `Ask` case:

```go
case policy.Ask:
	if r.broker == nil {
		log.Printf("[ASK->DENY] %s:%d (no approval broker)", dest, port)
		return ctx, false
	}
	log.Printf("[ASK] %s:%d (waiting for Telegram approval)", dest, port)
	timeout := time.Duration(r.engine.TimeoutSec) * time.Second
	resp, err := r.broker.Request(dest, port, timeout)
	if err != nil {
		log.Printf("[ASK->DENY] %s:%d (timeout: %v)", dest, port, err)
		return ctx, false
	}
	switch resp {
	case telegram.ResponseAllowOnce:
		log.Printf("[ASK->ALLOW] %s:%d (user approved once)", dest, port)
		return ctx, true
	case telegram.ResponseAlwaysAllow:
		log.Printf("[ASK->ALLOW+SAVE] %s:%d (user approved always)", dest, port)
		r.engine.AddDynamicAllow(dest, port)
		return ctx, true
	default:
		log.Printf("[ASK->DENY] %s:%d (user denied)", dest, port)
		return ctx, false
	}
```

- [x] **Step 2: Add AddDynamicAllow to policy engine**

Add to `internal/policy/engine.go`:

```go
func (e *Engine) AddDynamicAllow(dest string, port int) {
	rule := Rule{Destination: dest, Ports: []int{port}}
	e.AllowRules = append(e.AllowRules, rule)
	// Recompile to include new rule
	e.Compile()
}
```

- [x] **Step 3: Update main.go to start Telegram bot**

Add Telegram config flags and bot startup:

```go
telegramToken := flag.String("telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram bot token")
telegramChatID := flag.Int64("telegram-chat-id", 0, "Telegram chat ID for approvals")

// ... after policy/audit setup ...

broker := telegram.NewApprovalBroker()

// Start Telegram bot if configured
if *telegramToken != "" && *telegramChatID != 0 {
	bot, err := telegram.NewBot(telegram.BotConfig{
		Token:      *telegramToken,
		ChatID:     *telegramChatID,
		TimeoutSec: eng.TimeoutSec,
	}, broker)
	if err != nil {
		log.Fatalf("telegram bot: %v", err)
	}
	go bot.Run()
	defer bot.Stop()
	log.Printf("telegram approval bot started")
} else {
	log.Printf("telegram not configured (ask rules will auto-deny)")
}

srv, err := proxy.New(proxy.Config{
	ListenAddr: *listenAddr,
	Policy:     eng,
	Audit:      logger,
	Broker:     broker,
})
```

- [x] **Step 4: Run full test suite**

Run: `go test ./... -v -timeout 30s`
Expected: ALL PASS

- [x] **Step 5: Commit**

```bash
git add internal/ cmd/
git commit -m "feat: integrate Telegram approval into SOCKS5 proxy"
```

---

### Task 4: Add Telegram config to policy TOML

**Files:**
- Modify: `internal/policy/types.go`

- [ ] **Step 1: Add TelegramConfig to policy file struct**

```go
type TelegramConfig struct {
	BotTokenEnv string `toml:"bot_token_env"`
	ChatIDEnv   string `toml:"chat_id_env"`
}

// Add to policyFile:
// Telegram TelegramConfig `toml:"telegram"`
```

- [ ] **Step 2: Add test policy file with telegram section**

Create `testdata/policy_with_telegram.toml`:

```toml
[policy]
default = "ask"
timeout_sec = 60

[telegram]
bot_token_env = "TELEGRAM_BOT_TOKEN"
chat_id_env = "TELEGRAM_CHAT_ID"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[ask]]
destination = "*.unknown.com"
```

- [ ] **Step 3: Write test for loading telegram config**

```go
func TestLoadPolicyWithTelegram(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_with_telegram.toml")
	if err != nil {
		t.Fatal(err)
	}
	if eng.Telegram.BotTokenEnv != "TELEGRAM_BOT_TOKEN" {
		t.Errorf("expected bot_token_env, got %q", eng.Telegram.BotTokenEnv)
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./... -v -timeout 30s`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ testdata/
git commit -m "feat: telegram config in policy TOML"
```

---

## Chunk 3: Telegram Admin Commands

### Task 5: Policy management commands

The Telegram bot currently only handles approval inline keyboards. Add
admin commands for policy and credential management so operators can
manage Sluice entirely from Telegram without SSH access.

**Files:**
- Modify: `internal/telegram/bot.go` (add command handler dispatch)
- Create: `internal/telegram/commands.go`
- Create: `internal/telegram/commands_test.go`

- [ ] **Step 1: Implement command dispatcher**

Route incoming Telegram messages starting with `/` to command handlers:

```go
// internal/telegram/commands.go
// Commands:
//   /policy show              - List current allow/deny/ask rules
//   /policy allow <dest>      - Add allow rule, hot-reload policy
//   /policy deny <dest>       - Add deny rule, hot-reload policy
//   /policy remove <dest>     - Remove rule, hot-reload policy
//   /cred add <name>          - Prompt for credential value (next message)
//   /cred list                - List credential names (never values)
//   /cred rotate <name>       - Replace credential, regenerate phantom, restart agent
//   /cred remove <name>       - Remove credential, restart agent
//   /status                   - Proxy stats, pending approvals, agent container health
//   /audit recent [N]         - Show last N audit log entries (default 10)
//   /help                     - List available commands
```

- [ ] **Step 2: Implement /policy commands**

```go
func handlePolicyShow(bot *tgbotapi.BotAPI, chatID int64, engine *policy.Engine)
func handlePolicyAllow(bot *tgbotapi.BotAPI, chatID int64, engine *policy.Engine, dest string)
func handlePolicyDeny(bot *tgbotapi.BotAPI, chatID int64, engine *policy.Engine, dest string)
```

Policy changes are applied to the running engine AND written back to the
TOML file so they survive restarts.

- [ ] **Step 3: Implement /cred commands**

```go
func handleCredAdd(bot *tgbotapi.BotAPI, chatID int64, store *vault.Store, name string)
func handleCredList(bot *tgbotapi.BotAPI, chatID int64, store *vault.Store)
func handleCredRotate(bot *tgbotapi.BotAPI, chatID int64, store *vault.Store, name string)
func handleCredRemove(bot *tgbotapi.BotAPI, chatID int64, store *vault.Store, name string)
```

For `/cred add`: bot asks for the value in the next message, reads it,
deletes the message containing the secret, stores encrypted, confirms.

- [ ] **Step 4: Implement /status and /audit commands**

```go
func handleStatus(bot *tgbotapi.BotAPI, chatID int64, proxy *proxy.Server, broker *ApprovalBroker)
func handleAuditRecent(bot *tgbotapi.BotAPI, chatID int64, auditPath string, count int)
```

`/status` shows: uptime, connections allowed/denied/pending, active
approval requests, agent container status (via Docker API if available).

`/audit recent` reads last N lines from audit.jsonl and formats them.

- [ ] **Step 5: Secure command access**

Only accept commands from the configured `chat_id`. Reject and log
commands from other chat IDs.

- [ ] **Step 6: Write tests for command parsing and dispatch**

```go
func TestParseCommand(t *testing.T) {
    // Test: "/policy show" -> cmd="policy", args=["show"]
    // Test: "/cred add github_token" -> cmd="cred", args=["add", "github_token"]
    // Test: "/audit recent 20" -> cmd="audit", args=["recent", "20"]
    // Test: "not a command" -> nil
}
```

- [ ] **Step 7: Run tests**

Run: `go test ./internal/telegram/ -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/telegram/commands.go internal/telegram/commands_test.go internal/telegram/bot.go
git commit -m "feat: telegram admin commands for policy, credential, status, and audit management"
```
