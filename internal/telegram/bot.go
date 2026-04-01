package telegram

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/nemirovsky/sluice/internal/policy"
)

// tokenPattern matches Telegram bot tokens embedded in URLs or error messages.
// Tokens follow the format <numeric-id>:<alphanumeric-string> and typically
// appear right after "bot" in API URLs (e.g. /bot123456:AAH.../sendMessage).
var tokenPattern = regexp.MustCompile(`[0-9]+:[A-Za-z0-9_-]{20,}`)

// sanitizeError removes bot tokens from error messages to prevent leaking
// secrets in logs. The telegram-bot-api library includes the full request URL
// (containing the bot token) in HTTP/network error strings.
func sanitizeError(err error) string {
	return tokenPattern.ReplaceAllString(err.Error(), "<REDACTED>")
}

// telegramMaxMessage is Telegram's maximum message length (4096 UTF-8 chars).
// We leave a small margin for the truncation notice.
const telegramMaxMessage = 4000

type BotConfig struct {
	Token     string
	ChatID    int64
	Engine    *policy.Engine
	AuditPath string
}

type Bot struct {
	api      *tgbotapi.BotAPI
	chatID   int64
	broker   *ApprovalBroker
	commands *CommandHandler
}

func FormatApprovalMessage(dest string, port int) string {
	return fmt.Sprintf("Agent wants to connect to:\n\n`%s:%d`\n\nAllow this connection?", dest, port)
}

func NewBot(cfg BotConfig, broker *ApprovalBroker) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(cfg.Token)
	if err != nil {
		// Do not wrap the original error: the telegram-bot-api library
		// includes the full request URL (which contains the bot token) in
		// HTTP errors, so propagating it would leak the token in logs.
		return nil, fmt.Errorf("telegram bot init failed (check token and network connectivity)")
	}
	log.Printf("telegram bot authorized as @%s", api.Self.UserName)

	cmdHandler := NewCommandHandler(cfg.Engine, broker, cfg.AuditPath)

	return &Bot{api: api, chatID: cfg.ChatID, broker: broker, commands: cmdHandler}, nil
}

func (b *Bot) Run() {
	// Start callback query handler
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	updates := b.api.GetUpdatesChan(u)

	// Process pending approval requests (send to Telegram)
	go b.sendApprovalRequests()

	// Process updates (commands and callback queries)
	for update := range updates {
		if update.CallbackQuery != nil {
			b.handleCallback(update.CallbackQuery)
			continue
		}
		if update.Message != nil && update.Message.Text != "" {
			b.handleMessage(update.Message)
		}
	}
}

func (b *Bot) sendApprovalRequests() {
	for req := range b.broker.Pending() {
		// Skip requests whose waiter has already been cleaned up (timed out
		// or resolved while queued). This prevents sending stale approval
		// prompts to Telegram after backlog or recovery.
		if !b.broker.HasWaiter(req.ID) {
			b.broker.ClearTimedOut(req.ID) // clean up timedOut entry if present
			continue
		}
		msg := tgbotapi.NewMessage(b.chatID, FormatApprovalMessage(req.Destination, req.Port))
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("Allow Once", req.ID+"|allow_once"),
				tgbotapi.NewInlineKeyboardButtonData("Always Allow", req.ID+"|always_allow"),
				tgbotapi.NewInlineKeyboardButtonData("Deny", req.ID+"|deny"),
			),
		)
		sent, err := b.api.Send(msg)
		if err != nil {
			log.Printf("telegram send error: %s", sanitizeError(err))
			// On send failure, auto-deny
			b.broker.Resolve(req.ID, ResponseDeny)
			b.broker.ClearTimedOut(req.ID) // clean up timedOut entry if request expired during send
			continue
		}
		// If the request timed out while the Telegram API call was in
		// flight, update the message immediately so the user does not
		// see a stale prompt and only discover it expired after tapping.
		// Use WasTimedOut (not HasWaiter) to distinguish a genuine timeout
		// from a callback that resolved the request during the send.
		// Only clear the flag if the edit succeeds so that handleCallback
		// can still show "timed out" if the operator taps a stale button.
		if b.broker.WasTimedOut(req.ID) {
			edit := tgbotapi.NewEditMessageText(b.chatID, sent.MessageID,
				FormatApprovalMessage(req.Destination, req.Port)+"\n\n(request timed out)")
			if _, editErr := b.api.Send(edit); editErr == nil {
				b.broker.ClearTimedOut(req.ID)
			}
		}
	}
}

func (b *Bot) handleCallback(cq *tgbotapi.CallbackQuery) {
	if cq.Message == nil {
		return
	}
	if cq.Message.Chat.ID != b.chatID {
		log.Printf("unauthorized callback from chat %d (expected %d)", cq.Message.Chat.ID, b.chatID)
		return
	}

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

	resolved := b.broker.Resolve(reqID, resp)

	if resolved {
		callback := tgbotapi.NewCallback(cq.ID, label)
		b.api.Request(callback)

		// Do not use Markdown parse mode here: cq.Message.Text is Telegram's
		// plain-text extraction of the original Markdown message. Re-parsing
		// it as Markdown breaks when the destination contains underscores or
		// other Markdown-special characters (common in DNS names).
		edit := tgbotapi.NewEditMessageText(b.chatID, cq.Message.MessageID,
			fmt.Sprintf("%s\n\n%s at %s", cq.Message.Text, label, time.Now().UTC().Format("15:04:05")))
		b.api.Send(edit)
	} else if b.broker.WasTimedOut(reqID) {
		b.broker.ClearTimedOut(reqID)
		callback := tgbotapi.NewCallback(cq.ID, "Request timed out")
		b.api.Request(callback)

		edit := tgbotapi.NewEditMessageText(b.chatID, cq.Message.MessageID,
			cq.Message.Text+"\n\n(request timed out)")
		b.api.Send(edit)
	} else {
		// Request was already resolved by a previous callback (e.g. double-tap
		// or another user in a group chat). Don't overwrite the message since
		// it already shows the correct resolution.
		callback := tgbotapi.NewCallback(cq.ID, "Already resolved")
		b.api.Request(callback)
	}
}

func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	if !IsAuthorizedChat(msg.Chat.ID, b.chatID) {
		log.Printf("unauthorized command from chat %d (expected %d)", msg.Chat.ID, b.chatID)
		return
	}

	cmd := ParseCommand(msg.Text)
	if cmd == nil {
		return
	}

	response := b.commands.Handle(cmd)
	if response == "" {
		return
	}

	if len(response) > telegramMaxMessage {
		response = response[:telegramMaxMessage] + "\n\n(truncated)"
	}

	reply := tgbotapi.NewMessage(b.chatID, response)
	if _, err := b.api.Send(reply); err != nil {
		log.Printf("telegram send error: %s", sanitizeError(err))
	}
}

// UpdateEngine replaces the policy engine used by command handlers.
// Called on SIGHUP policy reload to keep the bot in sync with the proxy.
func (b *Bot) UpdateEngine(eng *policy.Engine) {
	b.commands.UpdateEngine(eng)
}

func (b *Bot) Stop() {
	b.api.StopReceivingUpdates()
}
