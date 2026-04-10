// Package telegram provides Telegram bot integration for human approval of
// agent actions. TelegramChannel implements the channel.Channel interface,
// providing inline keyboard approval UX, admin commands for policy and
// credential management, and one-way notifications.
package telegram

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/container"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// ChannelConfig holds configuration for creating a TelegramChannel.
type ChannelConfig struct {
	Token               string
	ChatID              int64
	EnginePtr           *atomic.Pointer[policy.Engine]
	ResolverPtr         *atomic.Pointer[vault.BindingResolver]
	ReloadMu            *sync.Mutex
	AuditPath           string
	Vault               *vault.Store
	ContainerMgr        container.ContainerManager
	Store               *store.Store
	OnEngineSwap        func(eng *policy.Engine) // called after policy mutations to update dependent state
	OnOAuthIndexRebuild func()                   // called after credential removal to rebuild proxy OAuth index
	APIEndpoint         string                   // custom Telegram API endpoint (for testing); empty uses default
}

// TelegramChannel implements channel.Channel for Telegram bot interaction.
// It sends approval requests as inline keyboard messages, processes callback
// responses, and handles admin commands.
type TelegramChannel struct { //nolint:revive // stuttering accepted for clarity
	api      *tgbotapi.BotAPI
	chatID   int64
	broker   *channel.Broker
	commands *CommandHandler
	msgMap   sync.Map // request ID -> approvalMsg{messageID, text}
	cmdCh    chan channel.Command
	done     chan struct{}
	stopOnce sync.Once
}

// NewTelegramChannel creates a TelegramChannel. Call SetBroker after creating
// the channel.Broker, then call Start to begin processing Telegram updates.
func NewTelegramChannel(cfg ChannelConfig) (*TelegramChannel, error) {
	var api *tgbotapi.BotAPI
	var err error
	if cfg.APIEndpoint != "" {
		api, err = tgbotapi.NewBotAPIWithAPIEndpoint(cfg.Token, cfg.APIEndpoint)
	} else {
		api, err = tgbotapi.NewBotAPI(cfg.Token)
	}
	if err != nil {
		// Do not wrap the original error: the telegram-bot-api library
		// includes the full request URL (which contains the bot token) in
		// HTTP errors, so propagating it would leak the token in logs.
		return nil, fmt.Errorf("telegram bot init failed (check token and network connectivity)")
	}
	log.Printf("telegram bot authorized as @%s", api.Self.UserName)

	tc := &TelegramChannel{
		api:    api,
		chatID: cfg.ChatID,
		cmdCh:  make(chan channel.Command, 100),
		done:   make(chan struct{}),
	}

	cmdHandler := NewCommandHandler(cfg.EnginePtr, cfg.ReloadMu, cfg.AuditPath)
	if cfg.Store != nil {
		cmdHandler.SetStore(cfg.Store)
	}
	if cfg.Vault != nil {
		cmdHandler.SetVault(cfg.Vault)
	}
	if cfg.ContainerMgr != nil {
		cmdHandler.SetContainerManager(cfg.ContainerMgr)
	}
	if cfg.ResolverPtr != nil {
		cmdHandler.SetResolverPtr(cfg.ResolverPtr)
	}
	if cfg.OnEngineSwap != nil {
		cmdHandler.SetOnEngineSwap(cfg.OnEngineSwap)
	}
	if cfg.OnOAuthIndexRebuild != nil {
		cmdHandler.SetOnOAuthIndexRebuild(cfg.OnOAuthIndexRebuild)
	}

	tc.commands = cmdHandler
	return tc, nil
}

// approvalMsg stores the Telegram message ID and the original approval
// request so that timeout/cancel/resolved edits can re-render the full
// HTML-formatted body (including the <pre><code> args block) without
// worrying about whether the stored text survived appending, parse
// mode changes, or Telegram's plain-text extraction in callback
// queries.
type approvalMsg struct {
	messageID int
	req       channel.ApprovalRequest
}

// SetBroker sets the broker reference for resolving approval requests.
// Must be called after channel.NewBroker creates the broker with this channel.
func (tc *TelegramChannel) SetBroker(b *channel.Broker) {
	tc.broker = b
	tc.commands.SetBroker(b)
}

// RequestApproval sends an approval prompt to Telegram (non-blocking).
// The message includes inline keyboard buttons for Allow Once, Always Allow,
// and Deny. The broker is notified via Resolve when the operator responds.
func (tc *TelegramChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	go tc.sendApprovalMessage(req)
	return nil
}

func (tc *TelegramChannel) sendApprovalMessage(req channel.ApprovalRequest) {
	// Skip requests whose waiter has already been cleaned up (timed out
	// or resolved while queued).
	if tc.broker != nil && !tc.broker.HasWaiter(req.ID) {
		tc.broker.ClearTimedOut(req.ID)
		return
	}

	msg := tgbotapi.NewMessage(tc.chatID, FormatApprovalMessage(req))
	msg.ParseMode = tgbotapi.ModeHTML
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Allow", req.ID+"|allow_once"),
			tgbotapi.NewInlineKeyboardButtonData("Deny", req.ID+"|deny"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Always Allow", req.ID+"|always_allow"),
			tgbotapi.NewInlineKeyboardButtonData("Always Deny", req.ID+"|always_deny"),
		),
	)
	sent, err := tc.api.Send(msg)
	if err != nil {
		log.Printf("telegram send error: %s", sanitizeError(err))
		// In a single-channel setup, resolve immediately as Deny rather
		// than waiting for the full broker timeout. In a multi-channel
		// setup, another channel may still deliver the prompt, so only
		// the broker timeout should deny.
		if tc.broker != nil && len(tc.broker.Channels()) <= 1 {
			tc.broker.Resolve(req.ID, channel.ResponseDeny)
		}
		return
	}
	tc.msgMap.Store(req.ID, approvalMsg{messageID: sent.MessageID, req: req})

	// If the request timed out while the Telegram API call was in
	// flight, update the message immediately so the user does not
	// see a stale prompt.
	if tc.broker != nil && tc.broker.WasTimedOut(req.ID) {
		edit := tgbotapi.NewEditMessageText(tc.chatID, sent.MessageID,
			FormatApprovalMessage(req)+"\n\n(request timed out)")
		edit.ParseMode = tgbotapi.ModeHTML
		if _, editErr := tc.api.Send(edit); editErr == nil {
			tc.broker.ClearTimedOut(req.ID)
		}
	}
}

// CancelApproval edits the Telegram message to indicate the request was
// resolved, timed out, or cancelled, removing the inline keyboard.
func (tc *TelegramChannel) CancelApproval(id string) error {
	val, ok := tc.msgMap.LoadAndDelete(id)
	if !ok {
		return nil
	}
	am := val.(approvalMsg)
	reason := "(resolved via another channel)"
	if tc.broker != nil && tc.broker.WasTimedOut(id) {
		reason = "(request timed out)"
		tc.broker.ClearTimedOut(id)
	} else if tc.broker != nil && tc.broker.IsClosed() {
		reason = "(proxy shutting down)"
	}
	edit := tgbotapi.NewEditMessageText(tc.chatID, am.messageID,
		FormatApprovalMessage(am.req)+"\n\n"+reason)
	edit.ParseMode = tgbotapi.ModeHTML
	_, _ = tc.api.Send(edit)
	return nil
}

// Commands returns incoming admin commands from Telegram.
func (tc *TelegramChannel) Commands() <-chan channel.Command {
	return tc.cmdCh
}

// Notify sends a one-way message to the Telegram chat.
func (tc *TelegramChannel) Notify(_ context.Context, text string) error {
	msg := tgbotapi.NewMessage(tc.chatID, text)
	_, err := tc.api.Send(msg)
	if err != nil {
		return fmt.Errorf("telegram notify: %s", sanitizeError(err))
	}
	return nil
}

// registerCommands sets the bot's command menu via Telegram's setMyCommands API.
func (tc *TelegramChannel) registerCommands() {
	cmds := []tgbotapi.BotCommand{
		{Command: "status", Description: "Show proxy status"},
		{Command: "policy", Description: "Manage policy rules"},
		{Command: "cred", Description: "Manage credentials"},
		{Command: "audit", Description: "Show audit log entries"},
		{Command: "start", Description: "Show welcome message"},
		{Command: "help", Description: "Show available commands"},
	}
	cfg := tgbotapi.NewSetMyCommands(cmds...)
	if _, err := tc.api.Request(cfg); err != nil {
		log.Printf("failed to register bot commands: %s", sanitizeError(err))
	}
}

// Start begins polling for Telegram updates (callbacks and commands).
func (tc *TelegramChannel) Start() error {
	tc.registerCommands()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	updates := tc.api.GetUpdatesChan(u)

	go func() {
		for {
			select {
			case update, ok := <-updates:
				if !ok {
					return
				}
				if update.CallbackQuery != nil {
					tc.handleCallback(update.CallbackQuery)
					continue
				}
				if update.Message != nil && update.Message.Text != "" {
					tc.handleMessage(update.Message)
				}
			case <-tc.done:
				return
			}
		}
	}()
	return nil
}

// Stop halts the Telegram bot and stops processing updates.
func (tc *TelegramChannel) Stop() {
	tc.stopOnce.Do(func() {
		close(tc.done)
		tc.api.StopReceivingUpdates()
	})
}

// Type returns channel.ChannelTelegram.
func (tc *TelegramChannel) Type() channel.ChannelType {
	return channel.ChannelTelegram
}

func (tc *TelegramChannel) handleCallback(cq *tgbotapi.CallbackQuery) {
	if cq.Message == nil {
		return
	}
	if cq.Message.Chat.ID != tc.chatID {
		log.Printf("unauthorized callback from chat %d (expected %d)", cq.Message.Chat.ID, tc.chatID)
		return
	}

	parts := strings.SplitN(cq.Data, "|", 2)
	if len(parts) != 2 {
		return
	}
	reqID, action := parts[0], parts[1]

	var resp channel.Response
	var label string
	switch action {
	case "allow_once":
		resp = channel.ResponseAllowOnce
		label = "Allowed (once)"
	case "always_allow":
		resp = channel.ResponseAlwaysAllow
		label = "Always allowed"
	case "deny":
		resp = channel.ResponseDeny
		label = "Denied"
	case "always_deny":
		resp = channel.ResponseAlwaysDeny
		label = "Always denied"
	default:
		return
	}

	resolved := false
	if tc.broker != nil {
		resolved = tc.broker.Resolve(reqID, resp)
	}

	if resolved {
		callback := tgbotapi.NewCallback(cq.ID, label)
		_, _ = tc.api.Request(callback)

		// Re-render the full HTML body from the stored request. This
		// preserves the <pre><code> args block because we are not
		// appending to or reusing a string that already contains HTML
		// tags. cq.Message.Text is Telegram's plain-text extraction and
		// loses the code block formatting entirely, so we fall back to
		// a minimal plain message only if the msgMap entry is gone.
		var body string
		if val, ok := tc.msgMap.Load(reqID); ok {
			am := val.(approvalMsg)
			body = fmt.Sprintf("%s\n\n%s at %s",
				FormatApprovalMessage(am.req), label, time.Now().UTC().Format("15:04:05"))
		} else {
			body = fmt.Sprintf("%s\n\n%s at %s",
				cq.Message.Text, label, time.Now().UTC().Format("15:04:05"))
		}
		edit := tgbotapi.NewEditMessageText(tc.chatID, cq.Message.MessageID, body)
		edit.ParseMode = tgbotapi.ModeHTML
		_, _ = tc.api.Send(edit)
		tc.msgMap.Delete(reqID)
	} else if tc.broker != nil && tc.broker.WasTimedOut(reqID) {
		tc.broker.ClearTimedOut(reqID)
		callback := tgbotapi.NewCallback(cq.ID, "Request timed out")
		_, _ = tc.api.Request(callback)

		var body string
		if val, ok := tc.msgMap.Load(reqID); ok {
			am := val.(approvalMsg)
			body = FormatApprovalMessage(am.req) + "\n\n(request timed out)"
		} else {
			body = cq.Message.Text + "\n\n(request timed out)"
		}
		edit := tgbotapi.NewEditMessageText(tc.chatID, cq.Message.MessageID, body)
		edit.ParseMode = tgbotapi.ModeHTML
		_, _ = tc.api.Send(edit)
		tc.msgMap.Delete(reqID)

	} else {
		// Request was already resolved by a previous callback (e.g. double-tap
		// or another user in a group chat).
		callback := tgbotapi.NewCallback(cq.ID, "Already resolved")
		_, _ = tc.api.Request(callback)
	}
}

func (tc *TelegramChannel) handleMessage(msg *tgbotapi.Message) {
	if !IsAuthorizedChat(msg.Chat.ID, tc.chatID) {
		log.Printf("unauthorized command from chat %d (expected %d)", msg.Chat.ID, tc.chatID)
		return
	}

	cmd := ParseCommand(msg.Text)
	if cmd == nil {
		return
	}

	// Delete messages that contain credential values before processing
	// to minimize exposure in chat history.
	if cmd.Name == "cred" && len(cmd.Args) >= 1 &&
		(cmd.Args[0] == "add" || cmd.Args[0] == "rotate") {
		del := tgbotapi.NewDeleteMessage(msg.Chat.ID, msg.MessageID)
		if _, err := tc.api.Request(del); err != nil {
			log.Printf("failed to delete credential message: %s", sanitizeError(err))
		}
	}

	// Forward as channel.Command (non-blocking, drop if full).
	// Skip cred add/rotate commands to avoid forwarding plaintext
	// credential values through the command channel.
	isSensitiveCred := cmd.Name == "cred" && len(cmd.Args) >= 1 &&
		(cmd.Args[0] == "add" || cmd.Args[0] == "rotate")
	if !isSensitiveCred {
		select {
		case tc.cmdCh <- channel.Command{
			Name:        cmd.Name,
			Args:        strings.Join(cmd.Args, " "),
			ChannelType: channel.ChannelTelegram,
			Reply: func(_ context.Context, text string) error {
				reply := tgbotapi.NewMessage(tc.chatID, text)
				_, sendErr := tc.api.Send(reply)
				return sendErr
			},
		}:
		default:
		}
	}

	// Handle internally via CommandHandler.
	response := tc.commands.Handle(cmd)
	if response == "" {
		return
	}

	if utf8.RuneCountInString(response) > telegramMaxMessage {
		// Find the byte offset of the telegramMaxMessage-th rune so
		// we truncate at the correct character count, not byte count.
		cut := 0
		for i := 0; i < telegramMaxMessage; i++ {
			_, size := utf8.DecodeRuneInString(response[cut:])
			cut += size
		}
		response = response[:cut] + "\n\n(truncated)"
	}

	reply := tgbotapi.NewMessage(tc.chatID, response)
	if _, err := tc.api.Send(reply); err != nil {
		log.Printf("telegram send error: %s", sanitizeError(err))
	}
}
