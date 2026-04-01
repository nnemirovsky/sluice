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
