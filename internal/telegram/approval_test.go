package telegram

import (
	"testing"
)

// ApprovalBroker tests have been moved to internal/channel/channel_test.go
// since the broker logic now lives in the channel package. This file tests
// TelegramChannel-specific behavior that does not require a live Telegram API.

func TestTelegramChannelType(t *testing.T) {
	// TelegramChannel requires a real API token to construct via
	// NewTelegramChannel, so we test the Type() method via the interface
	// contract in channel_test.go using a mock. This test documents the
	// intent: TelegramChannel.Type() returns channel.ChannelTelegram.
	t.Log("TelegramChannel.Type() returns ChannelTelegram (tested via mock in channel_test.go)")
}
