package main

import (
	"testing"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/store"
)

func TestChannelListDefault(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	channels, err := db.ListChannels()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("expected 1 default channel, got %d", len(channels))
	}
	if channels[0].Type != int(channel.ChannelTelegram) {
		t.Errorf("default channel type = %d, want %d", channels[0].Type, int(channel.ChannelTelegram))
	}
}

func TestChannelAddHTTP(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	id, err := db.AddChannel(int(channel.ChannelHTTP), true, store.AddChannelOpts{
		WebhookURL:    "https://example.com/sluice/webhook",
		WebhookSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("add http channel: %v", err)
	}

	ch, err := db.GetChannel(id)
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if ch.Type != int(channel.ChannelHTTP) {
		t.Errorf("type = %d, want %d", ch.Type, int(channel.ChannelHTTP))
	}
	if !ch.Enabled {
		t.Error("channel should be enabled")
	}
	if ch.WebhookURL != "https://example.com/sluice/webhook" {
		t.Errorf("webhook_url = %q", ch.WebhookURL)
	}
	if ch.WebhookSecret != "test-secret" {
		t.Errorf("webhook_secret = %q", ch.WebhookSecret)
	}
}

func TestChannelUpdateEnabled(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	id, _ := db.AddChannel(int(channel.ChannelHTTP), true, store.AddChannelOpts{
		WebhookURL: "https://example.com/hook",
	})

	disabled := false
	if err := db.UpdateChannel(id, store.ChannelUpdate{Enabled: &disabled}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	ch, _ := db.GetChannel(id)
	if ch.Enabled {
		t.Error("expected disabled")
	}

	enabled := true
	if err := db.UpdateChannel(id, store.ChannelUpdate{Enabled: &enabled}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	ch, _ = db.GetChannel(id)
	if !ch.Enabled {
		t.Error("expected enabled")
	}
}

func TestChannelRemoveNotLast(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Default Telegram channel exists as ID 1.
	// Add HTTP channel.
	id, _ := db.AddChannel(int(channel.ChannelHTTP), true, store.AddChannelOpts{
		WebhookURL: "https://example.com/hook",
	})

	// Now we have 2 enabled channels. Removing one is allowed.
	deleted, err := db.RemoveChannel(id)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !deleted {
		t.Error("expected deletion")
	}

	// Verify it's gone.
	ch, _ := db.GetChannel(id)
	if ch != nil {
		t.Error("channel should not exist after removal")
	}
}

func TestChannelRemoveLastProtection(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Only the default channel exists. CountEnabledChannels should be 1.
	count, err := db.CountEnabledChannels()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 enabled channel, got %d", count)
	}
	// The CLI would check this count and refuse to remove the last one.
	// The store itself does not enforce this constraint. The CLI does.
}

func TestMultiChannelCoexistence(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Default: Telegram (type=0, ID=1).
	// Add HTTP channel.
	_, err = db.AddChannel(int(channel.ChannelHTTP), true, store.AddChannelOpts{
		WebhookURL:    "https://example.com/webhook",
		WebhookSecret: "hmac-key",
	})
	if err != nil {
		t.Fatalf("add http channel: %v", err)
	}

	channels, err := db.ListChannels()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %d", len(channels))
	}

	// Verify types.
	if channels[0].Type != int(channel.ChannelTelegram) {
		t.Errorf("first channel type = %d, want telegram", channels[0].Type)
	}
	if channels[1].Type != int(channel.ChannelHTTP) {
		t.Errorf("second channel type = %d, want http", channels[1].Type)
	}

	// Both should be enabled.
	for _, ch := range channels {
		if !ch.Enabled {
			t.Errorf("channel [%d] should be enabled", ch.ID)
		}
	}
}
