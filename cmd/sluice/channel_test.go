package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/store"
)

func captureChannelOutput(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	fn()

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout
	return buf.String()
}

func setupChannelDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create test DB: %v", err)
	}
	_ = db.Close()
	return dbPath
}

// --- Store-level tests (existing, preserved) ---

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

	id, _ := db.AddChannel(int(channel.ChannelHTTP), true, store.AddChannelOpts{
		WebhookURL: "https://example.com/hook",
	})

	deleted, err := db.RemoveChannel(id)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !deleted {
		t.Error("expected deletion")
	}

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

	count, err := db.CountEnabledChannels()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 enabled channel, got %d", count)
	}
}

func TestMultiChannelCoexistence(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

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

	if channels[0].Type != int(channel.ChannelTelegram) {
		t.Errorf("first channel type = %d, want telegram", channels[0].Type)
	}
	if channels[1].Type != int(channel.ChannelHTTP) {
		t.Errorf("second channel type = %d, want http", channels[1].Type)
	}

	for _, ch := range channels {
		if !ch.Enabled {
			t.Errorf("channel [%d] should be enabled", ch.ID)
		}
	}
}

// --- Handler-level tests ---

func TestHandleChannelCommandNoArgs(t *testing.T) {
	err := handleChannelCommand([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestHandleChannelCommandUnknown(t *testing.T) {
	err := handleChannelCommand([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestHandleChannelListDefault(t *testing.T) {
	dbPath := setupChannelDB(t)

	output := captureChannelOutput(t, func() {
		if err := handleChannelList([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handleChannelList: %v", err)
		}
	})

	// Default DB has a telegram channel.
	if !strings.Contains(output, "telegram") {
		t.Errorf("expected 'telegram' in output: %s", output)
	}
	if !strings.Contains(output, "enabled") {
		t.Errorf("expected 'enabled' in output: %s", output)
	}
}

func TestHandleChannelAddHTTP(t *testing.T) {
	dbPath := setupChannelDB(t)

	output := captureChannelOutput(t, func() {
		if err := handleChannelAdd([]string{
			"--db", dbPath,
			"--type", "http",
			"--url", "https://example.com/webhook",
			"--secret", "test-secret",
		}); err != nil {
			t.Fatalf("handleChannelAdd: %v", err)
		}
	})

	if !strings.Contains(output, "added http channel") {
		t.Errorf("expected 'added http channel' in output: %s", output)
	}

	// Verify via listing.
	listOutput := captureChannelOutput(t, func() {
		if err := handleChannelList([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handleChannelList after add: %v", err)
		}
	})

	if !strings.Contains(listOutput, "http") {
		t.Errorf("expected http channel in list: %s", listOutput)
	}
	if !strings.Contains(listOutput, "https://example.com/webhook") {
		t.Errorf("expected webhook URL in list: %s", listOutput)
	}
	if !strings.Contains(listOutput, "secret=***") {
		t.Errorf("expected masked secret in list: %s", listOutput)
	}
}

func TestHandleChannelAddTelegram(t *testing.T) {
	dbPath := setupChannelDB(t)

	output := captureChannelOutput(t, func() {
		if err := handleChannelAdd([]string{
			"--db", dbPath,
			"--type", "telegram",
		}); err != nil {
			t.Fatalf("handleChannelAdd telegram: %v", err)
		}
	})

	if !strings.Contains(output, "added telegram channel") {
		t.Errorf("expected 'added telegram channel' in output: %s", output)
	}
}

func TestHandleChannelAddNoType(t *testing.T) {
	err := handleChannelAdd([]string{})
	if err == nil {
		t.Fatal("expected error for no type")
	}
}

func TestHandleChannelAddInvalidType(t *testing.T) {
	err := handleChannelAdd([]string{"--type", "slack"})
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "invalid channel type") {
		t.Errorf("expected 'invalid channel type' in error: %v", err)
	}
}

func TestHandleChannelAddHTTPWithoutURL(t *testing.T) {
	err := handleChannelAdd([]string{"--type", "http"})
	if err == nil {
		t.Fatal("expected error for http without url")
	}
	if !strings.Contains(err.Error(), "--url is required") {
		t.Errorf("expected '--url is required' in error: %v", err)
	}
}

func TestHandleChannelUpdateEnabled(t *testing.T) {
	dbPath := setupChannelDB(t)

	// Add an HTTP channel first.
	_ = captureChannelOutput(t, func() {
		if err := handleChannelAdd([]string{
			"--db", dbPath, "--type", "http", "--url", "https://example.com/hook",
		}); err != nil {
			t.Fatalf("add: %v", err)
		}
	})

	// Disable it.
	output := captureChannelOutput(t, func() {
		if err := handleChannelUpdate([]string{"--db", dbPath, "--enabled", "false", "2"}); err != nil {
			t.Fatalf("handleChannelUpdate disable: %v", err)
		}
	})

	if !strings.Contains(output, "updated channel") {
		t.Errorf("expected 'updated channel' in output: %s", output)
	}
}

func TestHandleChannelUpdateNoArgs(t *testing.T) {
	err := handleChannelUpdate([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestHandleChannelUpdateNonExistent(t *testing.T) {
	dbPath := setupChannelDB(t)
	err := handleChannelUpdate([]string{"--db", dbPath, "999"})
	if err == nil {
		t.Fatal("expected error for non-existent channel")
	}
	if !strings.Contains(err.Error(), "no channel with ID") {
		t.Errorf("expected 'no channel with ID' in error: %v", err)
	}
}

func TestHandleChannelRemoveNotLast(t *testing.T) {
	dbPath := setupChannelDB(t)

	// Add a second channel.
	_ = captureChannelOutput(t, func() {
		if err := handleChannelAdd([]string{
			"--db", dbPath, "--type", "http", "--url", "https://example.com/hook",
		}); err != nil {
			t.Fatalf("add: %v", err)
		}
	})

	// Remove the HTTP channel (ID 2).
	output := captureChannelOutput(t, func() {
		if err := handleChannelRemove([]string{"--db", dbPath, "2"}); err != nil {
			t.Fatalf("handleChannelRemove: %v", err)
		}
	})

	if !strings.Contains(output, "removed channel") {
		t.Errorf("expected 'removed channel' in output: %s", output)
	}
}

func TestHandleChannelRemoveLastProtection(t *testing.T) {
	dbPath := setupChannelDB(t)

	// Try to remove the default telegram channel (ID 1) which is the only one.
	err := handleChannelRemove([]string{"--db", dbPath, "1"})
	if err == nil {
		t.Fatal("expected error for removing last channel")
	}
	if !strings.Contains(err.Error(), "cannot remove the last enabled channel") {
		t.Errorf("expected last channel protection error: %v", err)
	}
}

func TestHandleChannelRemoveNoArgs(t *testing.T) {
	err := handleChannelRemove([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestHandleChannelRemoveNonExistent(t *testing.T) {
	dbPath := setupChannelDB(t)
	err := handleChannelRemove([]string{"--db", dbPath, "999"})
	if err == nil {
		t.Fatal("expected error for non-existent channel")
	}
}

func TestChannelTypeName(t *testing.T) {
	if got := channelTypeName(int(channel.ChannelTelegram)); got != "telegram" {
		t.Errorf("telegram: got %q", got)
	}
	if got := channelTypeName(int(channel.ChannelHTTP)); got != "http" {
		t.Errorf("http: got %q", got)
	}
	if got := channelTypeName(99); !strings.Contains(got, "unknown") {
		t.Errorf("unknown type: got %q", got)
	}
}
