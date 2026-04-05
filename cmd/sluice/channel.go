package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/store"
)

func handleChannelCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice channel [list|add|update|remove]")
	}

	switch args[0] {
	case "list":
		return handleChannelList(args[1:])
	case "add":
		return handleChannelAdd(args[1:])
	case "update":
		return handleChannelUpdate(args[1:])
	case "remove":
		return handleChannelRemove(args[1:])
	default:
		return fmt.Errorf("unknown channel command: %s, usage: sluice channel [list|add|update|remove]", args[0])
	}
}

func handleChannelList(args []string) error {
	fs := flag.NewFlagSet("channel list", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	channels, err := db.ListChannels()
	if err != nil {
		return fmt.Errorf("list channels: %w", err)
	}

	if len(channels) == 0 {
		fmt.Println("no channels configured")
		return nil
	}

	for _, ch := range channels {
		typeName := channelTypeName(ch.Type)
		status := "disabled"
		if ch.Enabled {
			status = "enabled"
		}
		extra := ""
		if ch.WebhookURL != "" {
			extra = fmt.Sprintf(" url=%s", ch.WebhookURL)
		}
		if ch.WebhookSecret != "" {
			extra += " secret=***"
		}
		fmt.Printf("[%d] %s %s%s\n", ch.ID, typeName, status, extra)
	}
	return nil
}

func handleChannelAdd(args []string) error {
	fs := flag.NewFlagSet("channel add", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	chType := fs.String("type", "", "channel type (telegram or http)")
	url := fs.String("url", "", "webhook URL (required for http type)")
	secret := fs.String("secret", "", "webhook HMAC secret (optional, for http type)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *chType == "" {
		return fmt.Errorf("usage: sluice channel add --type <telegram|http> [--url <url>] [--secret <secret>]")
	}

	var typeInt int
	switch *chType {
	case "telegram":
		typeInt = int(channel.ChannelTelegram)
	case "http":
		typeInt = int(channel.ChannelHTTP)
		if *url == "" {
			return fmt.Errorf("--url is required for http channel type")
		}
	default:
		return fmt.Errorf("invalid channel type: %s (must be telegram or http)", *chType)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	opts := store.AddChannelOpts{
		WebhookURL:    *url,
		WebhookSecret: *secret,
	}

	id, err := db.AddChannel(typeInt, true, opts)
	if err != nil {
		return fmt.Errorf("add channel: %w", err)
	}
	fmt.Printf("added %s channel [%d]\n", *chType, id)
	return nil
}

func handleChannelUpdate(args []string) error {
	fs := flag.NewFlagSet("channel update", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	enabled := fs.String("enabled", "", "set enabled state (true or false)")
	url := fs.String("url", "", "update webhook URL")
	secret := fs.String("secret", "", "update webhook HMAC secret")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice channel update <id> [--enabled true|false] [--url <url>] [--secret <secret>]")
	}

	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid channel ID %q: %w", fs.Arg(0), err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Check that channel exists.
	ch, err := db.GetChannel(id)
	if err != nil {
		return fmt.Errorf("get channel: %w", err)
	}
	if ch == nil {
		return fmt.Errorf("no channel with ID %d", id)
	}

	update := store.ChannelUpdate{}
	if *enabled != "" {
		val, parseErr := strconv.ParseBool(*enabled)
		if parseErr != nil {
			return fmt.Errorf("invalid --enabled value %q: must be true or false", *enabled)
		}
		update.Enabled = &val
	}
	if *url != "" {
		update.WebhookURL = url
	}
	if *secret != "" {
		update.WebhookSecret = secret
	}

	if err := db.UpdateChannel(id, update); err != nil {
		return fmt.Errorf("update channel: %w", err)
	}
	fmt.Printf("updated channel [%d]\n", id)
	return nil
}

func handleChannelRemove(args []string) error {
	fs := flag.NewFlagSet("channel remove", flag.ContinueOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice channel remove <id>")
	}

	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid channel ID %q: %w", fs.Arg(0), err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Prevent removing the last enabled channel.
	ch, err := db.GetChannel(id)
	if err != nil {
		return fmt.Errorf("get channel: %w", err)
	}
	if ch == nil {
		return fmt.Errorf("no channel with ID %d", id)
	}
	if ch.Enabled {
		count, countErr := db.CountEnabledChannels()
		if countErr != nil {
			return fmt.Errorf("count enabled channels: %w", countErr)
		}
		if count <= 1 {
			return fmt.Errorf("cannot remove the last enabled channel")
		}
	}

	deleted, err := db.RemoveChannel(id)
	if err != nil {
		return fmt.Errorf("remove channel: %w", err)
	}
	if !deleted {
		return fmt.Errorf("no channel with ID %d", id)
	}
	fmt.Printf("removed channel [%d]\n", id)
	return nil
}

func channelTypeName(t int) string {
	switch t {
	case int(channel.ChannelTelegram):
		return "telegram"
	case int(channel.ChannelHTTP):
		return "http"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
