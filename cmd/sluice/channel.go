package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/store"
)

func handleChannelCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice channel [list|add|update|remove] ...")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		handleChannelList(args[1:])
	case "add":
		handleChannelAdd(args[1:])
	case "update":
		handleChannelUpdate(args[1:])
	case "remove":
		handleChannelRemove(args[1:])
	default:
		fmt.Printf("unknown channel command: %s\n", args[0])
		fmt.Println("usage: sluice channel [list|add|update|remove] ...")
		os.Exit(1)
	}
}

func handleChannelList(args []string) {
	fs := flag.NewFlagSet("channel list", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	_ = fs.Parse(args)

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	channels, err := db.ListChannels()
	if err != nil {
		log.Fatalf("list channels: %v", err)
	}

	if len(channels) == 0 {
		fmt.Println("no channels configured")
		return
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
}

func handleChannelAdd(args []string) {
	fs := flag.NewFlagSet("channel add", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	chType := fs.String("type", "", "channel type (telegram or http)")
	url := fs.String("url", "", "webhook URL (required for http type)")
	secret := fs.String("secret", "", "webhook HMAC secret (optional, for http type)")
	_ = fs.Parse(args)

	if *chType == "" {
		fmt.Println("usage: sluice channel add --type <telegram|http> [--url <url>] [--secret <secret>]")
		os.Exit(1)
	}

	var typeInt int
	switch *chType {
	case "telegram":
		typeInt = int(channel.ChannelTelegram)
	case "http":
		typeInt = int(channel.ChannelHTTP)
		if *url == "" {
			fmt.Println("--url is required for http channel type")
			os.Exit(1)
		}
	default:
		fmt.Printf("invalid channel type: %s (must be telegram or http)\n", *chType)
		os.Exit(1)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	opts := store.AddChannelOpts{
		WebhookURL:    *url,
		WebhookSecret: *secret,
	}

	id, err := db.AddChannel(typeInt, true, opts)
	if err != nil {
		log.Fatalf("add channel: %v", err)
	}
	fmt.Printf("added %s channel [%d]\n", *chType, id)
}

func handleChannelUpdate(args []string) {
	fs := flag.NewFlagSet("channel update", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	enabled := fs.String("enabled", "", "set enabled state (true or false)")
	url := fs.String("url", "", "update webhook URL")
	secret := fs.String("secret", "", "update webhook HMAC secret")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice channel update <id> [--enabled true|false] [--url <url>] [--secret <secret>]")
		os.Exit(1)
	}

	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		log.Fatalf("invalid channel ID %q: %v", fs.Arg(0), err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Check that channel exists.
	ch, err := db.GetChannel(id)
	if err != nil {
		log.Fatalf("get channel: %v", err)
	}
	if ch == nil {
		fmt.Printf("no channel with ID %d\n", id)
		os.Exit(1)
	}

	update := store.ChannelUpdate{}
	if *enabled != "" {
		val, parseErr := strconv.ParseBool(*enabled)
		if parseErr != nil {
			log.Fatalf("invalid --enabled value %q: must be true or false", *enabled)
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
		log.Fatalf("update channel: %v", err)
	}
	fmt.Printf("updated channel [%d]\n", id)
}

func handleChannelRemove(args []string) {
	fs := flag.NewFlagSet("channel remove", flag.ExitOnError)
	dbPath := fs.String("db", "sluice.db", "path to SQLite database")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Println("usage: sluice channel remove <id>")
		os.Exit(1)
	}

	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		log.Fatalf("invalid channel ID %q: %v", fs.Arg(0), err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Prevent removing the last enabled channel.
	ch, err := db.GetChannel(id)
	if err != nil {
		log.Fatalf("get channel: %v", err)
	}
	if ch == nil {
		fmt.Printf("no channel with ID %d\n", id)
		os.Exit(1)
	}
	if ch.Enabled {
		count, countErr := db.CountEnabledChannels()
		if countErr != nil {
			log.Fatalf("count enabled channels: %v", countErr)
		}
		if count <= 1 {
			fmt.Println("cannot remove the last enabled channel")
			os.Exit(1)
		}
	}

	deleted, err := db.RemoveChannel(id)
	if err != nil {
		log.Fatalf("remove channel: %v", err)
	}
	if !deleted {
		fmt.Printf("no channel with ID %d\n", id)
		os.Exit(1)
	}
	fmt.Printf("removed channel [%d]\n", id)
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
