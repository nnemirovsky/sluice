package main

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
)

// bindingAddSourcePrefix is the source tag prefix for rules auto-created by
// "sluice binding add". Mirrors credAddSourcePrefix so that rules created as
// part of a binding add are easy to identify and clean up.
const bindingAddSourcePrefix = "binding-add:"

func handleBindingCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice binding [add|list|update|remove]")
	}

	switch args[0] {
	case "add":
		return handleBindingAdd(args[1:])
	case "list":
		return handleBindingList(args[1:])
	case "update":
		return handleBindingUpdate(args[1:])
	case "remove":
		return handleBindingRemove(args[1:])
	default:
		return fmt.Errorf("unknown binding command: %s (usage: sluice binding [add|list|update|remove] ...)", args[0])
	}
}

func handleBindingAdd(args []string) error {
	fs := flag.NewFlagSet("binding add", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	destination := fs.String("destination", "", "destination host pattern for the binding (required)")
	portsStr := fs.String("ports", "", "comma-separated port list (e.g. 443,80)")
	header := fs.String("header", "", "header for credential injection (e.g. Authorization)")
	template := fs.String("template", "", "template for credential injection (e.g. \"Bearer {value}\")")
	envVar := fs.String("env-var", "", "environment variable name for phantom injection (e.g. OPENAI_API_KEY)")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice binding add <credential> --destination <host> [--ports 443] [--header Authorization] [--template \"Bearer {value}\"] [--env-var OPENAI_API_KEY]")
	}
	credential := fs.Arg(0)

	if *destination == "" {
		return fmt.Errorf("--destination is required")
	}

	if _, err := policy.CompileGlob(*destination); err != nil {
		return fmt.Errorf("invalid destination pattern %q: %w", *destination, err)
	}

	var ports []int
	if *portsStr != "" {
		for _, ps := range strings.Split(*portsStr, ",") {
			ps = strings.TrimSpace(ps)
			p, err := strconv.Atoi(ps)
			if err != nil {
				return fmt.Errorf("invalid port %q: %w", ps, err)
			}
			if p < 1 || p > 65535 {
				return fmt.Errorf("port %d out of range (1-65535)", p)
			}
			ports = append(ports, p)
		}
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Create both the allow rule and the binding atomically, matching the
	// behavior of "sluice cred add --destination". The rule source is tagged
	// with bindingAddSourcePrefix+credential so cleanup can find it later.
	ruleID, bindingID, err := db.AddRuleAndBinding(
		"allow",
		store.RuleOpts{
			Destination: *destination,
			Ports:       ports,
			Name:        fmt.Sprintf("auto-created for binding on credential %q", credential),
			Source:      bindingAddSourcePrefix + credential,
		},
		credential,
		store.BindingOpts{
			Ports:    ports,
			Header:   *header,
			Template: *template,
			EnvVar:   *envVar,
		},
	)
	if err != nil {
		return fmt.Errorf("add rule and binding: %w", err)
	}
	fmt.Printf("added allow rule [%d] for %s\n", ruleID, *destination)
	fmt.Printf("added binding [%d] %s -> %s\n", bindingID, *destination, credential)
	return nil
}

func handleBindingList(args []string) error {
	fs := flag.NewFlagSet("binding list", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	credFilter := fs.String("credential", "", "filter bindings by credential name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	var bindings []store.BindingRow
	if *credFilter != "" {
		bindings, err = db.ListBindingsByCredential(*credFilter)
	} else {
		bindings, err = db.ListBindings()
	}
	if err != nil {
		return fmt.Errorf("list bindings: %w", err)
	}

	if len(bindings) == 0 {
		fmt.Println("no bindings found")
		return nil
	}

	for _, b := range bindings {
		ports := ""
		if len(b.Ports) > 0 {
			portStrs := make([]string, len(b.Ports))
			for i, p := range b.Ports {
				portStrs[i] = strconv.Itoa(p)
			}
			ports = " ports=" + strings.Join(portStrs, ",")
		}
		protos := ""
		if len(b.Protocols) > 0 {
			sorted := append([]string(nil), b.Protocols...)
			sort.Strings(sorted)
			protos = " protocols=" + strings.Join(sorted, ",")
		}
		hdr := ""
		if b.Header != "" {
			hdr = " header=" + b.Header
		}
		tmpl := ""
		if b.Template != "" {
			tmpl = " template=" + b.Template
		}
		env := ""
		if b.EnvVar != "" {
			env = " env=" + b.EnvVar
		}
		fmt.Printf("[%d] %s -> %s%s%s%s%s%s\n",
			b.ID, b.Credential, b.Destination, ports, protos, hdr, tmpl, env)
	}
	return nil
}

func handleBindingUpdate(args []string) error {
	fs := flag.NewFlagSet("binding update", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	// Use pointer-nil-means-skip pattern: only fields explicitly set by the
	// caller should be updated. The flag package cannot give us "was this
	// flag set at all?", so we track via fs.Visit after parsing.
	destination := fs.String("destination", "", "new destination host pattern")
	portsStr := fs.String("ports", "", "new comma-separated port list (empty string to clear)")
	header := fs.String("header", "", "new header (empty string to clear)")
	template := fs.String("template", "", "new template (empty string to clear)")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice binding update <id> [--destination <host>] [--ports 443] [--header Authorization] [--template \"Bearer {value}\"]")
	}
	idStr := fs.Arg(0)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid binding id %q: %w", idStr, err)
	}

	// Track which flags were explicitly set so we pass only those.
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if !set["destination"] && !set["ports"] && !set["header"] && !set["template"] {
		return fmt.Errorf("no fields to update: provide at least one of --destination, --ports, --header, --template")
	}

	opts := store.BindingUpdateOpts{}
	if set["destination"] {
		if _, err := policy.CompileGlob(*destination); err != nil {
			return fmt.Errorf("invalid destination pattern %q: %w", *destination, err)
		}
		d := *destination
		opts.Destination = &d
	}
	if set["ports"] {
		var ports []int
		if *portsStr != "" {
			for _, ps := range strings.Split(*portsStr, ",") {
				ps = strings.TrimSpace(ps)
				p, pErr := strconv.Atoi(ps)
				if pErr != nil {
					return fmt.Errorf("invalid port %q: %w", ps, pErr)
				}
				if p < 1 || p > 65535 {
					return fmt.Errorf("port %d out of range (1-65535)", p)
				}
				ports = append(ports, p)
			}
		}
		opts.Ports = &ports
	}
	if set["header"] {
		h := *header
		opts.Header = &h
	}
	if set["template"] {
		t := *template
		opts.Template = &t
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.UpdateBinding(id, opts); err != nil {
		return fmt.Errorf("update binding: %w", err)
	}
	fmt.Printf("updated binding [%d]\n", id)
	return nil
}

func handleBindingRemove(args []string) error {
	fs := flag.NewFlagSet("binding remove", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice binding remove <id>")
	}
	idStr := fs.Arg(0)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid binding id %q: %w", idStr, err)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	deleted, err := db.RemoveBinding(id)
	if err != nil {
		return fmt.Errorf("remove binding: %w", err)
	}
	if !deleted {
		return fmt.Errorf("binding %d not found", id)
	}
	fmt.Printf("removed binding [%d]\n", id)
	return nil
}
