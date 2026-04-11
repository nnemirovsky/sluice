package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
)

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

	ports, err := parsePortsList(*portsStr)
	if err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Create both the allow rule and the binding atomically, matching the
	// behavior of "sluice cred add --destination". The rule source is tagged
	// with store.BindingAddSourcePrefix+credential so cleanup can find it
	// later. The partial UNIQUE index on bindings(credential, destination)
	// rejects duplicates across all writers. A duplicate returns
	// store.ErrBindingDuplicate which we translate into the CLI's friendlier
	// message including the existing binding id.
	ruleID, bindingID, err := db.AddRuleAndBinding(
		"allow",
		store.RuleOpts{
			Destination: *destination,
			Ports:       ports,
			Name:        fmt.Sprintf("auto-created for binding on credential %q", credential),
			Source:      store.BindingAddSourcePrefix + credential,
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
		if errors.Is(err, store.ErrBindingDuplicate) {
			return err
		}
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
	protocolsStr := fs.String("protocols", "", "new comma-separated protocol list (e.g. http,grpc; empty string to clear)")
	envVar := fs.String("env-var", "", "new environment variable name (empty string to clear)")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice binding update <id> [--destination <host>] [--ports 443] [--header Authorization] [--template \"Bearer {value}\"] [--protocols http,grpc] [--env-var OPENAI_API_KEY]")
	}
	idStr := fs.Arg(0)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid binding id %q: %w", idStr, err)
	}

	// Track which flags were explicitly set so we pass only those.
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if !set["destination"] && !set["ports"] && !set["header"] && !set["template"] && !set["protocols"] && !set["env-var"] {
		return fmt.Errorf("no fields to update: provide at least one of --destination, --ports, --header, --template, --protocols, --env-var")
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
		ports, pErr := parsePortsList(*portsStr)
		if pErr != nil {
			return pErr
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
	if set["protocols"] {
		var protocols []string
		if *protocolsStr != "" {
			for _, p := range strings.Split(*protocolsStr, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					protocols = append(protocols, p)
				}
			}
		}
		opts.Protocols = &protocols
	}
	if set["env-var"] {
		e := *envVar
		opts.EnvVar = &e
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// UpdateBindingWithRuleSync performs the read, the binding update, and
	// (when destination, ports, or protocols change) the paired-rule update
	// all inside one transaction, so concurrent writers cannot observe a
	// partial state.
	ruleID, ruleFound, currentBinding, err := db.UpdateBindingWithRuleSync(id, opts)
	if err != nil {
		if errors.Is(err, store.ErrBindingDuplicate) || errors.Is(err, store.ErrBindingNotFound) {
			return err
		}
		return fmt.Errorf("update binding: %w", err)
	}

	// Report the paired-rule sync outcome. Intentionally no fallback rule is
	// created when the paired rule was missing: an operator may have removed
	// it on purpose. We warn instead so the change is visible in stdout.
	destChanged := opts.Destination != nil && *opts.Destination != currentBinding.Destination
	portsChanged := opts.Ports != nil
	protocolsChanged := opts.Protocols != nil
	if destChanged || portsChanged || protocolsChanged {
		if ruleFound {
			fmt.Printf("updated paired allow rule [%d] (destination=%t ports=%t protocols=%t)\n",
				ruleID, destChanged, portsChanged, protocolsChanged)
		} else {
			fmt.Printf("warning: no paired allow rule found for credential %q destination %q; binding updated without a matching rule\n",
				currentBinding.Credential, currentBinding.Destination)
		}
	}

	fmt.Printf("updated binding [%d]\n", id)
	return nil
}

func handleBindingRemove(args []string) error {
	fs := flag.NewFlagSet("binding remove", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
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

	// RemoveBindingWithRuleCleanup atomically reads the binding, deletes it,
	// and removes the paired auto-created allow rule in a single transaction.
	// This closes the TOCTOU window where a concurrent writer (e.g. via the
	// REST API or another CLI invocation) could move the binding to a new
	// destination between the snapshot and the delete and leave an orphaned
	// rule pointing at the previous destination.
	_, _, removedRules, _, found, err := db.RemoveBindingWithRuleCleanup(id)
	if err != nil {
		return fmt.Errorf("remove binding: %w", err)
	}
	if !found {
		return fmt.Errorf("binding %d not found", id)
	}
	if removedRules > 0 {
		fmt.Printf("removed %d paired allow rule(s) for binding [%d]\n", removedRules, id)
	}
	fmt.Printf("removed binding [%d]\n", id)
	return nil
}
