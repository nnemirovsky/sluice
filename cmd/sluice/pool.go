package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

func handlePoolCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice pool [create|list|status|rotate|remove]")
	}

	switch args[0] {
	case "create":
		return handlePoolCreate(args[1:])
	case "list":
		return handlePoolList(args[1:])
	case "status":
		return handlePoolStatus(args[1:])
	case "rotate":
		return handlePoolRotate(args[1:])
	case "remove":
		return handlePoolRemove(args[1:])
	default:
		return fmt.Errorf("unknown pool command: %s (usage: sluice pool [create|list|status|rotate|remove] ...)", args[0])
	}
}

func handlePoolCreate(args []string) error {
	fs := flag.NewFlagSet("pool create", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	membersStr := fs.String("members", "", "comma-separated ordered list of oauth credential names (failover order)")
	strategy := fs.String("strategy", store.PoolStrategyFailover, "pool strategy (only 'failover' is supported)")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice pool create <name> --members a,b[,c] [--strategy failover]")
	}
	name := fs.Arg(0)

	if *membersStr == "" {
		return fmt.Errorf("--members is required (comma-separated oauth credential names)")
	}
	var members []string
	for _, m := range strings.Split(*membersStr, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			return fmt.Errorf("empty credential name in --members list")
		}
		members = append(members, m)
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.CreatePoolWithMembers(name, *strategy, members); err != nil {
		return err
	}

	fmt.Printf("pool %q created (strategy: %s)\n", name, *strategy)
	for i, m := range members {
		fmt.Printf("  [%d] %s\n", i, m)
	}
	fmt.Printf("bind it with: sluice binding add %s --destination <host> [--ports 443]\n", name)
	return nil
}

func handlePoolList(args []string) error {
	fs := flag.NewFlagSet("pool list", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	pools, err := db.ListPools()
	if err != nil {
		return err
	}
	if len(pools) == 0 {
		fmt.Println("no credential pools configured")
		return nil
	}
	for _, p := range pools {
		names := make([]string, 0, len(p.Members))
		for _, m := range p.Members {
			names = append(names, m.Credential)
		}
		fmt.Printf("%s (strategy: %s): %s\n", p.Name, p.Strategy, strings.Join(names, ", "))
	}
	return nil
}

func handlePoolStatus(args []string) error {
	fs := flag.NewFlagSet("pool status", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice pool status <name>")
	}
	name := fs.Arg(0)

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	p, err := db.GetPool(name)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("pool %q not found", name)
	}
	healthRows, err := db.ListCredentialHealth()
	if err != nil {
		return err
	}

	// Compute the active member using the exact same selection logic the
	// proxy uses at injection time so `pool status` never disagrees with
	// what would actually be injected.
	resolver := vault.NewPoolResolver([]store.Pool{*p}, healthRows)
	active, _ := resolver.ResolveActive(name)

	healthByCred := make(map[string]store.CredentialHealth, len(healthRows))
	for _, h := range healthRows {
		healthByCred[h.Credential] = h
	}

	fmt.Printf("pool %q (strategy: %s)\n", p.Name, p.Strategy)
	now := time.Now()
	for _, m := range p.Members {
		marker := "  "
		if m.Credential == active {
			marker = "* "
		}
		status := "healthy"
		if h, ok := healthByCred[m.Credential]; ok && h.Status == "cooldown" && !h.CooldownUntil.IsZero() {
			if h.CooldownUntil.After(now) {
				status = fmt.Sprintf("cooldown until %s", h.CooldownUntil.Format(time.RFC3339))
			} else {
				status = "healthy (cooldown expired)"
			}
			if h.LastFailureReason != "" {
				status += " — " + h.LastFailureReason
			}
		}
		fmt.Printf("%s[%d] %s  %s\n", marker, m.Position, m.Credential, status)
	}
	fmt.Printf("active: %s\n", active)
	return nil
}

func handlePoolRotate(args []string) error {
	fs := flag.NewFlagSet("pool rotate", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice pool rotate <name>")
	}
	name := fs.Arg(0)

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	p, err := db.GetPool(name)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("pool %q not found", name)
	}
	healthRows, err := db.ListCredentialHealth()
	if err != nil {
		return err
	}
	resolver := vault.NewPoolResolver([]store.Pool{*p}, healthRows)
	active, ok := resolver.ResolveActive(name)
	if !ok || active == "" {
		return fmt.Errorf("pool %q has no resolvable member to rotate away from", name)
	}

	// Manual override: park the current active member so the next member in
	// position order becomes active. The cooldown lapses on its own (lazy
	// recovery, same as auto-failover), so a rotated-away member rejoins the
	// rotation once its cooldown expires.
	until := time.Now().Add(vault.AuthFailCooldown)
	if err := db.SetCredentialHealth(active, "cooldown", until, "manual rotate"); err != nil {
		return err
	}

	// Recompute the new active member for operator feedback.
	healthRows, err = db.ListCredentialHealth()
	if err != nil {
		return err
	}
	resolver = vault.NewPoolResolver([]store.Pool{*p}, healthRows)
	next, _ := resolver.ResolveActive(name)
	fmt.Printf("pool %q rotated: %s -> %s (parked %s until %s)\n",
		name, active, next, active, until.Format(time.RFC3339))
	return nil
}

func handlePoolRemove(args []string) error {
	fs := flag.NewFlagSet("pool remove", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice pool remove <name>")
	}
	name := fs.Arg(0)

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Reject the removal while any binding still references this pool by
	// name. A pool shares the credential namespace, so a binding's
	// "credential" column may hold the pool name (e.g. created via
	// "sluice binding add <pool> --destination ..."). Deleting the pool
	// out from under such bindings would leave them pointing at a
	// non-existent credential (injection silently fails for those
	// destinations) and, worse, a later credential created with the same
	// name would silently inherit the stale bindings. This mirrors the
	// fail-closed pool-membership guard in "sluice cred remove": refuse
	// with an actionable error instead of cascading or orphaning.
	refs, err := db.ListBindingsByCredential(name)
	if err != nil {
		return fmt.Errorf("check bindings referencing pool %q: %w", name, err)
	}
	if len(refs) > 0 {
		details := make([]string, len(refs))
		for i, b := range refs {
			details[i] = fmt.Sprintf("[%d] %s", b.ID, b.Destination)
		}
		return fmt.Errorf("pool %q is still referenced by %d binding(s): %s; rebind or remove these bindings first (sluice binding remove <id>, which also clears the auto-created allow rule), then retry pool remove",
			name, len(refs), strings.Join(details, ", "))
	}

	removed, err := db.RemovePool(name)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("pool %q not found", name)
	}
	fmt.Printf("pool %q removed\n", name)
	return nil
}
