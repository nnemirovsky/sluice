package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/nemirovsky/sluice/internal/poolops"
	"github.com/nemirovsky/sluice/internal/store"
)

func handlePoolCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice pool [create|list|status|rotate|set-auth-reset|remove]")
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
	case "set-auth-reset":
		return handlePoolSetAuthReset(args[1:])
	case "remove":
		return handlePoolRemove(args[1:])
	default:
		return fmt.Errorf("unknown pool command: %s (usage: sluice pool [create|list|status|rotate|set-auth-reset|remove] ...)", args[0])
	}
}

func handlePoolCreate(args []string) error {
	fs := flag.NewFlagSet("pool create", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	membersStr := fs.String("members", "", "comma-separated ordered list of oauth credential names (failover order)")
	strategy := fs.String("strategy", store.PoolStrategyFailover, "pool strategy (only 'failover' is supported)")
	authResetTarget := fs.String("auth-reset-target", "", "agent auth-reset target run on the exhausted->recovered edge (e.g. openai-codex); empty = no reset")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: sluice pool create <name> --members a,b[,c] [--strategy failover] [--auth-reset-target <target>]")
	}
	name := fs.Arg(0)

	if *membersStr == "" {
		return fmt.Errorf("--members is required (comma-separated oauth credential names)")
	}
	members, err := poolops.ParseMembers(*membersStr)
	if err != nil {
		return err
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := poolops.CreateWithAuthResetTarget(db, name, *strategy, members, *authResetTarget); err != nil {
		return err
	}

	fmt.Printf("pool %q created (strategy: %s)\n", name, *strategy)
	for i, m := range members {
		fmt.Printf("  [%d] %s\n", i, m)
	}
	if *authResetTarget != "" {
		fmt.Printf("auth-reset target: %s\n", *authResetTarget)
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

	pools, err := poolops.List(db)
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
		if p.AuthResetTarget != "" {
			fmt.Printf("  auth-reset target: %s\n", p.AuthResetTarget)
		}
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

	res, err := poolops.Status(db, name)
	if err != nil {
		var nf *poolops.PoolNotFoundError
		if errors.As(err, &nf) {
			return fmt.Errorf("pool %q not found", name)
		}
		return err
	}

	fmt.Printf("pool %q (strategy: %s)\n", res.Name, res.Strategy)
	for _, m := range res.Members {
		marker := "  "
		if m.Active {
			marker = "* "
		}
		status := "healthy"
		switch m.State {
		case "cooldown":
			status = fmt.Sprintf("cooldown until %s", m.CooldownUntil.Format(time.RFC3339))
			if m.LastFailureReason != "" {
				status += " — " + m.LastFailureReason
			}
		case "healthy (cooldown expired)":
			status = "healthy (cooldown expired)"
			if m.LastFailureReason != "" {
				status += " — " + m.LastFailureReason
			}
		}
		fmt.Printf("%s[%d] %s  %s\n", marker, m.Position, m.Credential, status)
	}
	fmt.Printf("active: %s\n", res.Active)
	if res.AuthResetTarget != "" {
		fmt.Printf("auth-reset target: %s\n", res.AuthResetTarget)
	}
	return nil
}

func handlePoolSetAuthReset(args []string) error {
	fs := flag.NewFlagSet("pool set-auth-reset", flag.ContinueOnError)
	dbPath := fs.String("db", "data/sluice.db", "path to SQLite database")
	if err := fs.Parse(reorderFlagsBeforePositional(args, fs)); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: sluice pool set-auth-reset <name> <target|->  (a single - clears the target)")
	}
	name := fs.Arg(0)
	target := fs.Arg(1)
	// A single "-" is the channel-uniform clear sentinel.
	if target == "-" {
		target = ""
	}

	db, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := poolops.SetAuthResetTarget(db, name, target); err != nil {
		var nf *poolops.PoolNotFoundError
		if errors.As(err, &nf) {
			return fmt.Errorf("pool %q not found", name)
		}
		return err
	}
	if target == "" {
		fmt.Printf("pool %q auth-reset target cleared\n", name)
	} else {
		fmt.Printf("pool %q auth-reset target set to %q\n", name, target)
	}
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

	res, err := poolops.Rotate(db, name)
	if err != nil {
		var nf *poolops.PoolNotFoundError
		if errors.As(err, &nf) {
			return fmt.Errorf("pool %q not found", name)
		}
		// poolops keeps RotateRaceError channel-neutral; the CLI adds its
		// own remediation hint here so CLI UX is unchanged.
		var race *poolops.RotateRaceError
		if errors.As(err, &race) {
			return fmt.Errorf("%w; re-check the pool with \"sluice pool status %s\" and retry", err, name)
		}
		return err
	}
	fmt.Printf("pool %q rotated: %s -> %s (parked %s until %s)\n",
		name, res.From, res.To, res.From, res.ParkedUntil.Format(time.RFC3339))
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

	err = poolops.Remove(db, name)
	if err != nil {
		var refErr *store.PoolReferencedError
		if errors.As(err, &refErr) {
			details := make([]string, len(refErr.Bindings))
			for i, b := range refErr.Bindings {
				details[i] = fmt.Sprintf("[%d] %s", b.ID, b.Destination)
			}
			return fmt.Errorf("pool %q is still referenced by %d binding(s): %s; rebind or remove these bindings first (sluice binding remove <id>, which also clears the auto-created allow rule), then retry pool remove",
				name, len(refErr.Bindings), strings.Join(details, ", "))
		}
		var nf *poolops.PoolNotFoundError
		if errors.As(err, &nf) {
			return fmt.Errorf("pool %q not found", name)
		}
		return err
	}
	fmt.Printf("pool %q removed\n", name)
	return nil
}
