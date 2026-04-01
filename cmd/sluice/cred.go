package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/nemirovsky/sluice/internal/vault"
	"golang.org/x/term"
)

func handleCredCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice cred [add|list|remove] ...")
		os.Exit(1)
	}

	vaultDir := os.Getenv("SLUICE_VAULT_DIR")
	if vaultDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("determine home dir: %v", err)
		}
		vaultDir = filepath.Join(home, ".sluice")
	}

	store, err := vault.NewStore(vaultDir)
	if err != nil {
		log.Fatalf("open vault: %v", err)
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("usage: sluice cred add <name>")
			os.Exit(1)
		}
		fmt.Print("Enter secret: ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("read secret: %v", err)
		}
		if err := store.Add(args[1], string(secret)); err != nil {
			log.Fatalf("add credential: %v", err)
		}
		fmt.Printf("credential %q added\n", args[1])

	case "list":
		names, err := store.List()
		if err != nil {
			log.Fatalf("list: %v", err)
		}
		for _, n := range names {
			fmt.Println(n)
		}

	case "remove":
		if len(args) < 2 {
			fmt.Println("usage: sluice cred remove <name>")
			os.Exit(1)
		}
		if err := store.Remove(args[1]); err != nil {
			log.Fatalf("remove: %v", err)
		}
		fmt.Printf("credential %q removed\n", args[1])

	default:
		fmt.Printf("unknown cred command: %s\n", args[0])
		fmt.Println("usage: sluice cred [add|list|remove] ...")
		os.Exit(1)
	}
}
