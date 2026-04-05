package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nemirovsky/sluice/internal/proxy"
)

func handleCertCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice cert [generate]")
	}

	switch args[0] {
	case "generate":
		return handleCertGenerate(args[1:])
	default:
		return fmt.Errorf("unknown cert command: %s\nusage: sluice cert [generate]", args[0])
	}
}

func handleCertGenerate(args []string) error {
	fs := flag.NewFlagSet("cert generate", flag.ContinueOnError)
	outDir := fs.String("out", "", "output directory for CA cert and key (default: $SLUICE_VAULT_DIR or ~/.sluice)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := *outDir
	if dir == "" {
		dir = os.Getenv("SLUICE_VAULT_DIR")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("determine home dir: %w", err)
		}
		dir = filepath.Join(home, ".sluice")
	}

	_, _, err := proxy.LoadOrCreateCA(dir)
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}

	certPath := filepath.Join(dir, "ca-cert.pem")
	fmt.Printf("CA certificate: %s\n", certPath)
	fmt.Printf("CA private key: %s\n", filepath.Join(dir, "ca-key.pem"))
	fmt.Println("Mount ca-cert.pem into agent containers as a trusted root CA.")
	return nil
}
