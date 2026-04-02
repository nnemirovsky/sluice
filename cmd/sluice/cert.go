package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/nemirovsky/sluice/internal/proxy"
)

func handleCertCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice cert [generate]")
		os.Exit(1)
	}

	switch args[0] {
	case "generate":
		handleCertGenerate(args[1:])
	default:
		fmt.Printf("unknown cert command: %s\n", args[0])
		fmt.Println("usage: sluice cert [generate]")
		os.Exit(1)
	}
}

func handleCertGenerate(args []string) {
	fs := flag.NewFlagSet("cert generate", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory for CA cert and key (default: $SLUICE_VAULT_DIR or ~/.sluice)")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("parse flags: %v", err)
	}

	dir := *outDir
	if dir == "" {
		dir = os.Getenv("SLUICE_VAULT_DIR")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("determine home dir: %v", err)
		}
		dir = filepath.Join(home, ".sluice")
	}

	_, _, err := proxy.LoadOrCreateCA(dir)
	if err != nil {
		log.Fatalf("generate CA: %v", err)
	}

	certPath := filepath.Join(dir, "ca-cert.pem")
	fmt.Printf("CA certificate: %s\n", certPath)
	fmt.Printf("CA private key: %s\n", filepath.Join(dir, "ca-key.pem"))
	fmt.Println("Mount ca-cert.pem into agent containers as a trusted root CA.")
}
