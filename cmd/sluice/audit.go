package main

import (
	"fmt"
	"os"

	"github.com/nemirovsky/sluice/internal/audit"
)

func handleAuditCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: sluice audit [verify] [path]")
		os.Exit(1)
	}

	switch args[0] {
	case "verify":
		path := "audit.jsonl"
		if len(args) > 1 {
			path = args[1]
		}
		handleAuditVerify(path)
	default:
		fmt.Printf("unknown audit command: %s\n", args[0])
		fmt.Println("usage: sluice audit [verify] [path]")
		os.Exit(1)
	}
}

func handleAuditVerify(path string) {
	result, err := audit.VerifyChain(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Total lines:  %d\n", result.TotalLines)
	fmt.Printf("Valid links:  %d\n", result.ValidLinks)
	fmt.Printf("Legacy lines: %d\n", result.LegacyLines)
	fmt.Printf("Broken links: %d\n", len(result.BrokenLinks))

	for _, bl := range result.BrokenLinks {
		fmt.Printf("  line %d: expected %s, got %s\n", bl.LineNumber, bl.ExpectedHash, bl.ActualHash)
	}

	if len(result.BrokenLinks) > 0 {
		os.Exit(1)
	}
}
