package main

import (
	"fmt"

	"github.com/nemirovsky/sluice/internal/audit"
)

func handleAuditCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sluice audit [verify] [path]")
	}

	switch args[0] {
	case "verify":
		path := "audit.jsonl"
		if len(args) > 1 {
			path = args[1]
		}
		return handleAuditVerify(path)
	default:
		return fmt.Errorf("unknown audit command: %s\nusage: sluice audit [verify] [path]", args[0])
	}
}

func handleAuditVerify(path string) error {
	result, err := audit.VerifyChain(path)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	fmt.Printf("Total lines:  %d\n", result.TotalLines)
	fmt.Printf("Valid links:  %d\n", result.ValidLinks)
	fmt.Printf("Legacy lines: %d\n", result.LegacyLines)
	fmt.Printf("Broken links: %d\n", len(result.BrokenLinks))

	for _, bl := range result.BrokenLinks {
		fmt.Printf("  line %d: expected %s, got %s\n", bl.LineNumber, bl.ExpectedHash, bl.ActualHash)
	}

	if len(result.BrokenLinks) > 0 {
		return fmt.Errorf("audit chain has %d broken link(s)", len(result.BrokenLinks))
	}
	return nil
}
