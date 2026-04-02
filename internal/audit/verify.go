package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult holds the outcome of a hash chain verification.
type VerifyResult struct {
	TotalLines  int
	ValidLinks  int
	BrokenLinks []BrokenLink
	LegacyLines int // lines without prev_hash (pre-upgrade)
}

// BrokenLink records a single hash chain discontinuity.
type BrokenLink struct {
	LineNumber   int
	ExpectedHash string
	ActualHash   string
}

// VerifyChain reads the audit log at path and checks every hash link.
// It returns the verification result or an error if the file cannot be read.
func VerifyChain(path string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	result := &VerifyResult{}
	expectedHash := hashLine([]byte("")) // genesis

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		lineNum++
		result.TotalLines++

		var evt Event
		if err := json.Unmarshal(line, &evt); err != nil {
			return nil, fmt.Errorf("parse line %d: %w", lineNum, err)
		}

		if evt.PrevHash == "" {
			result.LegacyLines++
			// Still update expectedHash so that if a chained line follows
			// a legacy line, we track the raw content hash.
			expectedHash = hashLine(line)
			continue
		}

		if evt.PrevHash != expectedHash {
			result.BrokenLinks = append(result.BrokenLinks, BrokenLink{
				LineNumber:   lineNum,
				ExpectedHash: expectedHash,
				ActualHash:   evt.PrevHash,
			})
		} else {
			result.ValidLinks++
		}

		expectedHash = hashLine(line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	return result, nil
}
