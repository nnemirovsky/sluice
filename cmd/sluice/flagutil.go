package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/nemirovsky/sluice/internal/flagutil"
)

// parsePortsList parses a comma-separated string of port numbers into a
// []int, validating that each port is in the legal 1-65535 range. An empty
// input returns (nil, nil) so callers can pass through "no port filter"
// without a special case. Whitespace around each entry is trimmed.
//
// Used by the binding/policy/cred CLI subcommands which all share the
// same --ports flag shape.
func parsePortsList(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var ports []int
	for _, ps := range strings.Split(s, ",") {
		ps = strings.TrimSpace(ps)
		p, err := strconv.Atoi(ps)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", ps, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", p)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// parseProtocolsList parses a comma-separated string of protocol names into
// a []string. An empty input returns (nil, nil). Whitespace around each
// entry is trimmed and the name is lowercased.
//
// Validation against the known protocol set is deferred to the store layer
// (validateProtocols) which runs during AddRule/ImportTOML. This keeps
// the canonical list in one place.
func parseProtocolsList(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var protocols []string
	for _, ps := range strings.Split(s, ",") {
		ps = strings.TrimSpace(strings.ToLower(ps))
		if ps == "" {
			return nil, fmt.Errorf("empty protocol name in list")
		}
		protocols = append(protocols, ps)
	}
	return protocols, nil
}

// reorderFlagsBeforePositional is a thin alias over flagutil.ReorderFlagsBeforePositional
// so existing cmd/sluice callers (and their many tests) keep the old signature
// without churn. New code should import internal/flagutil directly.
func reorderFlagsBeforePositional(args []string, fs *flag.FlagSet) []string {
	return flagutil.ReorderFlagsBeforePositional(args, fs)
}
