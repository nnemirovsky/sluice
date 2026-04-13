package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
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

// reorderFlagsBeforePositional returns a copy of args with all flag
// arguments moved before any positional arguments, so that Go's stdlib
// flag parser (which stops at the first non-flag) still sees every flag.
//
// The FlagSet is consulted to determine which flags take a value and
// therefore consume the following arg. "--flag=value" form is left as
// a single token. "--" is treated as a terminator; everything after it
// is positional, preserving the stdlib convention.
//
// Example: ["github", "--command", "https://x", "--timeout", "60"]
// becomes  ["--command", "https://x", "--timeout", "60", "github"]
//
// Flags defined as bool do not consume the following arg. Everything
// else (string, int, Func, Var) is assumed to.
func reorderFlagsBeforePositional(args []string, fs *flag.FlagSet) []string {
	var flagArgs, positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			// Terminator: everything after is positional, flag parsing
			// should still see "--" to stop.
			flagArgs = append(flagArgs, a)
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			i++
			continue
		}
		flagArgs = append(flagArgs, a)
		// --flag=value form: value is in the same arg.
		if strings.Contains(a, "=") {
			i++
			continue
		}
		// Otherwise the next arg is the value for non-bool flags.
		name := strings.TrimLeft(a, "-")
		if isValueFlag(fs, name) && i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i += 2
			continue
		}
		i++
	}
	return append(flagArgs, positional...)
}

// isValueFlag reports whether the named flag consumes the next argument
// as its value. Bool flags do not; everything else does.
func isValueFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		// Unknown flag. Assume it takes a value so we don't accidentally
		// slurp something that might be a positional arg. fs.Parse will
		// then surface the real error.
		return true
	}
	// The stdlib flag package exposes bool flags via an IsBoolFlag method
	// on the Value. Non-bool flags don't implement this.
	if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
		return false
	}
	return true
}
