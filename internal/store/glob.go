package store

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// validateDestinationGlob validates that a destination string is a syntactically
// valid glob pattern. It mirrors the compilation logic in
// internal/policy/glob.go (CompileGlob) so the store can reject invalid
// patterns before committing them, instead of letting the engine recompile
// fail later. Duplicating the logic here avoids a circular import with the
// policy package, which already imports the store.
//
// Keep this function in sync with internal/policy/glob.go. The error message
// uses the same wrapping format so users see consistent diagnostics across
// the CLI, REST API, and store layer.
func validateDestinationGlob(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("destination cannot be empty")
	}
	var re strings.Builder
	re.WriteString("(?i)^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '.' {
					re.WriteString(`(.*\.)?`)
					i += 2
				} else {
					re.WriteString(".*")
					i++
				}
			} else if len(pattern) == 1 {
				re.WriteString(".*")
			} else {
				re.WriteString("[^.]*")
			}
		case '?':
			re.WriteString("[^.]")
		case '.':
			re.WriteString(`\.`)
		default:
			r, size := utf8.DecodeRuneInString(pattern[i:])
			re.WriteString(regexp.QuoteMeta(string(r)))
			i += size - 1
		}
	}
	re.WriteString("$")
	if _, err := regexp.Compile(re.String()); err != nil {
		return fmt.Errorf("invalid destination pattern %q: %w", pattern, err)
	}
	return nil
}
