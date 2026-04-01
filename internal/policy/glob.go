package policy

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Glob struct {
	pattern string
	re      *regexp.Regexp
}

func CompileGlob(pattern string) (*Glob, error) {
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// ** matches across dots (any characters)
				re.WriteString(".*")
				i++
			} else if len(pattern) == 1 {
				// Standalone * matches everything
				re.WriteString(".*")
			} else {
				// Single * matches within one segment (no dots)
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

	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return nil, fmt.Errorf("compile glob %q -> regex %q: %w",
			pattern, re.String(), err)
	}
	return &Glob{pattern: pattern, re: compiled}, nil
}

func (g *Glob) Match(s string) bool {
	return g.re.MatchString(s)
}

func (g *Glob) String() string {
	return g.pattern
}
