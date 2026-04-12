package proxy

import "regexp"

// phantomPrefix is the byte prefix for all phantom tokens, used for quick
// detection before applying the more expensive regex strip.
var phantomPrefix = []byte("SLUICE_PHANTOM:")

// phantomStripRe is a last-resort regex for stripping phantom tokens when
// provider.List() cannot enumerate all credential names. It matches word
// characters, dots, and hyphens.
// The primary strip path uses exact matching via provider.List().
var phantomStripRe = regexp.MustCompile(`SLUICE_PHANTOM:[\w.\-]+`)

// PhantomToken returns the placeholder token for a credential name.
// Agents use this token in requests. The MITM proxy replaces it with
// the real credential value at injection time.
func PhantomToken(credentialName string) string {
	return "SLUICE_PHANTOM:" + credentialName
}
