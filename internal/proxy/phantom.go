package proxy

import "regexp"

// phantomPrefix is the byte prefix for all phantom tokens in their literal
// form, used for quick detection before applying the more expensive regex
// strip. Literal form appears in JSON bodies, raw header values, and
// anywhere the colon survives unencoded.
var phantomPrefix = []byte("SLUICE_PHANTOM:")

// urlEncodedPhantomPrefix is the byte prefix for phantom tokens after URL
// percent-encoding (the colon becomes %3A). Appears in
// application/x-www-form-urlencoded request bodies (e.g. OAuth refresh
// POSTs) and in URL query strings. Without scanning for this form, a
// phantom embedded in form-urlencoded data would pass through unswapped
// and the upstream would receive the literal `SLUICE_PHANTOM%3A...`
// string. The two prefixes are kept side by side rather than computed at
// runtime so the byte scan stays a single allocation-free contains check.
//
// Percent-encoding hex digits are case-insensitive per RFC 3986 §2.1, so
// callers may emit either %3A or %3a. Go's url.QueryEscape always produces
// uppercase, but third-party clients can produce lowercase. The lowercase
// variant is stored alongside the uppercase one so the prefix scan catches
// both forms.
var (
	urlEncodedPhantomPrefix      = []byte("SLUICE_PHANTOM%3A")
	urlEncodedPhantomPrefixLower = []byte("SLUICE_PHANTOM%3a")
)

// phantomStripRe is a last-resort regex for stripping phantom tokens when
// provider.List() cannot enumerate all credential names. It matches both
// literal (SLUICE_PHANTOM:...) and URL-encoded (SLUICE_PHANTOM%3A...) forms
// so unbound phantoms cannot leak via either encoding. The character class
// matches word characters, dots, and hyphens — the same set used by the
// credential-name and OAuth-suffix grammar.
// The primary strip path uses exact matching via provider.List().
var phantomStripRe = regexp.MustCompile(`SLUICE_PHANTOM(?::|%3[Aa])[\w.\-]+`)

// PhantomToken returns the placeholder token for a credential name.
// Agents use this token in requests. The MITM proxy replaces it with
// the real credential value at injection time.
func PhantomToken(credentialName string) string {
	return "SLUICE_PHANTOM:" + credentialName
}
