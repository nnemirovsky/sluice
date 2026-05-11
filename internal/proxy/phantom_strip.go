package proxy

import (
	"bytes"
	"sort"

	"github.com/nemirovsky/sluice/internal/vault"
)

// stripUnboundPhantomsFromProvider removes phantom tokens from data using
// exact matching via provider.List() first, then falls back to regex for any
// remaining tokens from providers that don't support listing. OAuth phantom
// variants (.access and .refresh suffixes) are stripped before the base token
// to prevent partial matches.
func stripUnboundPhantomsFromProvider(data []byte, provider vault.Provider) []byte {
	names, _ := provider.List()
	// Build phantom token list: for each credential, include the base phantom
	// and OAuth variants (.access, .refresh). OAuth variants are longer and
	// must be stripped before the base token to prevent partial matches.
	var phantoms [][]byte
	for _, name := range names {
		// For OAuth credentials, load real tokens to generate the correct
		// re-signed JWT phantoms. Fall back to deterministic phantoms if
		// vault read fails.
		secret, getErr := provider.Get(name)
		if getErr == nil {
			if vault.IsOAuth(secret.Bytes()) {
				cred, parseErr := vault.ParseOAuth(secret.Bytes())
				secret.Release()
				if parseErr == nil {
					phantoms = append(
						phantoms,
						[]byte(oauthPhantomAccess(name, cred.AccessToken)),
						[]byte(oauthPhantomRefresh(name, cred.RefreshToken)),
						[]byte(PhantomToken(name)),
					)
					continue
				}
			} else {
				secret.Release()
			}
		}
		phantoms = append(
			phantoms,
			[]byte(oauthPhantomAccess(name)),
			[]byte(oauthPhantomRefresh(name)),
			[]byte(PhantomToken(name)),
		)
	}
	// Mirror every phantom with its URL-encoded variants so phantoms carried
	// in form-urlencoded bodies or URL components are stripped as cleanly as
	// the literal form. Two variants are added: the canonical uppercase form
	// emitted by Go's url.QueryEscape, and a lowercase-hex form that other
	// clients may produce (RFC 3986 §2.1 makes percent-encoded hex case-
	// insensitive). Variants are only added when they differ from forms we
	// already cover, so the literal scan path is not duplicated.
	encodedPhantoms := make([][]byte, 0, len(phantoms)*2)
	for _, p := range phantoms {
		encoded := encodePhantomForPair(p)
		if encoded == nil {
			continue
		}
		encodedPhantoms = append(encodedPhantoms, encoded)
		if lower := encodePhantomLowerForPair(encoded); lower != nil {
			encodedPhantoms = append(encodedPhantoms, lower)
		}
	}
	phantoms = append(phantoms, encodedPhantoms...)
	// Sort by token length descending so longer phantom tokens are stripped
	// before shorter prefixes that could corrupt them via substring match.
	sort.Slice(phantoms, func(i, j int) bool {
		return len(phantoms[i]) > len(phantoms[j])
	})
	for _, p := range phantoms {
		if bytes.Contains(data, p) {
			data = bytes.ReplaceAll(data, p, nil)
		}
	}
	// Last-resort regex strip for phantom tokens from providers that
	// don't support List() (e.g. env provider). The regex handles literal
	// (SLUICE_PHANTOM:...) and URL-encoded (SLUICE_PHANTOM%3A.../%3a...)
	// forms so unbound phantoms in form-urlencoded bodies are caught too.
	if bytes.Contains(data, phantomPrefix) ||
		bytes.Contains(data, urlEncodedPhantomPrefix) ||
		bytes.Contains(data, urlEncodedPhantomPrefixLower) {
		data = phantomStripRe.ReplaceAll(data, nil)
	}
	return data
}
