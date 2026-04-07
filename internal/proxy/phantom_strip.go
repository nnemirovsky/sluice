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
		phantoms = append(phantoms,
			[]byte(oauthPhantomAccess(name)),
			[]byte(oauthPhantomRefresh(name)),
			[]byte(PhantomToken(name)),
		)
	}
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
	// don't support List() (e.g. env provider).
	if bytes.Contains(data, phantomPrefix) {
		data = phantomStripRe.ReplaceAll(data, nil)
	}
	return data
}
