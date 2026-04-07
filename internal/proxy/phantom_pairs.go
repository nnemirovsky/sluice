package proxy

import (
	"log"

	"github.com/nemirovsky/sluice/internal/vault"
)

// maxProxyBody limits the request/response body size that MITM proxies
// (HTTPS and QUIC) read for phantom token replacement. 16 MiB is
// sufficient for typical API traffic while preventing memory exhaustion
// from concurrent large requests.
const maxProxyBody = 16 << 20

// buildOAuthPhantomPairs parses an OAuth credential and returns phantom
// pairs for the access and (optionally) refresh tokens. The caller's
// raw secret is released before returning. On parse failure the secret
// is still released and an error is returned.
func buildOAuthPhantomPairs(name string, secret vault.SecureBytes, logPrefix string) ([]phantomPair, error) {
	cred, err := vault.ParseOAuth(secret.Bytes())
	secret.Release()
	if err != nil {
		log.Printf("[%s] parse oauth credential %q failed: %v", logPrefix, name, err)
		return nil, err
	}
	accessSecret := vault.NewSecureBytes(cred.AccessToken)
	pairs := []phantomPair{{
		phantom: []byte(oauthPhantomAccess(name)),
		secret:  accessSecret,
	}}
	if cred.RefreshToken != "" {
		refreshSecret := vault.NewSecureBytes(cred.RefreshToken)
		pairs = append(pairs, phantomPair{
			phantom: []byte(oauthPhantomRefresh(name)),
			secret:  refreshSecret,
		})
	}
	return pairs, nil
}
