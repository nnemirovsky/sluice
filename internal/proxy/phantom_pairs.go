package proxy

import (
	"bytes"
	"log"
	"net/url"

	"github.com/nemirovsky/sluice/internal/vault"
)

// encodePhantomForPair returns the URL query-escaped form of a phantom
// token, or nil when QueryEscape would leave the bytes unchanged. The
// "nil when unchanged" convention lets the hot-path swap skip a redundant
// bytes.Contains scan for the literal form a second time.
func encodePhantomForPair(phantom []byte) []byte {
	encoded := []byte(url.QueryEscape(string(phantom)))
	if bytes.Equal(encoded, phantom) {
		return nil
	}
	return encoded
}

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
	accessPhantom := []byte(oauthPhantomAccess(name, cred.AccessToken))
	pairs := []phantomPair{{
		phantom:        accessPhantom,
		encodedPhantom: encodePhantomForPair(accessPhantom),
		secret:         accessSecret,
	}}
	if cred.RefreshToken != "" {
		refreshSecret := vault.NewSecureBytes(cred.RefreshToken)
		refreshPhantom := []byte(oauthPhantomRefresh(name, cred.RefreshToken))
		pairs = append(pairs, phantomPair{
			phantom:        refreshPhantom,
			encodedPhantom: encodePhantomForPair(refreshPhantom),
			secret:         refreshSecret,
		})
	}
	return pairs, nil
}
