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

// encodePhantomLowerForPair returns the lowercase-hex variant of the
// uppercase-encoded phantom, or nil when the input is nil or the
// lowercased form is identical (which happens when the encoding has no
// hex digits A-F). RFC 3986 §2.1 makes percent-encoded hex case-
// insensitive, so a phantom that arrives encoded as %3a must still match
// the precomputed phantom whose canonical form is %3A.
func encodePhantomLowerForPair(encoded []byte) []byte {
	if len(encoded) == 0 {
		return nil
	}
	lower := make([]byte, len(encoded))
	i := 0
	for i < len(encoded) {
		// Lowercase only the two hex digits after a %, leave everything
		// else untouched so the credential name (which can contain
		// upper-case letters by policy) isn't corrupted.
		if encoded[i] == '%' && i+2 < len(encoded) {
			lower[i] = '%'
			lower[i+1] = asciiLowerHex(encoded[i+1])
			lower[i+2] = asciiLowerHex(encoded[i+2])
			i += 3
			continue
		}
		lower[i] = encoded[i]
		i++
	}
	if bytes.Equal(lower, encoded) {
		return nil
	}
	return lower
}

func asciiLowerHex(b byte) byte {
	if b >= 'A' && b <= 'F' {
		return b + ('a' - 'A')
	}
	return b
}

// queryEscapeBytes is a byte-in, byte-out form-component URL encoder that
// mirrors net/url.QueryEscape's output rules without ever materializing
// the input as a Go string. url.QueryEscape's signature is
// `func(string) string`, which forces callers to wrap a credential's
// SecureBytes via `url.QueryEscape(string(secret.Bytes()))` and leaves
// two immutable string copies of the secret on the heap that
// SecureBytes.Release() cannot zero. Operating on []byte throughout keeps
// the secret only in slices the caller can clear.
//
// The unreserved character set follows RFC 3986 §2.3 plus Go's
// net/url-compatible additions: spaces become '+' (form encoding), and
// everything outside the unreserved set is percent-encoded with
// uppercase hex (the canonical form Go and most clients emit).
func queryEscapeBytes(src []byte) []byte {
	dst := make([]byte, 0, len(src))
	for _, c := range src {
		switch {
		case c == ' ':
			dst = append(dst, '+')
		case shouldNotEscapeQueryComponent(c):
			dst = append(dst, c)
		default:
			dst = append(dst, '%', hexUpper(c>>4), hexUpper(c&0x0F))
		}
	}
	return dst
}

// pathEscapeBytes is the byte-level analogue of net/url.PathEscape. It
// preserves URL-path semantics: spaces become %20 (not '+'), and a
// slightly larger unreserved set is honored (sub-delims that are legal
// in path segments are emitted verbatim).
func pathEscapeBytes(src []byte) []byte {
	dst := make([]byte, 0, len(src))
	for _, c := range src {
		if shouldNotEscapePathSegment(c) {
			dst = append(dst, c)
			continue
		}
		dst = append(dst, '%', hexUpper(c>>4), hexUpper(c&0x0F))
	}
	return dst
}

// shouldNotEscapeQueryComponent reports whether a byte is safe to emit
// literally inside an application/x-www-form-urlencoded value. Matches
// the predicate net/url applies for encodeQueryComponent: ALPHA / DIGIT
// / '-' / '_' / '.' / '~'.
func shouldNotEscapeQueryComponent(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z',
		c >= 'a' && c <= 'z',
		c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '~':
		return true
	}
	return false
}

// shouldNotEscapePathSegment reports whether a byte is safe to emit
// literally inside a URL path segment. Matches the predicate net/url
// applies for encodePathSegment: unreserved + sub-delims minus the
// segment separators '/' and '?'. Specifically: ALPHA / DIGIT /
// '-' '_' '.' '~' '$' '&' '+' ',' ';' '=' ':' '@'.
func shouldNotEscapePathSegment(c byte) bool {
	if shouldNotEscapeQueryComponent(c) {
		return true
	}
	switch c {
	case '$', '&', '+', ',', ';', '=', ':', '@':
		return true
	}
	return false
}

// hexUpper returns the uppercase hex digit for a nibble in 0..15.
func hexUpper(nibble byte) byte {
	if nibble < 10 {
		return '0' + nibble
	}
	return 'A' + (nibble - 10)
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
	accessEncoded := encodePhantomForPair(accessPhantom)
	pairs := []phantomPair{{
		phantom:             accessPhantom,
		encodedPhantom:      accessEncoded,
		encodedPhantomLower: encodePhantomLowerForPair(accessEncoded),
		secret:              accessSecret,
	}}
	if cred.RefreshToken != "" {
		refreshSecret := vault.NewSecureBytes(cred.RefreshToken)
		refreshPhantom := []byte(oauthPhantomRefresh(name, cred.RefreshToken))
		refreshEncoded := encodePhantomForPair(refreshPhantom)
		pairs = append(pairs, phantomPair{
			phantom:             refreshPhantom,
			encodedPhantom:      refreshEncoded,
			encodedPhantomLower: encodePhantomLowerForPair(refreshEncoded),
			secret:              refreshSecret,
		})
	}
	return pairs, nil
}
