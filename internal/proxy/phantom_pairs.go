package proxy

import (
	"log"

	"github.com/nemirovsky/sluice/internal/vault"
)

// encodePhantomForPair returns the URL query-escaped form of a phantom
// token, or nil when QueryEscape would leave the bytes unchanged. The
// "nil when unchanged" convention lets the hot-path swap skip a redundant
// bytes.Contains scan for the literal form a second time. A pre-scan
// returns nil before any allocation when no byte in phantom would be
// escaped — also avoids the byte->string copy that url.QueryEscape would
// otherwise produce for the no-op case.
func encodePhantomForPair(phantom []byte) []byte {
	if !phantomNeedsQueryEscape(phantom) {
		return nil
	}
	return queryEscapeBytes(phantom)
}

// phantomNeedsQueryEscape reports whether any byte in phantom would be
// rewritten by queryEscapeBytes. Returns true on a space or any byte
// outside the unreserved-for-query-component set.
func phantomNeedsQueryEscape(phantom []byte) bool {
	for _, c := range phantom {
		if c == ' ' || !shouldNotEscapeQueryComponent(c) {
			return true
		}
	}
	return false
}

// encodePhantomLowerForPair returns the lowercase-hex variant of the
// uppercase-encoded phantom, or nil when the input is nil or the
// lowercased form is identical (which happens when the encoding has no
// hex digits A-F). RFC 3986 §2.1 makes percent-encoded hex case-
// insensitive, so a phantom that arrives encoded as %3a must still match
// the precomputed phantom whose canonical form is %3A.
//
// A pre-scan returns nil before any allocation when no percent-escape
// sequence contains an uppercase A-F hex digit. This fast path only
// fires for phantoms whose escaped form happens to use 0-9 hex digits
// exclusively. A phantom containing %3A (the encoded colon, which every
// SLUICE_PHANTOM:<name> phantom has after url-encoding) still differs
// between %3A and %3a, so the allocation still occurs in the common
// case — the fast path is for shapes like %20%21%30 where every escape
// is already lowercase-equivalent.
func encodePhantomLowerForPair(encoded []byte) []byte {
	if len(encoded) == 0 {
		return nil
	}
	hasUpperHex := false
	for i := 0; i < len(encoded); i++ {
		if encoded[i] != '%' || i+2 >= len(encoded) {
			continue
		}
		if isASCIIUpperHex(encoded[i+1]) || isASCIIUpperHex(encoded[i+2]) {
			hasUpperHex = true
			break
		}
	}
	if !hasUpperHex {
		return nil
	}
	lower := make([]byte, len(encoded))
	i := 0
	for i < len(encoded) {
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
	return lower
}

func isASCIIUpperHex(b byte) bool {
	return b >= 'A' && b <= 'F'
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
//
// onRefreshInject, when supplied (variadic; at most the first element is
// used), is called with the credential's real refresh token before the
// swap injects it into the outbound refresh-grant request body. This is
// the PLAIN-credential analogue of buildPooledOAuthPhantomPairs'
// onRefreshInject: it lets the caller record a realRefreshToken -> name
// attribution tag so a plain OAuth refresh whose token URL is shared with
// a pool can be told apart from a genuine pooled refresh on the response
// side (Finding 1). Plain callers that have no attribution context
// (ws.go, quic.go) simply omit it.
func buildOAuthPhantomPairs(name string, secret vault.SecureBytes, logPrefix string, onRefreshInject ...func(realRefresh string)) ([]phantomPair, error) {
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
		// Record the plain R1 join: this exact real refresh token is
		// about to be injected for the plain credential `name`. The
		// token-endpoint response recovers this value to attribute the
		// rotated tokens back to `name` rather than fail-closing as if
		// it were an unrecoverable pooled refresh.
		if len(onRefreshInject) > 0 && onRefreshInject[0] != nil {
			onRefreshInject[0](cred.RefreshToken)
		}
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

// buildPooledOAuthPhantomPairs builds phantom pairs for a pooled OAuth
// credential. The phantom strings are keyed on the POOL name so they are
// byte-identical across member switches (Risk R3): the access phantom is
// the pool-stable synthetic JWT, the refresh phantom is the deterministic
// static `SLUICE_PHANTOM:<pool>.refresh` string. The injected secrets are
// the ACTIVE MEMBER's real tokens.
//
// onRefreshInject, when non-nil, is called with the member's real refresh
// token so the caller can record the realRefreshToken -> member tag (the
// Risk R1 join key) before the swap injects that token into the outbound
// refresh-grant request body. The caller's raw secret is released before
// returning. On parse failure the secret is released and an error returned.
func buildPooledOAuthPhantomPairs(poolName, member string, secret vault.SecureBytes, logPrefix string, onRefreshInject func(realRefresh string)) ([]phantomPair, error) {
	cred, err := vault.ParseOAuth(secret.Bytes())
	secret.Release()
	if err != nil {
		log.Printf("[%s] parse pooled oauth member %q (pool %q) failed: %v", logPrefix, member, poolName, err)
		return nil, err
	}
	accessSecret := vault.NewSecureBytes(cred.AccessToken)
	accessPhantom := []byte(poolStablePhantomAccess(poolName))
	accessEncoded := encodePhantomForPair(accessPhantom)
	pairs := []phantomPair{{
		phantom:             accessPhantom,
		encodedPhantom:      accessEncoded,
		encodedPhantomLower: encodePhantomLowerForPair(accessEncoded),
		secret:              accessSecret,
		pooledMember:        member,
	}}
	if cred.RefreshToken != "" {
		// Record the precise R1 join: this exact real refresh token is
		// about to be injected into the outbound refresh-grant request
		// for `member`. The token-endpoint response is attributed back
		// to `member` by recovering this value from the request body.
		if onRefreshInject != nil {
			onRefreshInject(cred.RefreshToken)
		}
		refreshSecret := vault.NewSecureBytes(cred.RefreshToken)
		// Pool-stable static refresh phantom (not resignJWT, which would
		// be per-real-token and change on every member switch). Refresh
		// tokens travel in request bodies, not parsed client-side, so the
		// static form is sufficient and inherently pool-stable.
		refreshPhantom := []byte("SLUICE_PHANTOM:" + poolName + ".refresh")
		refreshEncoded := encodePhantomForPair(refreshPhantom)
		pairs = append(pairs, phantomPair{
			phantom:             refreshPhantom,
			encodedPhantom:      refreshEncoded,
			encodedPhantomLower: encodePhantomLowerForPair(refreshEncoded),
			secret:              refreshSecret,
			pooledMember:        member,
		})
	}
	return pairs, nil
}
