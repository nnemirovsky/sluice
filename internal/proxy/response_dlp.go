package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
)

// errDecompressedTooLarge signals that a decoder produced more than
// maxProxyBody bytes of plaintext. Callers (the addon's body-scan path)
// log this distinctly from generic decode errors so a compression-bomb
// attempt is visible in the operator logs as a separate failure mode.
// The post-decompression size guard in scanResponseForDLP catches the
// same case via a length check, but capping the decoder output here
// stops the OOM risk before io.ReadAll materializes the full inflated
// body in memory.
var errDecompressedTooLarge = errors.New("decompressed body exceeds maxProxyBody")

// dlpNoMatchLogEvery sets the rate-limit cadence for the no-match debug log.
// Every Nth scan emits one line so operators can confirm DLP is running
// without flooding logs on clean traffic. 500 was chosen as roughly one
// heartbeat every ~30s at moderate load (~15 req/s on a typical agent
// session), which is frequent enough to confirm the scanner is alive but
// infrequent enough that clean production traffic will not dominate the
// log stream.
const dlpNoMatchLogEvery = 500

// mitmRedactRule is a compiled content redact rule for MITM HTTP responses.
// It shares the same shape as wsRedactRule and quicRedactRule but is scoped
// to the HTTP response DLP path in SluiceAddon.Response. Callers that want
// to construct rules from policy data pass in policy.InspectRedactRule and
// let SetRedactRules compile them.
type mitmRedactRule struct {
	re          *regexp.Regexp
	replacement string
	name        string
}

// SetRedactRules compiles the given InspectRedactRule patterns and atomically
// swaps them into the addon so response DLP scanning uses the new rules on
// the next response. Safe to call concurrently with Response handling. An
// empty slice disables response DLP scanning.
func (a *SluiceAddon) SetRedactRules(rules []policy.InspectRedactRule) error {
	compiled := make([]mitmRedactRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("compile mitm redact pattern %q: %w", r.Name, err)
		}
		compiled = append(compiled, mitmRedactRule{
			re:          re,
			replacement: r.Replacement,
			name:        r.Name,
		})
	}
	a.redactRules.Store(&compiled)
	return nil
}

// loadRedactRules returns the current compiled redact rules, or nil when no
// rules are configured.
func (a *SluiceAddon) loadRedactRules() []mitmRedactRule {
	p := a.redactRules.Load()
	if p == nil {
		return nil
	}
	return *p
}

// binaryContentPrefixes lists content-type prefixes that should skip response
// DLP scanning. Redacting inside binary data would almost always corrupt the
// payload and these formats are not plausible hiding places for credential
// strings.
var binaryContentPrefixes = []string{
	"image/",
	"video/",
	"audio/",
	"application/octet-stream",
	"application/pdf",
	"application/zip",
	"application/x-tar",
	"application/x-gzip",
	"application/x-7z-compressed",
	"font/",
}

// isBinaryContentType returns true when the given Content-Type header value
// matches one of the binary prefixes. Matching is case-insensitive and
// ignores parameters after the media type.
func isBinaryContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if semi := strings.Index(ct, ";"); semi >= 0 {
		ct = ct[:semi]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	for _, prefix := range binaryContentPrefixes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// scanHeadersForDLP iterates the response headers once and applies each
// rule. Header scanning runs independently of body scanning so that a
// decompression failure on the body cannot suppress redaction of a
// header-borne credential leak. Returns per-rule match counts so the
// caller can combine them with body-side counts into a single audit
// event. A nil return means either no rules configured, no response
// header, or no header matched.
func scanHeadersForDLP(f *mitmproxy.Flow, rules []mitmRedactRule) map[string]int {
	if f.Response == nil || f.Response.Header == nil || len(rules) == 0 {
		return nil
	}
	header := f.Response.Header
	counts := make(map[string]int)
	for key, vals := range header {
		if shouldSkipHeaderForDLP(key) {
			continue
		}
		for i, v := range vals {
			original := v
			for _, rule := range rules {
				if matches := rule.re.FindAllStringIndex(v, -1); len(matches) > 0 {
					v = rule.re.ReplaceAllString(v, rule.replacement)
					counts[rule.name] += len(matches)
				}
			}
			if v != original {
				header[key][i] = v
			}
		}
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

// applyBodyDLP scans the response body and merges the resulting per-rule
// match counts with any header-side counts the caller passes in. Header
// scanning runs separately in scanHeadersForDLP so a decompression
// failure cannot suppress header redaction. Returns the sorted rule
// names that fired across header and body passes, and the combined
// per-rule counts. Returns (nil, nil) when neither pass matched.
//
// When rules is empty, only the header counts are returned. This path
// covers the oversize/binary/decode-failure cases where scanResponseForDLP
// has decided the body is not eligible for scanning but header matches
// still need to reach the audit event.
func applyBodyDLP(f *mitmproxy.Flow, rules []mitmRedactRule, headerCounts map[string]int) ([]string, map[string]int) {
	combined := make(map[string]int, len(headerCounts))
	for k, v := range headerCounts {
		combined[k] = v
	}

	// Body scan: apply each rule to the raw body bytes when body
	// scanning is enabled. Empty rules means the caller wants to skip
	// the body pass (oversize/binary/decode-failure path). We use
	// FindAllIndex on the raw []byte to avoid string-copy on no-match
	// and also to obtain the match count for audit reporting.
	if len(rules) > 0 && len(f.Response.Body) > 0 {
		body := f.Response.Body
		bodyModified := false
		for _, rule := range rules {
			if matches := rule.re.FindAllIndex(body, -1); len(matches) > 0 {
				body = rule.re.ReplaceAll(body, []byte(rule.replacement))
				combined[rule.name] += len(matches)
				bodyModified = true
			}
		}
		if bodyModified {
			f.Response.Body = body
			if f.Response.Header != nil {
				f.Response.Header.Set("Content-Length", strconv.Itoa(len(f.Response.Body)))
				f.Response.Header.Del("Transfer-Encoding")
			}
		}
	}

	if len(combined) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(combined))
	for n := range combined {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, combined
}

// contentEncodingTokens returns the lower-cased, trimmed list of
// Content-Encoding tokens in application order. Content-Encoding can be
// multi-valued either as a single "gzip, br" header or as repeated header
// lines. HTTP stacks have been known to use both. This normalizes them.
func contentEncodingTokens(h http.Header) []string {
	values := h.Values("Content-Encoding")
	out := make([]string, 0, len(values))
	for _, v := range values {
		for _, token := range strings.Split(v, ",") {
			token = strings.TrimSpace(strings.ToLower(token))
			if token == "" {
				continue
			}
			out = append(out, token)
		}
	}
	return out
}

// hasAnyContentEncoding returns true if Content-Encoding has any value
// (including identity). Used to decide whether to invoke the decode
// wrapper, which also normalizes identity-only headers.
func hasAnyContentEncoding(h http.Header) bool {
	return len(contentEncodingTokens(h)) > 0
}

// maxStackedEncodingDepth caps how many decode passes safeReplaceToDecodedBody
// will run on a stacked Content-Encoding. RFC 9110 permits stacked encodings
// in principle but legitimate upstreams almost never go beyond 2 levels (a
// JSON body emitted as gzip, then re-wrapped by an outer brotli layer at the
// CDN is the realistic upper bound). A malicious upstream could request
// arbitrarily deep stacking to consume CPU, so we cap at 2 and skip with a
// warning beyond that. Skipping is fail-open: the response still relays, but
// the body is not scanned by DLP.
const maxStackedEncodingDepth = 2

// safeReplaceToDecodedBody decompresses the response body in place.
//
// go-mitmproxy's `ReplaceToDecodedBody` (and its underlying `decode`) reads
// the entire decompressed body into memory via `io.Copy` with NO size cap,
// which makes a single small gzip/br/deflate/zstd response a credible memory
// exhaustion vector. We deliberately bypass that path and use our own
// bounded iterative decoder for ALL encodings (1 token or stacked) so there
// is one uniform decode path that respects maxProxyBody.
//
// The function runs in three clear steps:
//
//  1. Tokenize Content-Encoding and drop identity (no-op per RFC 9110).
//  2. Reject stacks deeper than maxStackedEncodingDepth so adversarial deep
//     stacks cannot consume CPU. Unknown encoding tokens (`compress`,
//     `x-gzip`, anything we have no decoder for) also fail with an error so
//     the caller's fail-open path skips body scanning rather than scanning a
//     still-encoded body as plaintext.
//  3. Iteratively decode in reverse order via decodeStacked, which reads
//     each layer through io.LimitReader capped at maxProxyBody+1 bytes. RFC
//     9110 Section 8.4.1 says encodings are listed in application order, so
//     decoding peels them off right-to-left.
//
// On success, the body is replaced with the fully decoded bytes,
// Content-Encoding is removed, Content-Length is rewritten to match the
// decoded length, and Transfer-Encoding is cleared. Without this, an
// otherwise-clean response (no DLP redaction) would relay a plaintext body
// with framing headers that still describe the COMPRESSED body, causing
// length mismatches and potential framing corruption downstream. On failure
// the original header values are restored so the caller sees a consistent
// pre-state.
//
// A deferred recover guards against panics from the third-party decoders.
func safeReplaceToDecodedBody(f *mitmproxy.Flow) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in safeReplaceToDecodedBody: %v", r)
		}
	}()

	header := f.Response.Header
	if header == nil {
		return nil
	}

	// Step 1: tokenize and drop identity. Identity is a no-op per
	// RFC 9110 but some upstreams still emit it explicitly.
	compact := nonIdentityEncodingTokens(header)
	if len(compact) == 0 {
		// Only identity values: nothing to decode but normalize the
		// header so downstream does not see "identity" lingering.
		header.Del("Content-Encoding")
		return nil
	}

	// Step 2: cap depth at maxStackedEncodingDepth so adversarial deep
	// stacks cannot consume CPU. Single-token encodings naturally pass
	// this gate.
	if len(compact) > maxStackedEncodingDepth {
		return fmt.Errorf("stacked content-encoding %v exceeds max depth %d", compact, maxStackedEncodingDepth)
	}

	// Save the original header values so we can restore them if decode fails.
	originalCE := append([]string(nil), header.Values("Content-Encoding")...)

	// Step 3: iteratively decode through bounded readers. Single-token and
	// stacked paths share this code so the maxProxyBody cap applies
	// uniformly to every layer.
	decoded, decErr := decodeStacked(f.Response.Body, compact)
	if decErr != nil {
		// Restore on failure so the caller sees the original Content-Encoding.
		header.Del("Content-Encoding")
		for _, v := range originalCE {
			header.Add("Content-Encoding", v)
		}
		return decErr
	}

	// Replace body and rewrite framing headers. Content-Length must match
	// the decoded length and Transfer-Encoding must be cleared so any
	// follow-on relay path (when no DLP redaction touches the body) does
	// not propagate stale framing that describes the COMPRESSED bytes.
	f.Response.Body = decoded
	header.Del("Content-Encoding")
	header.Set("Content-Length", strconv.Itoa(len(decoded)))
	header.Del("Transfer-Encoding")
	return nil
}

// decodeStacked decodes a body that was encoded by applying `encodings` in
// order. RFC 9110 Section 8.4.1 says Content-Encoding lists encodings in the
// order they were applied, so decoding peels them off right-to-left (the
// last applied is the first removed).
//
// Each decoder caps the DECOMPRESSED output at maxProxyBody+1 bytes via
// readDecodedBounded so a compression bomb cannot OOM the proxy before
// io.ReadAll returns. errDecompressedTooLarge is wrapped via fmt.Errorf
// with %w so callers can use errors.Is to detect it and log distinctly
// from generic decode failures.
//
// Returns an error when any encoding token has no registered decoder (e.g.
// "compress", "x-gzip"). The caller treats this as a decode failure and
// skips body scanning fail-open.
func decodeStacked(body []byte, encodings []string) ([]byte, error) {
	current := body
	// Walk right-to-left: encodings[len-1] was applied last, so it is
	// removed first.
	for i := len(encodings) - 1; i >= 0; i-- {
		next, err := decodeOne(current, encodings[i])
		if err != nil {
			return nil, fmt.Errorf("decode stacked encoding %q at level %d: %w", encodings[i], i, err)
		}
		current = next
	}
	return current, nil
}

// decodeOne applies a single decoder by name. Returns an error for unknown
// encoding tokens so the caller can fail-open and skip body scanning rather
// than misinterpret still-encoded bytes as plaintext.
//
// The io.LimitReader wraps the DECOMPRESSED output, not the compressed
// input, so a small compressed body (e.g. a few KiB of all-zeros gzip)
// cannot inflate past maxProxyBody and OOM the proxy. Capping the
// compressed input would still let the decoder allocate gigabytes of
// plaintext before io.ReadAll returns, which is the actual memory risk.
// Callers that hit the cap receive errDecompressedTooLarge so the addon
// can log the compression-bomb case distinctly.
//
// `Content-Encoding: deflate` is per RFC 9110 Section 8.4.1 the
// zlib-wrapped DEFLATE format (RFC 1950: 2-byte zlib header + raw RFC 1951
// DEFLATE stream + Adler-32 trailer), not raw RFC 1951. The zlib decoder
// handles the standards-compliant case. Some servers historically emit
// raw DEFLATE under `Content-Encoding: deflate` so we fall back to
// flate.NewReader on a zlib header error to preserve compatibility with
// that real-world misuse.
func decodeOne(body []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer zr.Close()
		return readDecodedBounded(zr)
	case "br":
		return readDecodedBounded(brotli.NewReader(bytes.NewReader(body)))
	case "deflate":
		// Standards-compliant deflate is zlib-wrapped per RFC 9110
		// Section 8.4.1. Try zlib first; fall back to raw DEFLATE
		// only on the zlib invalid-header sentinel so an unrelated
		// zlib decode failure is not silently masked.
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			if errors.Is(err, zlib.ErrHeader) {
				fr := flate.NewReader(bytes.NewReader(body))
				defer fr.Close()
				return readDecodedBounded(fr)
			}
			return nil, fmt.Errorf("zlib reader: %w", err)
		}
		defer zr.Close()
		return readDecodedBounded(zr)
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("zstd reader: %w", err)
		}
		defer zr.Close()
		return readDecodedBounded(zr)
	default:
		return nil, fmt.Errorf("unsupported encoding %q", encoding)
	}
}

// readDecodedBounded reads from a decompressing reader with a hard cap
// of maxProxyBody+1 bytes on the OUTPUT, returning errDecompressedTooLarge
// when the decoder would exceed the cap. This is the OOM defense for
// compression bombs: capping the compressed input reader is insufficient
// because a small compressed body can inflate to gigabytes before
// io.ReadAll allocates its growing slice.
//
// We read maxProxyBody+1 bytes (one byte over the cap) so we can
// distinguish "exactly at cap" from "exceeded cap" without a separate
// probe read. When the decompressor's Read returns io.EOF before the
// limit, the body is returned as-is.
func readDecodedBounded(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxProxyBody+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxProxyBody {
		return nil, errDecompressedTooLarge
	}
	return buf, nil
}

// nonIdentityEncodingTokens returns the lower-cased Content-Encoding
// tokens with any identity values removed. Identity is a no-op per
// RFC 9110 and is therefore safe to strip before deciding whether we
// need to decode.
func nonIdentityEncodingTokens(h http.Header) []string {
	tokens := contentEncodingTokens(h)
	compact := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if t != "identity" {
			compact = append(compact, t)
		}
	}
	return compact
}

// shouldSkipHeaderForDLP reports whether a header name should be skipped
// by response DLP rewriting. The set covers the standard hop-by-hop
// headers (RFC 7230) plus Content-Length, which is end-to-end but still
// unsafe to mutate because scanHeadersForDLP runs before the body pass
// recomputes framing. Modifying any of these risks breaking the HTTP
// transfer itself, so we leave them untouched regardless of whether a
// redact rule would match.
func shouldSkipHeaderForDLP(name string) bool {
	switch strings.ToLower(name) {
	case "connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"content-length":
		return true
	}
	return false
}

// scanResponseForDLP is the top-level entry point called from Response. It
// enforces body size limits (fail-open on oversize because data already left
// the upstream), skips binary content types for the body scan only (headers
// are always scanned because redaction rules may catch Bearer tokens echoed
// into headers even on binary responses), decompresses compressed bodies
// via the bounded safeReplaceToDecodedBody, applies the redact rules, and
// logs an audit event when any redaction occurred. Header scanning runs
// unconditionally and separately from body scanning so that a decode
// failure or a binary content type cannot hide a header-borne leak.
func (a *SluiceAddon) scanResponseForDLP(f *mitmproxy.Flow) {
	if f.Response == nil {
		return
	}
	rules := a.loadRedactRules()
	if len(rules) == 0 {
		return
	}

	// Scan headers first. Headers are always scanned regardless of
	// content-type (a binary response with a Bearer token echoed into a
	// header still leaks the token), and regardless of whether body
	// decompression later succeeds. scanHeadersForDLP returns per-rule
	// counts so we can thread them into applyBodyDLP for a single
	// combined audit event.
	headerCounts := scanHeadersForDLP(f, rules)

	bodyEligible := true

	// Size guard: fail-open on oversized responses. The data already left
	// the upstream by the time this runs, so blocking it would not
	// prevent leakage. Skipping the scan preserves streaming throughput
	// and avoids memory blowup on large downloads. Note: this checks the
	// ON-THE-WIRE size. A compressed body smaller than maxProxyBody can
	// still inflate past it, so a separate post-decompression check
	// below catches the compression-bomb case.
	if int64(len(f.Response.Body)) > maxProxyBody {
		log.Printf("[ADDON-DLP] response body exceeds %d bytes, skipping body DLP scan", maxProxyBody)
		bodyEligible = false
	}

	// Content-type filter: skip body scanning for binary payloads which
	// would not carry credential patterns and would be corrupted by
	// regex replacements. Headers already scanned above.
	if bodyEligible {
		contentType := ""
		if f.Response.Header != nil {
			contentType = f.Response.Header.Get("Content-Type")
		}
		if isBinaryContentType(contentType) {
			bodyEligible = false
		}
	}

	// Decompression: go-mitmproxy's attacker sets DisableCompression so
	// the body may still be gzip/br/deflate/zstd encoded. Decoding the
	// body in place lets regex patterns match plaintext. The body is
	// re-sent to the agent uncompressed, which is permissible because
	// Content-Encoding is removed from the response header.
	//
	// Content-Encoding may be multi-valued (e.g. "gzip, br") for stacked
	// encodings. http.Header.Get only returns the first value, so we read
	// all values. safeReplaceToDecodedBody strips identity tokens (no-op
	// per RFC 9110), rejects stacks beyond maxStackedEncodingDepth, and
	// runs every layer (single or stacked) through a bounded iterative
	// decoder capped at maxProxyBody+1 bytes per layer. Always called
	// when the response has any Content-Encoding set so that identity-only
	// values are normalized to an empty header (otherwise `Content-Encoding:
	// identity, identity` would linger).
	//
	// Compression-bomb guard: the post-decompression size check below is
	// a secondary bomb defense. The decoder's per-layer io.LimitReader
	// caps each io.ReadAll at maxProxyBody+1 so a single-shot zip-bomb
	// cannot OOM. We additionally reject the decoded body here when the
	// total exceeds maxProxyBody so we do not allocate regex match state
	// on top of an already-large body. We rely on the post-decompression
	// check (rather than an upfront compressed-size cap) because a tight
	// upfront cap rejects ordinary gzip/br/deflate/zstd JSON responses
	// (1-2 MiB compressed expanding well under our 16 MiB cap) before
	// they can be scanned.
	if bodyEligible && f.Response.Header != nil && hasAnyContentEncoding(f.Response.Header) {
		if err := safeReplaceToDecodedBody(f); err != nil {
			if errors.Is(err, errDecompressedTooLarge) {
				log.Printf("[ADDON-DLP] skip body scan: decompressed body exceeds %d bytes for %s (compression-bomb guard)", maxProxyBody, requestHostForFlow(f))
			} else {
				log.Printf("[ADDON-DLP] skip body scan: decode error for %s: %v", requestHostForFlow(f), err)
			}
			bodyEligible = false
		} else if int64(len(f.Response.Body)) > maxProxyBody {
			// Post-decompression size check: the inflated body may
			// exceed maxProxyBody even if the compressed wire size was
			// modest (compression-bomb pattern, or a legitimately huge
			// payload that compressed extremely well). The decoder's
			// per-layer io.LimitReader caps each io.ReadAll at
			// maxProxyBody+1 bytes (so we will not OOM during decode),
			// but we still skip scanning a body that exceeds the cap so
			// we do not also allocate the regex match state on top. The
			// response is still relayed; fail-open matches the oversize
			// semantics earlier in this function.
			log.Printf("[ADDON-DLP] skip body scan: decompressed body %d bytes exceeds %d bytes for %s", len(f.Response.Body), maxProxyBody, requestHostForFlow(f))
			bodyEligible = false
		}
	}

	// applyBodyDLP folds in the header counts even when the body pass
	// is skipped (oversize/binary/decode failure), so header-only
	// redactions still reach the audit event.
	bodyRules := rules
	if !bodyEligible {
		bodyRules = nil
	}
	names, counts := applyBodyDLP(f, bodyRules, headerCounts)
	if len(counts) == 0 {
		// Observability: no-match scans are frequent (every clean
		// response). Rate-limit to one log line per dlpNoMatchLogEvery
		// scans to avoid spamming production logs while still giving
		// operators a pulse signal that DLP is running.
		if n := atomic.AddUint64(&a.dlpNoMatchScans, 1); n%dlpNoMatchLogEvery == 1 {
			log.Printf("[ADDON-DLP] scanned %d responses with no match (sample: %s, %d rules)", n, requestHostForFlow(f), len(rules))
		}
		return
	}

	host, port := connectTargetForFlow(a, f)
	log.Printf("[ADDON-DLP] redacted response for %s:%d (rules: %s, counts: %v)", host, port, strings.Join(names, ","), counts)
	a.logDLPAudit(host, port, names, counts)
}

// requestHostForFlow returns a printable host for the flow's request URL,
// or "unknown" when Request or URL is nil. Used in log lines so a nil
// request (rare, defensive) does not panic.
func requestHostForFlow(f *mitmproxy.Flow) string {
	if f == nil || f.Request == nil || f.Request.URL == nil {
		return "unknown"
	}
	return f.Request.URL.Host
}

// connectTargetForFlow returns the CONNECT host and port for the flow's
// connection, or empty/zero when the connection state is missing.
func connectTargetForFlow(a *SluiceAddon, f *mitmproxy.Flow) (string, int) {
	if f == nil || f.ConnContext == nil || f.ConnContext.ClientConn == nil {
		return "", 0
	}
	cs := a.getConnState(f.ConnContext.ClientConn.Id)
	if cs == nil {
		return "", 0
	}
	return cs.connectHost, cs.connectPort
}

// logDLPAudit emits an audit event describing which rules fired. Reason is
// formatted as `name1=count1,name2=count2` so ops can differentiate "one
// Bearer token redacted" from "50 AWS keys redacted" in the audit stream.
// Safe to call with a nil auditLog.
func (a *SluiceAddon) logDLPAudit(host string, port int, names []string, counts map[string]int) {
	if a.auditLog == nil {
		return
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", n, counts[n]))
	}
	evt := audit.Event{
		Destination: host,
		Port:        port,
		Protocol:    "https",
		Verdict:     "redact",
		Action:      "response_dlp_redact",
		Reason:      strings.Join(parts, ","),
	}
	if err := a.auditLog.Log(evt); err != nil {
		log.Printf("[ADDON-DLP] audit log error: %v", err)
	}
}
