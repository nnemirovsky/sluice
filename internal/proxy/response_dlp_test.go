package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/policy"
	uuid "github.com/satori/go.uuid"
)

// newDLPResponseFlow builds a flow with a Response suitable for DLP tests.
// The request URL is fixed to a harmless API endpoint because DLP scanning
// is URL-agnostic (unlike OAuth interception which matches on URL). Status
// code is hard-coded to 200 because every DLP test exercises the success
// path. A non-2xx response would skip DLP scanning entirely via the
// StatusCode guard in Response.
func newDLPResponseFlow(client *mitmproxy.ClientConn, body []byte, header http.Header) *mitmproxy.Flow {
	u, _ := url.Parse("https://api.example.com/data")
	if header == nil {
		header = make(http.Header)
	}
	return &mitmproxy.Flow{
		Id: uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{
			ClientConn: client,
		},
		Request: &mitmproxy.Request{
			Method: "GET",
			URL:    u,
			Header: make(http.Header),
		},
		Response: &mitmproxy.Response{
			StatusCode: 200,
			Header:     header,
			Body:       body,
		},
	}
}

// apiKeyRedactRule returns a redact rule that matches AWS-style access
// key IDs (e.g., AKIA... followed by 16 hex-ish characters).
func apiKeyRedactRule() policy.InspectRedactRule {
	return policy.InspectRedactRule{
		Pattern:     `AKIA[A-Z0-9]{16}`,
		Replacement: "AKIA[REDACTED]",
		Name:        "aws_access_key",
	}
}

// bearerRedactRule returns a redact rule that matches Bearer tokens in
// response headers.
func bearerRedactRule() policy.InspectRedactRule {
	return policy.InspectRedactRule{
		Pattern:     `Bearer [A-Za-z0-9._-]+`,
		Replacement: "Bearer [REDACTED]",
		Name:        "bearer_token",
	}
}

func TestSetRedactRules_EmptyDisables(t *testing.T) {
	addon := NewSluiceAddon()

	if err := addon.SetRedactRules(nil); err != nil {
		t.Fatalf("SetRedactRules(nil) returned error: %v", err)
	}

	rules := addon.loadRedactRules()
	if len(rules) != 0 {
		t.Fatalf("expected zero rules after nil set, got %d", len(rules))
	}
}

func TestSetRedactRules_InvalidPatternReturnsError(t *testing.T) {
	addon := NewSluiceAddon()

	err := addon.SetRedactRules([]policy.InspectRedactRule{
		{Pattern: "(invalid", Replacement: "X", Name: "bad"},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
	if !strings.Contains(err.Error(), "compile mitm redact pattern") {
		t.Errorf("error message = %q, want to contain compile error prefix", err.Error())
	}
}

func TestSetRedactRules_ValidReplaces(t *testing.T) {
	addon := NewSluiceAddon()

	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules returned error: %v", err)
	}

	rules := addon.loadRedactRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].name != "aws_access_key" {
		t.Errorf("rule name = %q, want aws_access_key", rules[0].name)
	}

	// Swap to a different rule set and confirm the update is visible.
	if err := addon.SetRedactRules([]policy.InspectRedactRule{bearerRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules second call returned error: %v", err)
	}
	rules = addon.loadRedactRules()
	if len(rules) != 1 || rules[0].name != "bearer_token" {
		t.Fatalf("expected bearer_token rule after swap, got %+v", rules)
	}
}

func TestResponseDLP_BodyRedacted(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	body := []byte(`{"credential":"AKIAIOSFODNN7EXAMPLE","owner":"alice"}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("raw AWS key leaked in response body: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker in body, got %q", got)
	}

	// Content-Length must be updated to the new size.
	cl := f.Response.Header.Get("Content-Length")
	wantCL := strconv.Itoa(len(f.Response.Body))
	if cl != wantCL {
		t.Errorf("Content-Length = %q, want %q", cl, wantCL)
	}
}

func TestResponseDLP_HeaderRedacted(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{bearerRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("X-Echo-Auth", "Bearer abc123.def456.ghi789")
	body := []byte(`{"ok":true}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	echoed := f.Response.Header.Get("X-Echo-Auth")
	if strings.Contains(echoed, "abc123.def456.ghi789") {
		t.Errorf("bearer token leaked in response header: %q", echoed)
	}
	if !strings.Contains(echoed, "Bearer [REDACTED]") {
		t.Errorf("expected redacted bearer marker in header, got %q", echoed)
	}
}

func TestResponseDLP_CleanResponseUnchanged(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("X-Request-Id", "req-1234")
	body := []byte(`{"greeting":"hello, world"}`)
	originalBody := append([]byte(nil), body...)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	if !bytes.Equal(f.Response.Body, originalBody) {
		t.Errorf("clean body was modified: got %q, want %q", string(f.Response.Body), string(originalBody))
	}
	if got := f.Response.Header.Get("X-Request-Id"); got != "req-1234" {
		t.Errorf("clean header was modified: got %q, want %q", got, "req-1234")
	}
}

func TestResponseDLP_BinaryContentTypeSkipped(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	cases := []struct {
		contentType string
	}{
		{"image/png"},
		{"image/jpeg; charset=binary"},
		{"video/mp4"},
		{"audio/mpeg"},
		{"application/octet-stream"},
		{"application/pdf"},
		{"application/zip"},
		{"font/woff2"},
	}

	for _, tc := range cases {
		t.Run(tc.contentType, func(t *testing.T) {
			header := make(http.Header)
			header.Set("Content-Type", tc.contentType)

			// A body that literally contains the AWS key pattern. The
			// scan must NOT redact it because the content type is
			// binary.
			body := []byte("AKIAIOSFODNN7EXAMPLE raw binary")
			originalBody := append([]byte(nil), body...)
			f := newDLPResponseFlow(client, body, header)

			addon.Response(f)

			if !bytes.Equal(f.Response.Body, originalBody) {
				t.Errorf("binary body was modified for Content-Type %q: got %q", tc.contentType, string(f.Response.Body))
			}
		})
	}
}

func TestResponseDLP_OversizedBodySkipped(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Body length exceeds maxProxyBody. Use a short prefix that contains
	// the AWS key pattern so we can verify the scan did not run. The
	// remaining bytes are filler. This is a fail-open case because the
	// data already left the upstream.
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	body := make([]byte, maxProxyBody+1)
	// Seed with an AWS key at the start so the regex would match if
	// the scan ran.
	copy(body, []byte("AKIAIOSFODNN7EXAMPLE"))
	for i := len("AKIAIOSFODNN7EXAMPLE"); i < len(body); i++ {
		body[i] = 'x'
	}
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	if !bytes.HasPrefix(f.Response.Body, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Errorf("oversized body was modified (fail-open expected). prefix = %q", string(f.Response.Body[:len("AKIAIOSFODNN7EXAMPLE")]))
	}
	if len(f.Response.Body) != maxProxyBody+1 {
		t.Errorf("oversized body length changed: got %d, want %d", len(f.Response.Body), maxProxyBody+1)
	}
}

func TestResponseDLP_GzipDecompressedAndScanned(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE","user":"alice"}`

	// Gzip-compress the body so the scan must decode it first.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip")
	header.Set("Content-Length", strconv.Itoa(buf.Len()))

	f := newDLPResponseFlow(client, buf.Bytes(), header)

	addon.Response(f)

	// After scanning the decoded body must be in plaintext form and
	// the real AWS key must have been redacted.
	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("gzip body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after gzip decode, got %q", got)
	}

	// Content-Encoding must be removed by go-mitmproxy's
	// ReplaceToDecodedBody so the agent receives plaintext.
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after decode: %q", enc)
	}
}

func TestResponseDLP_NoRulesNoOp(t *testing.T) {
	addon := NewSluiceAddon()
	// Do not call SetRedactRules: no rules configured.

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	body := []byte(`{"credential":"AKIAIOSFODNN7EXAMPLE"}`)
	originalBody := append([]byte(nil), body...)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	if !bytes.Equal(f.Response.Body, originalBody) {
		t.Errorf("body was modified with no rules configured: got %q", string(f.Response.Body))
	}
}

func TestResponseDLP_HopByHopHeadersSkipped(t *testing.T) {
	addon := NewSluiceAddon()
	// Pattern matches anything. If hop-by-hop headers were scanned, this
	// would corrupt the response framing.
	if err := addon.SetRedactRules([]policy.InspectRedactRule{
		{Pattern: `chunked`, Replacement: "REDACTED", Name: "match_all"},
	}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Transfer-Encoding", "chunked")
	body := []byte(`{"ok":true}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	if got := f.Response.Header.Get("Transfer-Encoding"); got != "chunked" {
		t.Errorf("hop-by-hop Transfer-Encoding was mutated: got %q", got)
	}
}

func TestResponseDLP_AuditLogged(t *testing.T) {
	// Use a temporary audit log file.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() {
		_ = logger.Close()
	})

	addon := NewSluiceAddon(WithAuditLogger(logger))
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	body := []byte(`{"k":"AKIAIOSFODNN7EXAMPLE"}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	// Close to flush.
	if err := logger.Close(); err != nil {
		t.Fatalf("logger close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	contents := string(data)
	if !strings.Contains(contents, "response_dlp_redact") {
		t.Errorf("audit log missing response_dlp_redact action: %q", contents)
	}
	if !strings.Contains(contents, "aws_access_key") {
		t.Errorf("audit log missing rule name: %q", contents)
	}
	if !strings.Contains(contents, `"destination":"api.example.com"`) {
		t.Errorf("audit log missing destination: %q", contents)
	}
	// Reason must include the match count so ops can distinguish
	// "one Bearer token" from "50 AWS keys" in the audit stream. The
	// format is `name=count` joined by commas.
	if !strings.Contains(contents, "aws_access_key=1") {
		t.Errorf("audit log missing per-rule count: %q", contents)
	}
}

func TestResponseDLP_NilResponseNoPanic(t *testing.T) {
	// Use a temp audit log so we can assert no event was written.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	addon := NewSluiceAddon(WithAuditLogger(logger))
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}
	client := newTestClientConn()
	addon.ClientConnected(client)

	f := &mitmproxy.Flow{
		Id: uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{
			ClientConn: client,
		},
		Request: &mitmproxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "api.example.com", Path: "/"},
			Header: make(http.Header),
		},
		Response: nil,
	}

	// Must not panic.
	addon.Response(f)

	// Must not emit an audit event for a nil response. Flush then read.
	if err := logger.Close(); err != nil {
		t.Fatalf("logger close: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Contains(string(data), "response_dlp_redact") {
		t.Errorf("audit log should not contain response_dlp_redact for nil response: %q", string(data))
	}
}

func TestIsBinaryContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"", false},
		{"application/json", false},
		{"text/plain", false},
		{"text/html; charset=utf-8", false},
		{"application/xml", false},
		{"image/png", true},
		{"image/jpeg", true},
		{"IMAGE/GIF", true},
		{"image/svg+xml; charset=utf-8", true},
		{"video/mp4", true},
		{"audio/ogg", true},
		{"application/octet-stream", true},
		{"application/pdf", true},
		{"application/zip", true},
		{"application/x-tar", true},
		{"application/x-gzip", true},
		{"application/x-7z-compressed", true},
		{"font/woff2", true},
	}

	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			got := isBinaryContentType(tc.ct)
			if got != tc.want {
				t.Errorf("isBinaryContentType(%q) = %v, want %v", tc.ct, got, tc.want)
			}
		})
	}
}

func TestShouldSkipHeaderForDLP(t *testing.T) {
	skip := []string{
		"Connection",
		"keep-alive",
		"PROXY-AUTHENTICATE",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Content-Length",
	}
	for _, h := range skip {
		if !shouldSkipHeaderForDLP(h) {
			t.Errorf("shouldSkipHeaderForDLP(%q) = false, want true", h)
		}
	}

	scan := []string{
		"Content-Type",
		"X-Custom",
		"Authorization",
		"",
	}
	for _, h := range scan {
		if shouldSkipHeaderForDLP(h) {
			t.Errorf("shouldSkipHeaderForDLP(%q) = true, want false", h)
		}
	}
}

func TestResponseDLP_MultipleRulesApplied(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	addon := NewSluiceAddon(WithAuditLogger(logger))
	if err := addon.SetRedactRules([]policy.InspectRedactRule{
		apiKeyRedactRule(),
		bearerRedactRule(),
	}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	body := []byte(`{"aws":"AKIAIOSFODNN7EXAMPLE","jwt":"Bearer abc.def.ghi"}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key leaked: %q", got)
	}
	if strings.Contains(got, "Bearer abc.def.ghi") {
		t.Errorf("bearer token leaked: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected AWS redacted marker: %q", got)
	}
	if !strings.Contains(got, "Bearer [REDACTED]") {
		t.Errorf("expected bearer redacted marker: %q", got)
	}

	// Audit Reason must list BOTH rule names so operators can see
	// which rules fired for a given response.
	if err := logger.Close(); err != nil {
		t.Fatalf("logger close: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	contents := string(data)
	if !strings.Contains(contents, "aws_access_key") {
		t.Errorf("audit log missing aws_access_key rule name: %q", contents)
	}
	if !strings.Contains(contents, "bearer_token") {
		t.Errorf("audit log missing bearer_token rule name: %q", contents)
	}
	// Reason should include `name=count` for both rules.
	if !strings.Contains(contents, "aws_access_key=1") {
		t.Errorf("audit log missing aws_access_key count: %q", contents)
	}
	if !strings.Contains(contents, "bearer_token=1") {
		t.Errorf("audit log missing bearer_token count: %q", contents)
	}
	// Rule names in audit Reason must be alphabetically sorted so
	// operators can rely on a stable format. scanResponseForDLP sorts
	// the names before joining, so `aws_access_key=1,bearer_token=1`
	// must come before `bearer_token=1,aws_access_key=1`.
	awsIdx := strings.Index(contents, "aws_access_key=1")
	bearerIdx := strings.Index(contents, "bearer_token=1")
	if awsIdx < 0 || bearerIdx < 0 {
		t.Fatalf("both rule counts must be present, got awsIdx=%d bearerIdx=%d in %q", awsIdx, bearerIdx, contents)
	}
	if awsIdx >= bearerIdx {
		t.Errorf("expected alphabetical order (aws_access_key before bearer_token), got aws=%d bearer=%d in %q", awsIdx, bearerIdx, contents)
	}
}

// TestResponseDLP_IdentityEncodingScanned verifies that an explicit
// Content-Encoding: identity header is treated as non-encoded and the body
// is scanned as plaintext. Also covers the multi-token case (`identity,
// identity`) which per RFC 9110 is also a no-op.
func TestResponseDLP_IdentityEncodingScanned(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
	}{
		{"single token", "identity"},
		{"multi token", "identity, identity"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addon := NewSluiceAddon()
			if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
				t.Fatalf("SetRedactRules: %v", err)
			}

			client := setupAddonConn(addon, "api.example.com:443")

			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			header.Set("Content-Encoding", tc.encoding)
			body := []byte(`{"k":"AKIAIOSFODNN7EXAMPLE"}`)
			f := newDLPResponseFlow(client, body, header)

			addon.Response(f)

			got := string(f.Response.Body)
			if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("identity-encoded body leaked: %q", got)
			}
			if !strings.Contains(got, "AKIA[REDACTED]") {
				t.Errorf("expected redacted marker in identity body, got %q", got)
			}
			// Content-Encoding must be cleared after identity
			// normalization so downstream code does not see a
			// lingering identity value.
			if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
				t.Errorf("Content-Encoding should be cleared after identity normalization, got %q", enc)
			}
		})
	}
}

// TestResponseDLP_DeflateDecompressedAndScanned verifies that a
// deflate-compressed response body is decoded before scanning. The
// payload is raw RFC 1951 DEFLATE (no zlib wrapper). This is the
// fallback path: per RFC 9110 Section 8.4.1, `Content-Encoding: deflate`
// is supposed to be zlib-wrapped (RFC 1950), but some servers
// historically emit raw DEFLATE. Codex iter 6 added zlib as the primary
// decoder with raw flate as the fallback so both forms decode.
func TestResponseDLP_DeflateDecompressedAndScanned(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`

	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := fw.Write([]byte(raw)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "deflate")

	f := newDLPResponseFlow(client, buf.Bytes(), header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("deflate body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after deflate decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after decode: %q", enc)
	}
}

// TestResponseDLP_DeflateZlibWrapped verifies that the standards-compliant
// `Content-Encoding: deflate` form (RFC 1950 zlib wrapper around raw RFC
// 1951 DEFLATE, per RFC 9110 Section 8.4.1) decodes correctly. Codex iter
// 6 flagged that the previous implementation used flate.NewReader as the
// only decoder, which expects raw RFC 1951 DEFLATE without the 2-byte
// zlib header and 4-byte Adler-32 trailer. Standards-compliant servers
// hit the decode-error fail-open path and skipped body DLP entirely. The
// fix routes deflate through zlib.NewReader first, falling back to
// flate.NewReader only on the zlib invalid-header sentinel so non-conformant
// raw DEFLATE servers still work.
func TestResponseDLP_DeflateZlibWrapped(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`

	// zlib.NewWriter emits the standards-compliant RFC 1950 wrapper
	// around raw RFC 1951 DEFLATE. This is what RFC 9110 Section 8.4.1
	// requires for `Content-Encoding: deflate`.
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "deflate")

	f := newDLPResponseFlow(client, buf.Bytes(), header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("zlib-wrapped deflate body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after zlib-wrapped deflate decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after decode: %q", enc)
	}
}

// TestResponseDLP_ZstdDecompressedAndScanned verifies that a
// zstd-compressed response body is decoded before scanning.
func TestResponseDLP_ZstdDecompressedAndScanned(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`

	zenc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	compressed := zenc.EncodeAll([]byte(raw), nil)
	_ = zenc.Close()

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "zstd")

	f := newDLPResponseFlow(client, compressed, header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("zstd body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after zstd decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after decode: %q", enc)
	}
}

// TestResponseDLP_BrotliDecompressedAndScanned verifies that a real
// brotli-compressed response body is decoded before scanning. Uses
// github.com/andybalholm/brotli (already depended on via go-mitmproxy).
func TestResponseDLP_BrotliDecompressedAndScanned(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE","user":"alice"}`

	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write([]byte(raw)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "br")
	header.Set("Content-Length", strconv.Itoa(buf.Len()))

	f := newDLPResponseFlow(client, buf.Bytes(), header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("brotli body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after brotli decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after decode: %q", enc)
	}
}

// TestResponseDLP_MultiValueContentEncoding verifies that a multi-value
// Content-Encoding like "gzip, identity" is recognized as non-identity and
// triggers decoding. http.Header.Get returns only the first value, so
// naive code would miss the gzip layer.
func TestResponseDLP_MultiValueContentEncoding(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	// Multi-value single-header form: Content-Encoding: gzip, identity.
	header.Set("Content-Encoding", "gzip, identity")

	f := newDLPResponseFlow(client, buf.Bytes(), header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("multi-value Content-Encoding body leaked: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker, got %q", got)
	}
}

// TestResponseDLP_HopByHopModifiedBody verifies that when a body is
// modified (redacted), a pre-existing Transfer-Encoding header is removed
// so go-mitmproxy does not try to re-frame the body with stale chunking.
// Complements TestResponseDLP_HopByHopHeadersSkipped which exercises the
// unmodified path.
func TestResponseDLP_HopByHopModifiedBody(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Transfer-Encoding", "chunked")
	body := []byte(`{"leak":"AKIAIOSFODNN7EXAMPLE"}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("body not redacted: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker: %q", got)
	}
	// Transfer-Encoding must be removed when the body is rewritten with
	// a fixed Content-Length.
	if te := f.Response.Header.Get("Transfer-Encoding"); te != "" {
		t.Errorf("Transfer-Encoding should be cleared after body rewrite, got %q", te)
	}
	cl := f.Response.Header.Get("Content-Length")
	wantCL := strconv.Itoa(len(f.Response.Body))
	if cl != wantCL {
		t.Errorf("Content-Length = %q, want %q", cl, wantCL)
	}
}

// TestResponseDLP_DLPRunsIndependentOfOAuth verifies that DLP runs to
// completion when no OAuth index is configured. This is a baseline sanity
// check that the DLP code path is not accidentally coupled to the OAuth
// phantom-swap code path. A real test exercising OAuth swap followed by
// DLP lives in TestResponseDLP_OAuthAndDLPCoexist below.
func TestResponseDLP_DLPRunsIndependentOfOAuth(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	body := []byte(`{"access_token":"oauth-ish-value","aws":"AKIAIOSFODNN7EXAMPLE"}`)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key leaked: %q", got)
	}
	if !strings.Contains(got, "oauth-ish-value") {
		t.Errorf("non-matching field should pass through: %q", got)
	}
}

// TestResponseDLP_UnknownContentEncoding verifies the fail-closed
// behavior for Content-Encoding tokens sluice/go-mitmproxy does not
// recognize (x-gzip, compress, etc.). Current behavior: the safe
// wrapper treats any non-identity token other than the four supported
// encodings as a decode failure and skips the body scan. Headers are
// still scanned because header DLP does not depend on body decoding.
func TestResponseDLP_UnknownContentEncoding(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	cases := []string{"x-gzip", "compress", "pack200-gzip"}
	for _, enc := range cases {
		t.Run(enc, func(t *testing.T) {
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			header.Set("Content-Encoding", enc)
			body := []byte(`{"k":"AKIAIOSFODNN7EXAMPLE"}`)
			originalBody := append([]byte(nil), body...)
			f := newDLPResponseFlow(client, body, header)

			addon.Response(f)

			// Body must NOT be modified when decoding fails: we do not
			// want to scan a still-encoded body as plaintext and also
			// we do not want to destroy data.
			if !bytes.Equal(f.Response.Body, originalBody) {
				t.Errorf("body was modified despite decode failure for %q: got %q", enc, string(f.Response.Body))
			}
			// Content-Encoding must be preserved on failure.
			if got := f.Response.Header.Get("Content-Encoding"); got != enc {
				t.Errorf("Content-Encoding = %q, want %q after decode failure", got, enc)
			}
		})
	}
}

// TestResponseDLP_HeaderScanSurvivesDecodeFailure verifies that a header
// leak is redacted even when body decompression fails. Header scanning
// runs unconditionally so a broken/unsupported Content-Encoding cannot
// suppress header redaction. The audit event must still fire for the
// header-only redaction so ops see the leak.
func TestResponseDLP_HeaderScanSurvivesDecodeFailure(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	addon := NewSluiceAddon(WithAuditLogger(logger))
	if err := addon.SetRedactRules([]policy.InspectRedactRule{bearerRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	// Unsupported Content-Encoding: decode will fail.
	header.Set("Content-Encoding", "x-gzip")
	// Leak in a header that should still be redacted despite the
	// body scan being skipped.
	header.Set("X-Echo-Auth", "Bearer abc123.def456.ghi789")
	body := []byte("some-invalid-body")
	originalBody := append([]byte(nil), body...)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	// Body must be unchanged (decode failed, scan skipped).
	if !bytes.Equal(f.Response.Body, originalBody) {
		t.Errorf("body was modified despite decode failure: got %q", string(f.Response.Body))
	}
	// Header must be redacted: this is the key assertion.
	echoed := f.Response.Header.Get("X-Echo-Auth")
	if strings.Contains(echoed, "abc123.def456.ghi789") {
		t.Errorf("header leaked Bearer token despite body decode failure: %q", echoed)
	}
	if !strings.Contains(echoed, "Bearer [REDACTED]") {
		t.Errorf("expected redacted bearer marker in header, got %q", echoed)
	}

	// Audit event must fire even when only headers were redacted so
	// ops see the leak in the audit stream.
	if err := logger.Close(); err != nil {
		t.Fatalf("logger close: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	contents := string(data)
	if !strings.Contains(contents, "response_dlp_redact") {
		t.Errorf("audit log missing response_dlp_redact for header-only redaction: %q", contents)
	}
	if !strings.Contains(contents, "bearer_token") {
		t.Errorf("audit log missing bearer_token rule name: %q", contents)
	}
}

// TestResponseDLP_HeaderScanSurvivesBinaryContentType verifies that
// header redaction fires on a binary-Content-Type response even though
// the body scan is skipped.
func TestResponseDLP_HeaderScanSurvivesBinaryContentType(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{bearerRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "image/png")
	header.Set("X-Echo-Auth", "Bearer abc.def.ghi")
	body := []byte("raw-image-bytes-containing-not-a-token")
	originalBody := append([]byte(nil), body...)
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	// Binary body must be untouched.
	if !bytes.Equal(f.Response.Body, originalBody) {
		t.Errorf("binary body was modified: got %q", string(f.Response.Body))
	}
	// Header redacted regardless of content type.
	if got := f.Response.Header.Get("X-Echo-Auth"); strings.Contains(got, "abc.def.ghi") {
		t.Errorf("binary response header not redacted: %q", got)
	}
}

// TestResponseDLP_SSEStreamingBypassed documents the current known
// limitation: sluice does not scan SSE (text/event-stream) responses
// because go-mitmproxy auto-sets f.Stream=true for SSE, which skips the
// Response addon callback. Instead, StreamResponseModifier logs a
// one-shot WARNING per connection. This test pins that behavior so a
// future fix (see plan Future work) is recognized as an intentional
// change rather than silently hiding the gap.
func TestResponseDLP_SSEStreamingBypassed(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Build a flow mimicking what go-mitmproxy would pass to
	// StreamResponseModifier for an SSE response. f.Stream is not
	// explicitly set here because the important contract is that
	// StreamResponseModifier emits the WARNING regardless (the
	// underlying library sets Stream when the Content-Type is SSE).
	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream")
	body := []byte("data: AKIAIOSFODNN7EXAMPLE\n\n")
	f := newDLPResponseFlow(client, body, header)

	// Invoke StreamResponseModifier directly. The sluice addon passes
	// through the input reader; it does not scan the body, so the AWS
	// key in the SSE payload would leak through. This is intentional
	// until stream-aware scanning lands.
	in := bytes.NewReader(body)
	out := addon.StreamResponseModifier(f, in)
	if out == nil {
		t.Fatal("StreamResponseModifier returned nil reader")
	}

	// The passthrough reader returns the original bytes including the
	// AWS key. If a future change wires scanning into this path, this
	// assertion will need updating.
	streamed, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("read streamed body: %v", err)
	}
	if !bytes.Contains(streamed, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Errorf("SSE path is no longer pure passthrough: got %q", string(streamed))
	}
}

// TestResponseDLP_StreamWarningDedupOnePerConnection verifies the
// one-shot dedup contract: StreamResponseModifier emits the WARNING
// exactly once per client connection, even when called multiple times
// for the same connection (which happens for multi-chunk streams).
// The dedup state lives on dlpStreamWarned, scoped by client connection
// id. This pins the iter-2 dedup behavior so a regression that emits
// a warning per chunk is caught.
func TestResponseDLP_StreamWarningDedupOnePerConnection(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Capture log output to count WARNING lines.
	var logBuf strings.Builder
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream")
	body := []byte("data: chunk\n\n")

	// Call StreamResponseModifier five times on the same connection
	// to simulate multi-chunk streaming.
	for i := 0; i < 5; i++ {
		f := newDLPResponseFlow(client, body, header)
		out := addon.StreamResponseModifier(f, bytes.NewReader(body))
		if out == nil {
			t.Fatalf("call %d: StreamResponseModifier returned nil reader", i)
		}
		// Consume so subsequent calls see a fresh reader state.
		_, _ = io.ReadAll(out)
	}

	warnings := strings.Count(logBuf.String(), "WARNING: streaming response bypasses DLP")
	if warnings != 1 {
		t.Errorf("expected exactly 1 streaming-bypass WARNING per connection, got %d. logs:\n%s", warnings, logBuf.String())
	}
}

// TestResponseDLP_LargeCompressedJSONScanned verifies that a legitimately
// large compressed JSON response (multi-MiB compressed expanding to ~10 MiB
// plaintext, well under maxProxyBody) is decoded and scanned. A previous
// iteration applied an upfront compressed-size cap (maxProxyBody / 20 ~=
// 819 KiB) that incorrectly skipped DLP on most LLM API responses. The
// upfront guard has been dropped in favor of the post-decompression size
// check, which only fails open on inflated bodies that exceed maxProxyBody.
// This test pins the new behavior: a body whose decoded size is comfortably
// inside the cap must still be scanned and have its embedded AWS key
// redacted.
func TestResponseDLP_LargeCompressedJSONScanned(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Build a JSON-like payload around 10 MiB plaintext containing an
	// AWS key. We use pseudo-text that gzip can compress meaningfully
	// (so the wire size stays in the realistic LLM-response range of a
	// few MiB) but the decoded body comfortably fits under maxProxyBody.
	const decodedTarget = 10 << 20 // ~10 MiB plaintext
	var raw bytes.Buffer
	raw.WriteString(`{"data":"`)
	chunk := make([]byte, 1024)
	// Use a lightly varied filler so it compresses to a realistic JSON
	// ratio (around 4-5x for typical UTF-8 text), not the extreme 1000x
	// that flat zeros produce.
	for i := range chunk {
		chunk[i] = byte('a' + (i % 26))
	}
	for raw.Len() < decodedTarget {
		raw.Write(chunk)
	}
	// Embed the AWS key so a successful scan must redact it.
	raw.WriteString(`AKIAIOSFODNN7EXAMPLE","tail":"end"}`)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	if int64(buf.Len()) >= int64(maxProxyBody) {
		t.Fatalf("test setup: compressed body %d bytes >= maxProxyBody %d, plain oversize guard would trip first", buf.Len(), maxProxyBody)
	}
	if int64(raw.Len()) >= int64(maxProxyBody) {
		t.Fatalf("test setup: decoded body %d bytes >= maxProxyBody %d, post-decompression guard would skip the scan", raw.Len(), maxProxyBody)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip")
	f := newDLPResponseFlow(client, buf.Bytes(), header)

	addon.Response(f)

	// Decompression must have run and stripped the encoding header.
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty after successful decode", enc)
	}
	// The AWS key must have been redacted.
	if bytes.Contains(f.Response.Body, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Error("AWS key was not redacted; large compressed body should have been scanned")
	}
	if !bytes.Contains(f.Response.Body, []byte("AKIA[REDACTED]")) {
		t.Error("redaction marker AKIA[REDACTED] missing; scan did not run")
	}
}

// TestResponseDLP_OversizedAfterDecompressionSkipped verifies the
// post-decompression size check, which is the sole compression-bomb
// defense after the upfront compressed-size cap was dropped (it was
// rejecting legitimate large LLM responses). All-zero input compresses
// extremely well, so a tiny compressed body can balloon past maxProxyBody
// during decode. The post-decompression guard catches that case and skips
// the body scan fail-open while the response is still relayed.
func TestResponseDLP_OversizedAfterDecompressionSkipped(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Build a gzip body whose decompressed size exceeds maxProxyBody.
	// All-zero input compresses extremely well, so a modest compressed
	// size maps to a massive plaintext.
	raw := make([]byte, maxProxyBody+1)
	// Seed with an AWS key so we can tell if the scan ran.
	copy(raw, []byte("AKIAIOSFODNN7EXAMPLE"))
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := gw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	// We need the decoded body to exceed maxProxyBody so the
	// post-decompression check trips and skips the scan.
	if int64(len(raw)) <= int64(maxProxyBody) {
		t.Fatalf("test setup: decoded body %d bytes <= maxProxyBody %d; post-decompression guard would not trip", len(raw), maxProxyBody)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip")
	originalCompressed := append([]byte(nil), buf.Bytes()...)
	f := newDLPResponseFlow(client, buf.Bytes(), header)

	var logBuf strings.Builder
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	addon.Response(f)

	// The bounded decoder catches the oversize via errDecompressedTooLarge
	// before io.ReadAll materializes the full inflated body, so
	// safeReplaceToDecodedBody returns an error and leaves the COMPRESSED
	// body intact (with Content-Encoding restored). The body scan is
	// skipped fail-open. This is more secure than the old behavior, which
	// allocated the full inflated body before the post-decompression check
	// caught it.
	if !bytes.Equal(f.Response.Body, originalCompressed) {
		t.Errorf("compressed body modified despite decompression-bomb rejection: len got %d, want %d", len(f.Response.Body), len(originalCompressed))
	}
	if bytes.Contains(f.Response.Body, []byte("AKIA[REDACTED]")) {
		t.Errorf("scan unexpectedly ran on oversized decompressed body")
	}
	// Content-Encoding must be restored so the agent can decode if it
	// knows how. Without restore, the agent would see a still-compressed
	// body advertised as plaintext.
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip restored after bounded decode failure", enc)
	}

	// Verify the compression-bomb skip log fired. The new sentinel produces
	// a distinct message from generic decode errors so operators can tell
	// the OOM-defense path apart in audit triage.
	if !strings.Contains(logBuf.String(), "compression-bomb guard") {
		t.Errorf("compression-bomb skip did not log. logs:\n%s", logBuf.String())
	}
}

// TestResponseDLP_StreamWarningFiresOnNon2xx verifies that the DLP-bypass
// warning fires on streamed responses with a non-2xx status code. Buffered
// 4xx/5xx responses are scanned by the Response callback, but streamed
// error responses (e.g. an SSE error stream from an LLM API, or a large
// 5xx body) skip the Response callback and would silently bypass DLP
// without this warning. The warning is a visibility signal only (it does
// not modify the response), so firing on any status code is safe. This
// pins the behavior so a regression that short-circuits on non-2xx and
// suppresses the warning is caught.
func TestResponseDLP_StreamWarningFiresOnNon2xx(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	var logBuf strings.Builder
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	// Build an SSE flow with a 5xx status code. The contract is that
	// StreamResponseModifier still logs the DLP-bypass warning even when
	// the response would otherwise short-circuit on the status guard.
	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream")
	body := []byte("data: AKIAIOSFODNN7EXAMPLE\n\n")
	f := newDLPResponseFlow(client, body, header)
	f.Response.StatusCode = 500

	out := addon.StreamResponseModifier(f, bytes.NewReader(body))
	if out == nil {
		t.Fatal("StreamResponseModifier returned nil reader")
	}
	if _, err := io.ReadAll(out); err != nil {
		t.Fatalf("read streamed body: %v", err)
	}

	if !strings.Contains(logBuf.String(), "WARNING: streaming response bypasses DLP") {
		t.Errorf("DLP-bypass warning did not fire for 5xx streamed response. logs:\n%s", logBuf.String())
	}
}

// TestResponseDLP_StackedEncoding_GzipBr verifies that a body encoded
// twice (gzip then br applied last) is decoded in reverse order and
// scanned. Without iterative stacked-encoding support, a malicious
// upstream could double-encode credential responses to bypass body DLP
// scanning. RFC 9110 Section 8.4.1 lists encodings in application order,
// so decoding peels them off right-to-left: br first, then gzip.
func TestResponseDLP_StackedEncoding_GzipBr(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE","user":"alice"}`

	// Inner: gzip the raw payload.
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	// Outer: br over the gzip output.
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	if _, err := bw.Write(gz.Bytes()); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	// Application order: gzip first, br last. Decoding peels right-to-left.
	header.Set("Content-Encoding", "gzip, br")

	f := newDLPResponseFlow(client, br.Bytes(), header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stacked gzip+br body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after stacked decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after stacked decode: %q", enc)
	}
}

// TestResponseDLP_StackedEncoding_BrGzip verifies the reverse stacking
// order ("br, gzip" meaning br applied first, gzip applied last). This
// covers both stacking orders so a malicious upstream cannot pick the
// untested order to slip past DLP. Decoding is symmetric in the
// implementation: each level is peeled off in turn.
func TestResponseDLP_StackedEncoding_BrGzip(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`

	// Inner: br the raw payload.
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	if _, err := bw.Write([]byte(raw)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	// Outer: gzip over the br output.
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(br.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	// Application order: br first, gzip last. Decoding peels right-to-left.
	header.Set("Content-Encoding", "br, gzip")

	f := newDLPResponseFlow(client, gz.Bytes(), header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stacked br+gzip body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after stacked decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after stacked decode: %q", enc)
	}
}

// TestResponseDLP_StackedEncoding_DeflateZstd verifies a stacked
// deflate+zstd combination works. Pins coverage for the less common
// encoding pair so a regression in either decoder branch is caught.
func TestResponseDLP_StackedEncoding_DeflateZstd(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`

	// Inner: deflate the raw payload.
	var def bytes.Buffer
	dw, err := flate.NewWriter(&def, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := dw.Write([]byte(raw)); err != nil {
		t.Fatalf("deflate write: %v", err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}

	// Outer: zstd over the deflate output.
	zenc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	zstdBody := zenc.EncodeAll(def.Bytes(), nil)
	if err := zenc.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "deflate, zstd")

	f := newDLPResponseFlow(client, zstdBody, header)

	addon.Response(f)

	got := string(f.Response.Body)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stacked deflate+zstd body leaked AWS key after scan: %q", got)
	}
	if !strings.Contains(got, "AKIA[REDACTED]") {
		t.Errorf("expected redacted marker after stacked decode, got %q", got)
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding still set after stacked decode: %q", enc)
	}
}

// TestResponseDLP_StackedEncoding_ThreeLevelsRejected verifies that a
// three-level encoding stack is rejected with an error and falls into
// the body-scan-skipped fail-open path. Legitimate stacking beyond 2
// levels is vanishingly rare, and accepting arbitrary depth would let
// an adversarial upstream consume CPU. Cap is maxStackedEncodingDepth.
func TestResponseDLP_StackedEncoding_ThreeLevelsRejected(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Capture logs to verify the skip log fires.
	var logBuf strings.Builder
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	// Build a 3-level stack: gzip -> gzip -> gzip.
	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`
	current := []byte(raw)
	for i := 0; i < 3; i++ {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(current); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		current = buf.Bytes()
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip, gzip, gzip")

	originalBody := append([]byte(nil), current...)
	f := newDLPResponseFlow(client, current, header)

	addon.Response(f)

	// Body should be unchanged: decoder rejected stacking depth, so
	// scan was skipped and original body relayed.
	if !bytes.Equal(f.Response.Body, originalBody) {
		t.Errorf("body modified despite three-level stack rejection: got %d bytes, want %d", len(f.Response.Body), len(originalBody))
	}
	// Content-Encoding must be preserved on failure so the agent can
	// still decode if it knows how.
	enc := f.Response.Header.Get("Content-Encoding")
	if !strings.Contains(enc, "gzip") {
		t.Errorf("Content-Encoding should be preserved on stacking depth rejection, got %q", enc)
	}
	// Skip log must fire so operators see the bypass.
	if !strings.Contains(logBuf.String(), "skip body scan") {
		t.Errorf("expected skip body scan log on three-level stack. logs:\n%s", logBuf.String())
	}
}

// TestResponseDLP_StackedEncoding_UnknownTokenRejected verifies that a
// stacked encoding containing an unrecognized token (e.g. "compress",
// "x-gzip") is rejected with an error and the body-scan is skipped
// fail-open. Without this guard, the iterative decoder might emit a
// confusing error or attempt to scan still-encoded bytes as plaintext.
func TestResponseDLP_StackedEncoding_UnknownTokenRejected(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	var logBuf strings.Builder
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	// Build a body that is only gzip-encoded but advertise "gzip, unknown"
	// so the iterative decoder fails on the unknown token.
	raw := `{"leak":"AKIAIOSFODNN7EXAMPLE"}`
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip, unknown-encoding")

	originalBody := append([]byte(nil), gz.Bytes()...)
	f := newDLPResponseFlow(client, gz.Bytes(), header)

	addon.Response(f)

	if !bytes.Equal(f.Response.Body, originalBody) {
		t.Errorf("body modified despite unknown-token rejection: got %d bytes, want %d", len(f.Response.Body), len(originalBody))
	}
	if !strings.Contains(logBuf.String(), "skip body scan") {
		t.Errorf("expected skip body scan log on unknown-token rejection. logs:\n%s", logBuf.String())
	}
}

// TestResponseDLP_StackedEncoding_HeaderStillScanned verifies that even
// when the body is rejected due to an unsupported stacked encoding,
// header-borne credentials are still redacted. Header scanning runs
// independently of body scanning so a broken Content-Encoding cannot
// suppress header DLP.
func TestResponseDLP_StackedEncoding_HeaderStillScanned(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{bearerRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip, gzip, gzip")
	header.Set("X-Echo-Auth", "Bearer abc123.def456.ghi789")
	body := []byte("some-encoded-body")
	f := newDLPResponseFlow(client, body, header)

	addon.Response(f)

	echoed := f.Response.Header.Get("X-Echo-Auth")
	if strings.Contains(echoed, "abc123.def456.ghi789") {
		t.Errorf("header leaked Bearer token despite stacked decode rejection: %q", echoed)
	}
	if !strings.Contains(echoed, "Bearer [REDACTED]") {
		t.Errorf("expected redacted bearer marker in header, got %q", echoed)
	}
}

// TestResponseDLP_SingleEncodingBoundedDecode verifies that the
// single-encoding decode path enforces the same maxProxyBody+1 io.LimitReader
// cap as the stacked-encoding path. Codex iter 5 flagged that the previous
// implementation delegated single-encoding decode to go-mitmproxy's
// ReplaceToDecodedBody, which uses io.Copy with NO size cap. A small
// gzip body that inflates past maxProxyBody could OOM before the
// post-decompression check ran. The fix routed single-encoding through
// the same bounded decodeStacked path used for stacked encodings.
//
// The test crafts a gzip body whose decompressed size exceeds
// maxProxyBody. The bounded decoder reads only maxProxyBody+1 bytes, then
// the post-decompression size guard trips, the body scan is skipped, and
// the original (still-encoded) body is preserved with Content-Encoding
// intact so the agent can decode if it knows how. The test passes when
// no OOM occurs and the skip log fires.
func TestResponseDLP_SingleEncodingBoundedDecode(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Build a gzip body that decompresses to more than maxProxyBody.
	// All-zero input is highly compressible, so a modest compressed size
	// expands to a massive plaintext.
	raw := make([]byte, maxProxyBody+1)
	copy(raw, []byte("AKIAIOSFODNN7EXAMPLE"))
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := gw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	// Sanity-check the test fixture: the compressed body must be small
	// enough to pass the upfront size guard so we exercise the decode
	// path. The decoded body must exceed maxProxyBody so the
	// post-decompression guard trips after the bounded decoder runs.
	if int64(buf.Len()) >= int64(maxProxyBody) {
		t.Fatalf("test setup: compressed body %d bytes >= maxProxyBody %d, upfront guard would trip first", buf.Len(), maxProxyBody)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip")
	originalCompressed := append([]byte(nil), buf.Bytes()...)
	f := newDLPResponseFlow(client, buf.Bytes(), header)

	var logBuf strings.Builder
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	addon.Response(f)

	// Codex iter 6 hardened the bounded decoder to cap the DECOMPRESSED
	// output via io.LimitReader on the decoder's reader (not the input).
	// A small compressed body that decompresses past maxProxyBody now
	// fails decode with errDecompressedTooLarge BEFORE io.ReadAll can
	// allocate the full inflated body. The compressed body is preserved
	// (with Content-Encoding intact) and the body scan is skipped
	// fail-open.
	if !bytes.Equal(f.Response.Body, originalCompressed) {
		t.Errorf("compressed body modified despite bounded-decoder rejection: len got %d, want %d", len(f.Response.Body), len(originalCompressed))
	}
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip restored after bounded-decoder failure", enc)
	}

	// The skip log fires with the compression-bomb-specific message so
	// operators can tell this case apart from a generic decode failure.
	if !strings.Contains(logBuf.String(), "compression-bomb guard") {
		t.Errorf("expected compression-bomb skip log, got:\n%s", logBuf.String())
	}
}

// TestResponseDLP_DecodedBodyHasCorrectFraming verifies that after a
// successful stacked decode that does not result in any DLP redaction,
// Content-Length is rewritten to match the decoded body length and
// Transfer-Encoding is cleared. Codex iter 5 flagged that the
// stacked-decode path replaced the body and dropped Content-Encoding but
// did not update framing headers, so the proxy would forward a plaintext
// body with framing headers describing the COMPRESSED body. The fix
// rewrites Content-Length and clears Transfer-Encoding right after the
// body replacement, regardless of whether downstream redaction touches
// the body.
func TestResponseDLP_DecodedBodyHasCorrectFraming(t *testing.T) {
	addon := NewSluiceAddon()
	if err := addon.SetRedactRules([]policy.InspectRedactRule{apiKeyRedactRule()}); err != nil {
		t.Fatalf("SetRedactRules: %v", err)
	}

	client := setupAddonConn(addon, "api.example.com:443")

	// Benign payload: no AWS key, so no body redaction will fire after
	// decode. We still need framing headers to reflect the decoded length.
	raw := `{"data":"benign content with no secrets","ok":true}`

	// Stack: gzip then br applied last. RFC 9110 Section 8.4.1 says
	// encodings are listed in application order, so decoding peels them
	// off right-to-left.
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	if _, err := bw.Write(gz.Bytes()); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Encoding", "gzip, br")
	// Set framing headers that describe the COMPRESSED body. After
	// decode without redact, these must be updated to match the
	// decoded body, otherwise the proxy emits a length-mismatched
	// response.
	header.Set("Content-Length", strconv.Itoa(br.Len()))
	header.Set("Transfer-Encoding", "chunked")

	f := newDLPResponseFlow(client, br.Bytes(), header)

	addon.Response(f)

	// Body must equal the decoded raw payload.
	if string(f.Response.Body) != raw {
		t.Errorf("decoded body mismatch:\n got: %q\nwant: %q", f.Response.Body, raw)
	}
	// Content-Encoding must be cleared after successful decode.
	if enc := f.Response.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty after decode", enc)
	}
	// Content-Length must match the decoded body length, not the
	// compressed length we put in earlier.
	if got, want := f.Response.Header.Get("Content-Length"), strconv.Itoa(len(raw)); got != want {
		t.Errorf("Content-Length = %q, want %q (decoded body length)", got, want)
	}
	// Transfer-Encoding must be cleared. Mixing chunked transfer with
	// a fixed Content-Length is a framing error.
	if te := f.Response.Header.Get("Transfer-Encoding"); te != "" {
		t.Errorf("Transfer-Encoding = %q, want empty after decode", te)
	}
}

// TestDecodeOne_OutputCappedAtMaxProxyBody is a direct unit test for the
// bounded-decoder OOM defense. The previous decodeOne wrapped the
// COMPRESSED input with io.LimitReader, which let io.ReadAll allocate
// arbitrary plaintext from a small compressed body. The fix moves the
// io.LimitReader to the DECOMPRESSED output via readDecodedBounded and
// returns errDecompressedTooLarge when the cap would be exceeded.
//
// The test compresses a payload larger than maxProxyBody and asserts that
// decodeOne returns the sentinel error rather than the inflated body.
// This pins the OOM defense at the lowest layer so a regression that
// reverts the cap to the input side fails this test before any
// integration-level test runs.
func TestDecodeOne_OutputCappedAtMaxProxyBody(t *testing.T) {
	// Build a gzip body that decompresses to maxProxyBody+1 bytes.
	raw := make([]byte, maxProxyBody+1)
	for i := range raw {
		raw[i] = 'a'
	}
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := gw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	// Direct unit test of decodeOne. Returns errDecompressedTooLarge
	// because the decompressed output exceeds maxProxyBody.
	out, err := decodeOne(buf.Bytes(), "gzip")
	if err == nil {
		t.Fatalf("decodeOne returned no error for oversized decompressed output (got %d bytes)", len(out))
	}
	if !errors.Is(err, errDecompressedTooLarge) {
		t.Errorf("decodeOne error = %v, want errDecompressedTooLarge", err)
	}
	if out != nil {
		t.Errorf("decodeOne returned non-nil bytes on error: %d bytes", len(out))
	}
}

// TestDecodeOne_DeflatePrefersZlib verifies that decodeOne uses the
// zlib decoder for `Content-Encoding: deflate` per RFC 9110 Section
// 8.4.1, with raw RFC 1951 DEFLATE as the fallback. We feed both
// forms and confirm both decode. The fallback is gated on the
// zlib.ErrHeader sentinel so an unrelated zlib failure (corrupted
// trailer, etc) is not silently masked into a flate decode.
func TestDecodeOne_DeflatePrefersZlib(t *testing.T) {
	raw := []byte(`{"data":"plaintext"}`)

	// zlib-wrapped form (standards-compliant).
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	// Raw RFC 1951 DEFLATE (the historical-misuse form).
	var fbuf bytes.Buffer
	fw, err := flate.NewWriter(&fbuf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := fw.Write(raw); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"zlib_wrapped", zbuf.Bytes()},
		{"raw_deflate", fbuf.Bytes()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeOne(tc.body, "deflate")
			if err != nil {
				t.Fatalf("decodeOne(%q): %v", tc.name, err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("decodeOne(%q) = %q, want %q", tc.name, got, raw)
			}
		})
	}
}
