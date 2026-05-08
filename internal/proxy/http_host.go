package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
)

// peekHTTPHost reads enough bytes from r to parse the HTTP/1.x request line
// and Host header, returning the peeked buffer and the host. Like peekSNI
// but for plain HTTP (e.g. ports 80, 8080). The caller prepends the buffer
// to subsequent reads so the upstream sees the full request.
//
// Returns an empty host when the bytes are not a valid HTTP/1.x request
// (binary protocol, partial data, malformed). In that case the caller should
// fall back to IP-based policy. Reads are bounded by maxBytes to avoid
// hanging on slow clients or very long header sets.
func peekHTTPHost(r io.Reader, maxBytes int) ([]byte, string, error) {
	buf := make([]byte, 0, maxBytes)
	tmp := make([]byte, 4096)

	for len(buf) < maxBytes {
		// Cap each read so a single big chunk does not push buf
		// past maxBytes.
		want := maxBytes - len(buf)
		if want > len(tmp) {
			want = len(tmp)
		}
		n, err := r.Read(tmp[:want])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		// Quick reject: HTTP/1.x request lines start with a method like
		// GET/POST/HEAD/etc. Method tokens are uppercase ASCII letters.
		// If the first byte is not in the [A-Z] range, this is not HTTP.
		// Returning early on the first read avoids waiting maxBytes worth
		// of data for a binary protocol that happens to be on port 80.
		if len(buf) >= 1 && (buf[0] < 'A' || buf[0] > 'Z') {
			return buf, "", nil
		}
		// Look for end of headers. http.ReadRequest needs the full header
		// section before it returns; calling it on partial data yields
		// io.ErrUnexpectedEOF, which we treat as "keep reading".
		if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
			host, ok := extractHTTPHost(buf[:idx+4])
			if ok {
				return buf, host, nil
			}
			return buf, "", nil
		}
		if err != nil {
			if len(buf) > 0 {
				return buf, "", nil
			}
			return nil, "", err
		}
	}
	return buf, "", nil
}

// extractHTTPHost parses an HTTP/1.x request prefix terminated by \r\n\r\n
// and returns the Host header value with any port stripped. The fast-path
// uses net/http's parser, which handles obs-fold, mixed case, multiple
// Host header rules, and request-line validation in one pass.
func extractHTTPHost(prefix []byte) (string, bool) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(prefix)))
	if err != nil {
		return "", false
	}
	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	// net.SplitHostPort handles every shape Host can legitimately
	// take: "example.com:80" -> ("example.com", "80"),
	// "[::1]:80" -> ("::1", "80"), "[::1]" with no port -> error,
	// and bare IPv6 like "2001:db8::1" -> error ("too many colons").
	// Falling back to the trimmed host on error avoids the previous
	// LastIndex(":") approach that mishandled bare IPv6 by stripping
	// the final hextet as if it were a port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" {
		return "", false
	}
	return host, true
}
