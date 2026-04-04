package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/vault"
)

func setupTestInjector(t *testing.T, bindings []vault.Binding) (*Injector, *vault.Store) {
	t.Helper()
	return setupTestInjectorWithWS(t, bindings, nil, nil)
}

func setupTestInjectorWithWS(
	t *testing.T,
	bindings []vault.Binding,
	blockRules []WSBlockRuleConfig,
	redactRules []WSRedactRuleConfig,
) (*Injector, *vault.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	var wsProxy *WSProxy
	if blockRules != nil || redactRules != nil {
		wsProxy, err = NewWSProxy(store, &resolverPtr, blockRules, redactRules)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		wsProxy, _ = NewWSProxy(store, &resolverPtr, nil, nil)
	}

	return NewInjector(store, &resolverPtr, caCert, "", wsProxy), store
}

func TestPhantomSwapInHeaders(t *testing.T) {
	var mu sync.Mutex
	var received http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination: backendURL.Hostname(),
		Credential:  "api_key",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("api_key", "sk-real-secret-12345"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantom := PhantomToken("api_key")
	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+phantom)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	auth := received.Get("Authorization")
	if strings.Contains(auth, phantom) {
		t.Error("phantom token was not replaced in header")
	}
	if auth != "Bearer sk-real-secret-12345" {
		t.Errorf("expected 'Bearer sk-real-secret-12345', got %q", auth)
	}
}

func TestPhantomSwapInBody(t *testing.T) {
	var mu sync.Mutex
	var receivedBody string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination: backendURL.Hostname(),
		Credential:  "api_key",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("api_key", "sk-real-secret-12345"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantom := PhantomToken("api_key")
	bodyStr := `{"key": "` + phantom + `", "data": "hello"}`
	req, _ := http.NewRequest("POST", backend.URL+"/test", strings.NewReader(bodyStr))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if strings.Contains(receivedBody, phantom) {
		t.Error("phantom token was not replaced in body")
	}
	expected := `{"key": "sk-real-secret-12345", "data": "hello"}`
	if receivedBody != expected {
		t.Errorf("expected %q, got %q", expected, receivedBody)
	}
}

func TestHeaderInjectionViaBindingHeader(t *testing.T) {
	var mu sync.Mutex
	var received http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination:  backendURL.Hostname(),
		Credential:   "temp_key",
		Header: "X-Api-Key",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("temp_key", "secret-that-should-be-zeroed"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	got := received.Get("X-Api-Key")
	if got != "secret-that-should-be-zeroed" {
		t.Errorf("expected injected credential, got %q", got)
	}
}

func TestHeaderInjectionWithTemplate(t *testing.T) {
	var mu sync.Mutex
	var received http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination:  backendURL.Hostname(),
		Credential:   "github_token",
		Header: "Authorization",
		Template:     "Bearer {value}",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("github_token", "ghp_abc123"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/api/repos", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	auth := received.Get("Authorization")
	if auth != "Bearer ghp_abc123" {
		t.Errorf("expected 'Bearer ghp_abc123', got %q", auth)
	}
}

func TestNoInjectionWithoutBinding(t *testing.T) {
	var mu sync.Mutex
	var received http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	// No bindings configured.
	inj, _ := setupTestInjector(t, nil)

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("Authorization", "original-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	auth := received.Get("Authorization")
	if auth != "original-value" {
		t.Errorf("expected original header preserved, got %q", auth)
	}
}

func TestMITMHTTPS(t *testing.T) {
	var mu sync.Mutex
	var received http.Header

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination:  backendURL.Hostname(),
		Credential:   "tls_key",
		Header: "X-Secret",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("tls_key", "tls-injected-value"); err != nil {
		t.Fatal(err)
	}

	// The proxy must skip TLS verification when connecting to the test
	// backend (which uses a self-signed cert from httptest).
	inj.Proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	// Build a client that trusts the injector's MITM CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(inj.caCert.Leaf)

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/secure", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	got := received.Get("X-Secret")
	if got != "tls-injected-value" {
		t.Errorf("expected 'tls-injected-value', got %q", got)
	}
}

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()

	// First call generates a new CA.
	cert1, x509Cert1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !x509Cert1.IsCA {
		t.Error("expected CA cert")
	}
	if x509Cert1.Subject.CommonName != "Sluice CA" {
		t.Errorf("unexpected CN: %s", x509Cert1.Subject.CommonName)
	}

	// Second call loads from disk.
	cert2, x509Cert2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if x509Cert1.SerialNumber.Cmp(x509Cert2.SerialNumber) != 0 {
		t.Error("expected same serial number on reload")
	}
	if len(cert1.Certificate) != len(cert2.Certificate) {
		t.Error("expected same cert chain on reload")
	}
}

func TestPhantomToken(t *testing.T) {
	token := PhantomToken("my_api_key")
	if token != "SLUICE_PHANTOM:my_api_key" {
		t.Errorf("unexpected phantom token: %s", token)
	}
}

func TestPhantomStripHyphenatedCredentialName(t *testing.T) {
	var mu sync.Mutex
	var receivedBody string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	// No bindings. Hyphenated credential name must be fully stripped.
	inj, store := setupTestInjector(t, nil)
	if _, err := store.Add("my-api-key", "real-value"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantom := PhantomToken("my-api-key")
	bodyStr := `{"token": "` + phantom + `"}`
	req, _ := http.NewRequest("POST", backend.URL+"/test", strings.NewReader(bodyStr))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if strings.Contains(receivedBody, "SLUICE_PHANTOM") {
		t.Error("phantom token prefix leaked in body")
	}
	if strings.Contains(receivedBody, "-api-key") {
		t.Error("partial phantom token suffix leaked in body")
	}
	expected := `{"token": ""}`
	if receivedBody != expected {
		t.Errorf("body: expected %q, got %q", expected, receivedBody)
	}
}

func TestGlobalPhantomReplacementWithoutBinding(t *testing.T) {
	var mu sync.Mutex
	var receivedBody string
	var receivedHeaders http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	// No bindings configured. The host has no binding match.
	inj, store := setupTestInjector(t, nil)
	if _, err := store.Add("api_key", "sk-real-secret-12345"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantom := PhantomToken("api_key")

	// Send phantom in body.
	bodyStr := `{"token": "` + phantom + `"}`
	req, _ := http.NewRequest("POST", backend.URL+"/unbound", strings.NewReader(bodyStr))
	// Also send phantom in a header.
	req.Header.Set("X-Custom", "prefix-"+phantom+"-suffix")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if strings.Contains(receivedBody, phantom) {
		t.Error("phantom token leaked in body to unbound host")
	}
	// Unbound phantom tokens are stripped (not replaced with real values)
	// to prevent cross-credential exfiltration.
	expected := `{"token": ""}`
	if receivedBody != expected {
		t.Errorf("body: expected %q, got %q", expected, receivedBody)
	}

	customHeader := receivedHeaders.Get("X-Custom")
	if strings.Contains(customHeader, phantom) {
		t.Error("phantom token leaked in header to unbound host")
	}
	if customHeader != "prefix--suffix" {
		t.Errorf("header: expected %q, got %q", "prefix--suffix", customHeader)
	}
}

func TestBindingHeaderInjectionAndGlobalPhantomReplacement(t *testing.T) {
	var mu sync.Mutex
	var receivedBody string
	var receivedHeaders http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination:  backendURL.Hostname(),
		Credential:   "api_key",
		Header: "X-Api-Key",
		Template:     "Bearer {value}",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("api_key", "sk-real-secret-12345"); err != nil {
		t.Fatal(err)
	}
	// Add a second credential that has no binding but may appear in traffic.
	if _, err := store.Add("other_key", "other-real-value"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantomAPI := PhantomToken("api_key")
	phantomOther := PhantomToken("other_key")

	// Body contains both phantom tokens.
	bodyStr := `{"key": "` + phantomAPI + `", "other": "` + phantomOther + `"}`
	req, _ := http.NewRequest("POST", backend.URL+"/test", strings.NewReader(bodyStr))
	// Also send a phantom in a custom header.
	req.Header.Set("X-Ref", phantomOther)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	// Verify binding-specific header injection.
	apiKey := receivedHeaders.Get("X-Api-Key")
	if apiKey != "Bearer sk-real-secret-12345" {
		t.Errorf("X-Api-Key: expected %q, got %q", "Bearer sk-real-secret-12345", apiKey)
	}

	// Verify bound phantom replaced in body, unbound phantom stripped.
	if strings.Contains(receivedBody, phantomAPI) {
		t.Error("api_key phantom leaked in body")
	}
	if strings.Contains(receivedBody, phantomOther) {
		t.Error("other_key phantom leaked in body")
	}
	// Bound credential (api_key) is replaced with real value.
	// Unbound credential (other_key) is stripped to prevent cross-credential
	// exfiltration to unintended destinations.
	expectedBody := `{"key": "sk-real-secret-12345", "other": ""}`
	if receivedBody != expectedBody {
		t.Errorf("body: expected %q, got %q", expectedBody, receivedBody)
	}

	// Verify unbound phantom stripped in header (not replaced with real value).
	refHeader := receivedHeaders.Get("X-Ref")
	if strings.Contains(refHeader, phantomOther) {
		t.Error("other_key phantom leaked in X-Ref header")
	}
	if refHeader != "" {
		t.Errorf("X-Ref: expected empty (stripped), got %q", refHeader)
	}
}

func TestPhantomPrefixMatchOrdering(t *testing.T) {
	// Verify that SLUICE_PHANTOM:api_key does not corrupt
	// SLUICE_PHANTOM:api_key_v2 via substring match.
	var mu sync.Mutex
	var receivedBody string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{
		{Destination: backendURL.Hostname(), Credential: "api_key"},
		{Destination: backendURL.Hostname(), Credential: "api_key_v2"},
	}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("api_key", "secret-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("api_key_v2", "secret-v2"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantomV1 := PhantomToken("api_key")
	phantomV2 := PhantomToken("api_key_v2")

	bodyStr := `{"v1": "` + phantomV1 + `", "v2": "` + phantomV2 + `"}`
	req, _ := http.NewRequest("POST", backend.URL+"/test", strings.NewReader(bodyStr))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	expected := `{"v1": "secret-v1", "v2": "secret-v2"}`
	if receivedBody != expected {
		t.Errorf("body: expected %q, got %q", expected, receivedBody)
	}
}

func TestPhantomReplacementInURLQuery(t *testing.T) {
	var mu sync.Mutex
	var receivedQuery string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedQuery = r.URL.RawQuery
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination: backendURL.Hostname(),
		Credential:  "api_key",
	}}

	inj, store := setupTestInjector(t, bindings)
	if _, err := store.Add("api_key", "sk-real-secret-12345"); err != nil {
		t.Fatal(err)
	}
	// Unbound credential that should be stripped in URL.
	if _, err := store.Add("other_key", "other-real-value"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	phantomAPI := PhantomToken("api_key")
	phantomOther := PhantomToken("other_key")

	// Bound phantom in query: replaced with real value.
	// Unbound phantom in query: stripped.
	targetURL := backend.URL + "/test?token=" + phantomAPI + "&other=" + phantomOther
	req, _ := http.NewRequest("GET", targetURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if strings.Contains(receivedQuery, "SLUICE_PHANTOM") {
		t.Errorf("phantom token leaked in URL query: %s", receivedQuery)
	}
	// Bound phantom should be replaced with real value.
	if !strings.Contains(receivedQuery, "sk-real-secret-12345") {
		t.Errorf("bound phantom not replaced in query: %s", receivedQuery)
	}
	// Unbound phantom should be stripped (empty).
	expectedQ := "token=sk-real-secret-12345&other="
	if receivedQuery != expectedQ {
		t.Errorf("query: expected %q, got %q", expectedQ, receivedQuery)
	}
}

// wsEchoServer creates an httptest.Server that accepts WebSocket upgrades
// via manual hijacking and echoes text frames. The receivedPayloads channel
// receives unmasked payloads of text frames the server reads.
func wsEchoServer(t *testing.T, receivedPayloads chan<- string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		// Write 101 Switching Protocols response.
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		bufrw.WriteString("Upgrade: websocket\r\n")
		bufrw.WriteString("Connection: Upgrade\r\n")
		bufrw.WriteString("\r\n")
		bufrw.Flush()

		for {
			frame, readErr := ReadFrame(conn)
			if readErr != nil {
				return
			}
			if frame.Opcode == OpcodeClose {
				sendCloseFrame(conn, 1000, "bye")
				return
			}
			if frame.Opcode == OpcodeText {
				payload := frame.UnmaskedPayload()
				if receivedPayloads != nil {
					receivedPayloads <- string(payload)
				}
				// Echo the payload back.
				resp := &Frame{FIN: true, Opcode: OpcodeText}
				resp.SetPayload(payload)
				if writeErr := WriteFrame(conn, resp); writeErr != nil {
					return
				}
			}
		}
	}))
}

// wsClientUpgrade connects to the proxy as an HTTP forward proxy client,
// sends a WebSocket upgrade request to the given backend URL, reads the
// 101 response, and returns the raw connection for frame-level I/O.
func wsClientUpgrade(t *testing.T, proxyAddr, backendURL string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	u, _ := url.Parse(backendURL)
	req := fmt.Sprintf(
		"GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		backendURL, u.Host,
	)
	if _, wErr := conn.Write([]byte(req)); wErr != nil {
		conn.Close()
		t.Fatalf("write upgrade request: %v", wErr)
	}

	br := bufio.NewReader(conn)
	resp, rErr := http.ReadResponse(br, &http.Request{Method: "GET"})
	if rErr != nil {
		conn.Close()
		t.Fatalf("read upgrade response: %v", rErr)
	}
	if resp.StatusCode != 101 {
		conn.Close()
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	// Wrap the connection so reads go through the buffered reader
	// (which may have consumed bytes past the HTTP headers).
	if br.Buffered() > 0 {
		return &bufferedConn{Reader: br, Conn: conn}
	}

	// Brief pause so goproxy finishes hijacking the server-side connection
	// and starts its WebSocket relay goroutines. Without this, frame data
	// sent immediately can be consumed by Go's http.Server bufio.Reader
	// and lost when goproxy discards the bufio.ReadWriter from Hijack().
	time.Sleep(50 * time.Millisecond)

	return conn
}

func TestWSMITM_PhantomTokenReplacement(t *testing.T) {
	received := make(chan string, 1)
	backend := wsEchoServer(t, received)
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	bindings := []vault.Binding{{
		Destination: backendURL.Hostname(),
		Credential:  "api_key",
	}}

	inj, store := setupTestInjectorWithWS(t, bindings, nil, nil)
	if _, err := store.Add("api_key", "sk-real-secret-12345"); err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyAddr := proxyServer.Listener.Addr().String()
	wsConn := wsClientUpgrade(t, proxyAddr, backend.URL)
	defer wsConn.Close()

	// Send text frame with phantom token.
	phantom := PhantomToken("api_key")
	msg := `{"authorization": "` + phantom + `"}`
	sendFrame := &Frame{FIN: true, Opcode: OpcodeText, Masked: true, MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78}}
	sendFrame.SetPayload([]byte(msg))
	if err := WriteFrame(wsConn, sendFrame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	// Verify upstream received the real credential (not phantom).
	select {
	case payload := <-received:
		if strings.Contains(payload, "SLUICE_PHANTOM") {
			t.Error("phantom token was not replaced in WebSocket text frame")
		}
		expected := `{"authorization": "sk-real-secret-12345"}`
		if payload != expected {
			t.Errorf("upstream received %q, want %q", payload, expected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for upstream to receive frame")
	}

	// Read the echo response from upstream (through the proxy).
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respFrame, err := ReadFrame(wsConn)
	if err != nil {
		t.Fatalf("read echo frame: %v", err)
	}
	if respFrame.Opcode != OpcodeText {
		t.Errorf("expected text frame echo, got opcode %d", respFrame.Opcode)
	}

	// Clean up.
	sendCloseFrame(wsConn, 1000, "done")
}

func TestWSMITM_ContentRedaction(t *testing.T) {
	// Backend that sends a text frame containing a sensitive API key.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		bufrw.WriteString("Upgrade: websocket\r\n")
		bufrw.WriteString("Connection: Upgrade\r\n")
		bufrw.WriteString("\r\n")
		bufrw.Flush()

		// Wait for the client's initial frame (handshake confirmation).
		frame, readErr := ReadFrame(conn)
		if readErr != nil {
			return
		}
		_ = frame

		// Send a response containing a sensitive API key.
		respMsg := `{"api_key": "sk-abcdefghijklmnopqrstuvwxyz12345"}`
		resp := &Frame{FIN: true, Opcode: OpcodeText}
		resp.SetPayload([]byte(respMsg))
		WriteFrame(conn, resp)

		// Wait for close.
		for {
			f, err := ReadFrame(conn)
			if err != nil || f.Opcode == OpcodeClose {
				sendCloseFrame(conn, 1000, "bye")
				return
			}
		}
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	inj, _ := setupTestInjectorWithWS(t, nil,
		nil,
		[]WSRedactRuleConfig{{
			Pattern:     `sk-[a-zA-Z0-9_-]{20,}`,
			Replacement: "[REDACTED_API_KEY]",
			Name:        "api key in response",
		}},
	)
	// Ensure the proxy is not nil even without bindings.
	_ = backendURL

	proxyServer := httptest.NewServer(inj.Proxy)
	defer proxyServer.Close()

	proxyAddr := proxyServer.Listener.Addr().String()
	wsConn := wsClientUpgrade(t, proxyAddr, backend.URL)
	defer wsConn.Close()

	// Send a text frame to trigger the backend's response.
	initFrame := &Frame{FIN: true, Opcode: OpcodeText, Masked: true, MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD}}
	initFrame.SetPayload([]byte("hello"))
	if err := WriteFrame(wsConn, initFrame); err != nil {
		t.Fatalf("write init frame: %v", err)
	}

	// Read the response frame. The API key should be redacted.
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respFrame, err := ReadFrame(wsConn)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	if respFrame.Opcode != OpcodeText {
		t.Errorf("expected text frame, got opcode %d", respFrame.Opcode)
	}

	payload := string(respFrame.UnmaskedPayload())
	if strings.Contains(payload, "sk-abcdefghijklmnopqrstuvwxyz12345") {
		t.Error("API key was not redacted in WebSocket response frame")
	}
	expected := `{"api_key": "[REDACTED_API_KEY]"}`
	if !bytes.Equal([]byte(payload), []byte(expected)) {
		t.Errorf("payload: got %q, want %q", payload, expected)
	}

	sendCloseFrame(wsConn, 1000, "done")
}
