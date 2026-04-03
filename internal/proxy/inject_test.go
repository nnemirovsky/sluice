package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nemirovsky/sluice/internal/vault"
)

func setupTestInjector(t *testing.T, bindings []vault.Binding) (*Injector, *vault.Store) {
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
	return NewInjector(store, &resolverPtr, caCert, ""), store
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
	resp.Body.Close()

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
	resp.Body.Close()

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

func TestHeaderInjectionViaInjectHeader(t *testing.T) {
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
		InjectHeader: "X-Api-Key",
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
	resp.Body.Close()

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
		InjectHeader: "Authorization",
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
	resp.Body.Close()

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
	resp.Body.Close()

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
		InjectHeader: "X-Secret",
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
	resp.Body.Close()

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
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if strings.Contains(receivedBody, phantom) {
		t.Error("phantom token leaked in body to unbound host")
	}
	expected := `{"token": "sk-real-secret-12345"}`
	if receivedBody != expected {
		t.Errorf("body: expected %q, got %q", expected, receivedBody)
	}

	customHeader := receivedHeaders.Get("X-Custom")
	if strings.Contains(customHeader, phantom) {
		t.Error("phantom token leaked in header to unbound host")
	}
	if customHeader != "prefix-sk-real-secret-12345-suffix" {
		t.Errorf("header: expected %q, got %q", "prefix-sk-real-secret-12345-suffix", customHeader)
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
		InjectHeader: "X-Api-Key",
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
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	// Verify binding-specific header injection.
	apiKey := receivedHeaders.Get("X-Api-Key")
	if apiKey != "Bearer sk-real-secret-12345" {
		t.Errorf("X-Api-Key: expected %q, got %q", "Bearer sk-real-secret-12345", apiKey)
	}

	// Verify global phantom replacement in body.
	if strings.Contains(receivedBody, phantomAPI) {
		t.Error("api_key phantom leaked in body")
	}
	if strings.Contains(receivedBody, phantomOther) {
		t.Error("other_key phantom leaked in body")
	}
	expectedBody := `{"key": "sk-real-secret-12345", "other": "other-real-value"}`
	if receivedBody != expectedBody {
		t.Errorf("body: expected %q, got %q", expectedBody, receivedBody)
	}

	// Verify global phantom replacement in header.
	refHeader := receivedHeaders.Get("X-Ref")
	if strings.Contains(refHeader, phantomOther) {
		t.Error("other_key phantom leaked in X-Ref header")
	}
	if refHeader != "other-real-value" {
		t.Errorf("X-Ref: expected %q, got %q", "other-real-value", refHeader)
	}
}
