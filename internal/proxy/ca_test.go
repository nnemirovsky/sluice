package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGenerateCA_CertFields(t *testing.T) {
	_, cert, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Error("expected IsCA to be true")
	}
	if cert.Subject.CommonName != "Sluice CA" {
		t.Errorf("expected CN 'Sluice CA', got %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Sluice Proxy" {
		t.Errorf("unexpected Organization: %v", cert.Subject.Organization)
	}
	if !cert.BasicConstraintsValid {
		t.Error("expected BasicConstraintsValid to be true")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Error("expected MaxPathLen=0 with MaxPathLenZero=true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("expected KeyUsageCRLSign")
	}
}

func TestGenerateCA_KeyType(t *testing.T) {
	tlsCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	key, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", tlsCert.PrivateKey)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", key.Curve.Params().Name)
	}
}

func TestGenerateCA_ValidityPeriod(t *testing.T) {
	_, cert, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	// NotBefore should be about 1 hour ago.
	expectedNotBefore := time.Now().Add(-time.Hour)
	if cert.NotBefore.Before(expectedNotBefore.Add(-time.Minute)) || cert.NotBefore.After(expectedNotBefore.Add(time.Minute)) {
		t.Errorf("NotBefore %v not within 1 minute of expected %v", cert.NotBefore, expectedNotBefore)
	}

	// NotAfter should be about 2 years from now (not 10).
	expectedNotAfter := time.Now().Add(2 * 365 * 24 * time.Hour)
	if cert.NotAfter.Before(expectedNotAfter.Add(-time.Minute)) || cert.NotAfter.After(expectedNotAfter.Add(time.Minute)) {
		t.Errorf("NotAfter %v not within 1 minute of expected %v", cert.NotAfter, expectedNotAfter)
	}

	// Explicitly check it's NOT 10 years.
	tenYears := time.Now().Add(10 * 365 * 24 * time.Hour)
	if cert.NotAfter.After(tenYears.Add(-24 * time.Hour)) {
		t.Error("CA cert validity should be 2 years, not 10")
	}
}

func TestGenerateCA_UniqueSerials(t *testing.T) {
	_, cert1, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	_, cert2, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Error("two generated CAs should have different serial numbers")
	}
}

func TestIsCACertExpiring_Valid(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca-cert.pem")

	// Create a cert that expires in 1 year (well within any reasonable threshold).
	writeCertWithExpiry(t, certPath, time.Now().Add(365*24*time.Hour))

	expiring, err := IsCACertExpiring(certPath, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if expiring {
		t.Error("cert expiring in 1 year should not be flagged with 30-day threshold")
	}
}

func TestIsCACertExpiring_ExpiringSoon(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca-cert.pem")

	// Create a cert that expires in 15 days.
	writeCertWithExpiry(t, certPath, time.Now().Add(15*24*time.Hour))

	expiring, err := IsCACertExpiring(certPath, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !expiring {
		t.Error("cert expiring in 15 days should be flagged with 30-day threshold")
	}
}

func TestIsCACertExpiring_AlreadyExpired(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca-cert.pem")

	// Create an already-expired cert.
	writeCertWithExpiry(t, certPath, time.Now().Add(-24*time.Hour))

	expiring, err := IsCACertExpiring(certPath, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !expiring {
		t.Error("already-expired cert should be flagged")
	}
}

func TestIsCACertExpiring_FileNotFound(t *testing.T) {
	_, err := IsCACertExpiring("/nonexistent/path/ca-cert.pem", 30*24*time.Hour)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestIsCACertExpiring_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(certPath, []byte("not a pem file"), 0o644)

	_, err := IsCACertExpiring(certPath, 30*24*time.Hour)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadOrCreateCA_ConcurrentCalls(t *testing.T) {
	dir := t.TempDir()

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	type result struct {
		serial *big.Int
		err    error
	}
	results := make([]result, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, cert, err := LoadOrCreateCA(dir)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			results[idx] = result{serial: cert.SerialNumber}
		}(i)
	}
	wg.Wait()

	// All should succeed and produce the same serial (same CA loaded from disk).
	var firstSerial *big.Int
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("goroutine %d failed: %v", i, r.err)
		}
		if firstSerial == nil {
			firstSerial = r.serial
		} else if firstSerial.Cmp(r.serial) != 0 {
			t.Errorf("goroutine %d got different serial: %v vs %v", i, r.serial, firstSerial)
		}
	}

	// Verify the files exist and are valid.
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("ca-cert.pem not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("ca-key.pem not found: %v", err)
	}
}

func TestGenerateHostCert_ChainVerification(t *testing.T) {
	caCert, caCertX509, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	hostCert, err := GenerateHostCert(caCert, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(hostCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("expected CN 'example.com', got %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("unexpected DNSNames: %v", leaf.DNSNames)
	}
	if leaf.IsCA {
		t.Error("host cert should not be a CA")
	}

	// Verify the chain: host cert should be signed by the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCertX509)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("host cert chain verification failed: %v", err)
	}
}

// writeCertWithExpiry creates a self-signed cert that expires at the given time.
func writeCertWithExpiry(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAtomicWriteFile verifies atomic file writing.
func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if err := atomicWriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Errorf("got %q, want %q", string(data), "hello world")
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %o, want 0600", info.Mode().Perm())
	}
}

// TestAtomicWriteFileOverwrite verifies that overwriting an existing file works.
func TestAtomicWriteFileOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	_ = os.WriteFile(path, []byte("old content"), 0o644)

	if err := atomicWriteFile(path, []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "new content" {
		t.Errorf("got %q, want %q", string(data), "new content")
	}
}

// TestAtomicWriteFileInvalidDir verifies error on nonexistent directory.
func TestAtomicWriteFileInvalidDir(t *testing.T) {
	err := atomicWriteFile("/nonexistent/dir/file.txt", []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

// TestGenerateHostCertBasic verifies host certificate generation.
func TestGenerateHostCertBasic(t *testing.T) {
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	hostCert, err := GenerateHostCert(caCert, "example.com")
	if err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	if hostCert.Certificate == nil {
		t.Fatal("expected non-nil certificate")
	}

	// Parse the leaf and verify it's for the right host.
	leaf, err := x509.ParseCertificate(hostCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "example.com")
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("SAN = %v, want [example.com]", leaf.DNSNames)
	}
}

// TestGenerateHostCertIPAddress verifies host cert for IP address.
func TestGenerateHostCertIPAddress(t *testing.T) {
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	hostCert, err := GenerateHostCert(caCert, "192.168.1.1")
	if err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	leaf, _ := x509.ParseCertificate(hostCert.Certificate[0])
	// GenerateHostCert uses DNSNames for all hosts including IPs.
	if leaf.Subject.CommonName != "192.168.1.1" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "192.168.1.1")
	}
}
