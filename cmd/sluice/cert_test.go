package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/proxy"
)

func TestCertGenerate(t *testing.T) {
	dir := t.TempDir()

	// Generate CA cert and key.
	tlsCert, x509Cert, err := proxy.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	// Verify the cert is a valid CA.
	if !x509Cert.IsCA {
		t.Error("generated cert should be a CA")
	}
	if x509Cert.Subject.CommonName != "Sluice CA" {
		t.Errorf("unexpected CN: %s", x509Cert.Subject.CommonName)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Error("no certificates in TLS cert")
	}

	// Verify files were written.
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read ca-cert.pem: %v", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read ca-key.pem: %v", err)
	}

	// Verify PEM format.
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		t.Fatal("ca-cert.pem is not valid PEM")
	}
	if certBlock.Type != "CERTIFICATE" {
		t.Errorf("unexpected PEM type: %s", certBlock.Type)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		t.Fatal("ca-key.pem is not valid PEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("unexpected key PEM type: %s", keyBlock.Type)
	}

	// Verify the cert can be parsed from the PEM file.
	parsed, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse cert from PEM: %v", err)
	}
	if !parsed.IsCA {
		t.Error("parsed cert should be CA")
	}
}

func TestCertGenerateIdempotent(t *testing.T) {
	dir := t.TempDir()

	// First generation.
	_, cert1, err := proxy.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}

	// Second call should load the existing cert, not create a new one.
	_, cert2, err := proxy.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Error("serial numbers should match on second call (idempotent)")
	}
}

func TestCertGeneratePermissions(t *testing.T) {
	dir := t.TempDir()

	_, _, err := proxy.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	// Key file should have restricted permissions (0600).
	keyPath := filepath.Join(dir, "ca-key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat ca-key.pem: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("ca-key.pem permissions: %o, want 0600", perm)
	}

	// Cert file should be readable (0644).
	certPath := filepath.Join(dir, "ca-cert.pem")
	info, err = os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat ca-cert.pem: %v", err)
	}
	perm = info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("ca-cert.pem permissions: %o, want 0644", perm)
	}
}

// --- Handler-level tests ---

func TestHandleCertGenerateCreatesFiles(t *testing.T) {
	dir := t.TempDir()

	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	if err := handleCertGenerate([]string{"--out", dir}); err != nil {
		t.Fatalf("handleCertGenerate: %v", err)
	}

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, "CA certificate:") {
		t.Errorf("expected 'CA certificate:' in output: %s", output)
	}
	if !strings.Contains(output, "CA private key:") {
		t.Errorf("expected 'CA private key:' in output: %s", output)
	}
	if !strings.Contains(output, "ca-cert.pem") {
		t.Errorf("expected cert path in output: %s", output)
	}

	// Verify files exist.
	if _, err := os.Stat(filepath.Join(dir, "ca-cert.pem")); err != nil {
		t.Errorf("ca-cert.pem not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); err != nil {
		t.Errorf("ca-key.pem not created: %v", err)
	}
}

func TestHandleCertGenerateIdempotentViaHandler(t *testing.T) {
	dir := t.TempDir()

	// First call.
	oldStdout := os.Stdout
	_, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	if err := handleCertGenerate([]string{"--out", dir}); err != nil {
		os.Stdout = oldStdout
		t.Fatalf("first handleCertGenerate: %v", err)
	}
	_ = outW.Close()
	os.Stdout = oldStdout

	// Get serial of first cert.
	certData1, _ := os.ReadFile(filepath.Join(dir, "ca-cert.pem"))
	block1, _ := pem.Decode(certData1)
	cert1, _ := x509.ParseCertificate(block1.Bytes)

	// Second call.
	_, outW2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW2
	if err := handleCertGenerate([]string{"--out", dir}); err != nil {
		os.Stdout = oldStdout
		t.Fatalf("second handleCertGenerate: %v", err)
	}
	_ = outW2.Close()
	os.Stdout = oldStdout

	// Get serial of second cert.
	certData2, _ := os.ReadFile(filepath.Join(dir, "ca-cert.pem"))
	block2, _ := pem.Decode(certData2)
	cert2, _ := x509.ParseCertificate(block2.Bytes)

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Error("serial numbers should match on second call (idempotent)")
	}
}

func TestHandleCertCommandNoArgs(t *testing.T) {
	err := handleCertCommand([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestHandleCertCommandUnknown(t *testing.T) {
	err := handleCertCommand([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown cert command") {
		t.Errorf("expected 'unknown cert command' in error, got: %v", err)
	}
}

func TestHandleCertGenerateWithEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SLUICE_VAULT_DIR", dir)

	oldStdout := os.Stdout
	_, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	if err := handleCertGenerate([]string{}); err != nil {
		os.Stdout = oldStdout
		t.Fatalf("handleCertGenerate with env: %v", err)
	}
	_ = outW.Close()
	os.Stdout = oldStdout

	if _, err := os.Stat(filepath.Join(dir, "ca-cert.pem")); err != nil {
		t.Errorf("ca-cert.pem not created in SLUICE_VAULT_DIR: %v", err)
	}
}
