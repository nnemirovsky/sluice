package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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
