package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreateCA loads a CA certificate and key from dir, or generates a new
// self-signed CA if none exists. The CA is used for HTTPS MITM to generate
// per-host certificates. Uses ECDSA P-256.
func LoadOrCreateCA(dir string) (tls.Certificate, *x509.Certificate, error) {
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		x509Cert, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr != nil {
			return tls.Certificate{}, nil, fmt.Errorf("parse existing CA cert: %w", parseErr)
		}
		cert.Leaf = x509Cert
		return cert, x509Cert, nil
	}

	// Only generate a new CA if the files don't exist. If they exist but
	// are corrupted or unreadable, return the error instead of silently
	// overwriting.
	if !os.IsNotExist(err) {
		// tls.LoadX509KeyPair may wrap the underlying error. Check both
		// cert and key individually to distinguish missing from corrupt.
		_, certStatErr := os.Stat(certPath)
		_, keyStatErr := os.Stat(keyPath)
		if certStatErr == nil || keyStatErr == nil {
			// At least one file exists but the pair failed to load.
			return tls.Certificate{}, nil, fmt.Errorf("load existing CA: %w", err)
		}
	}

	if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create CA dir: %w", mkErr)
	}

	tlsCert, x509Cert, genErr := GenerateCA()
	if genErr != nil {
		return tls.Certificate{}, nil, genErr
	}

	keyDER, marshalErr := x509.MarshalECPrivateKey(tlsCert.PrivateKey.(*ecdsa.PrivateKey))
	if marshalErr != nil {
		return tls.Certificate{}, nil, fmt.Errorf("marshal CA key: %w", marshalErr)
	}
	// Write key first. If the cert write fails afterward, the orphaned key
	// is less problematic than an orphaned cert (the missing cert causes
	// LoadX509KeyPair to fail, and the stat check detects only one file).
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if writeErr := os.WriteFile(keyPath, keyPEM, 0600); writeErr != nil {
		return tls.Certificate{}, nil, fmt.Errorf("write CA key: %w", writeErr)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})
	if writeErr := os.WriteFile(certPath, certPEM, 0644); writeErr != nil {
		os.Remove(keyPath)
		return tls.Certificate{}, nil, fmt.Errorf("write CA cert: %w", writeErr)
	}

	return tlsCert, x509Cert, nil
}

// GenerateCA creates a new self-signed CA certificate and key in memory.
func GenerateCA() (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sluice Proxy"},
			CommonName:   "Sluice CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create CA cert: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        x509Cert,
	}, x509Cert, nil
}

// GenerateHostCert creates a TLS certificate for the given hostname, signed
// by the provided CA. Used for MITM on mail protocols (IMAPS/SMTPS) where
// the proxy terminates TLS from the agent and re-establishes it to upstream.
func GenerateHostCert(caCert tls.Certificate, host string) (tls.Certificate, error) {
	caX509 := caCert.Leaf
	if caX509 == nil {
		var parseErr error
		caX509, parseErr = x509.ParseCertificate(caCert.Certificate[0])
		if parseErr != nil {
			return tls.Certificate{}, fmt.Errorf("parse CA cert: %w", parseErr)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate host key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sluice Proxy"},
			CommonName:   host,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{host},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caX509, &key.PublicKey, caCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create host cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Certificate[0]},
		PrivateKey:  key,
	}, nil
}
