package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestValidatePEM(t *testing.T) {
	valid := []byte("-----BEGIN TEST-----\nYWJj\n-----END TEST-----\n")
	if err := ValidatePEM(valid); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePEM([]byte("not pem")); err == nil {
		t.Fatal("expected invalid PEM error")
	}
}

func TestCertificateMatchesKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var certPEM bytes.Buffer
	var keyPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	ok, err := CertificateMatchesKey(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected certificate to match key")
	}
}

func TestCertificateMatchesECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, tc := range []struct {
		key  *ecdsa.PrivateKey
		want bool
	}{{key, true}, {otherKey, false}} {
		keyDER, err := x509.MarshalECPrivateKey(tc.key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		got, err := CertificateMatchesKey(certPEM, keyPEM)
		if err != nil || got != tc.want {
			t.Fatalf("CertificateMatchesKey() = %v, %v; want %v, nil", got, err, tc.want)
		}
	}
}
