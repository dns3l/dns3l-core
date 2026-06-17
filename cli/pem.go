package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
)

var pemResourceOrder = []string{"cert", "key", "chain", "root", "rootchain", "fullchain"}

var pemResourceLabels = map[string]string{
	"cert":      "Certificate (cert)",
	"key":       "Private key (key)",
	"chain":     "Intermediate chain (chain)",
	"root":      "Root certificate (root)",
	"rootchain": "Root chain (rootchain)",
	"fullchain": "Full chain (fullchain)",
}

func ValidatePEM(data []byte) error {
	rest := data
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		found = true
		if strings.TrimSpace(block.Type) == "" || len(block.Bytes) == 0 {
			return errors.New("PEM block has empty type or body")
		}
	}
	if !found {
		return errors.New("no PEM block found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return errors.New("trailing non-PEM data found")
	}
	return nil
}

func WritePEMFile(path string, data []byte, check bool) error {
	if check {
		if err := ValidatePEM(data); err != nil {
			return fmt.Errorf("validate PEM for %s: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func WritePEMDirectory(dir string, resources apiv1.CertResources, check bool) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create output directory %s: %w", dir, err)
	}
	for _, name := range pemResourceOrder {
		data := resourceByName(resources, name)
		if strings.TrimSpace(data) == "" {
			continue
		}
		if err := WritePEMFile(filepath.Join(dir, name+".pem"), []byte(data), check); err != nil {
			return err
		}
	}
	return nil
}

func resourceByName(resources apiv1.CertResources, name string) string {
	switch name {
	case "cert", "crt":
		return resources.Certificate
	case "key":
		return resources.Key
	case "root":
		return resources.Root
	case "rootchain":
		return resources.RootChain
	case "chain":
		return resources.Chain
	case "fullchain":
		return resources.FullChain
	default:
		return ""
	}
}

func CertificateMatchesKey(certPEM, keyPEM []byte) (bool, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return false, errors.New("certificate PEM contains no block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return false, errors.New("key PEM contains no block")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return false, err
	}

	switch priv := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		return ok && pub.N.Cmp(priv.PublicKey.N) == 0 && pub.E == priv.PublicKey.E, nil
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		return ok && pub.X.Cmp(priv.PublicKey.X) == 0 && pub.Y.Cmp(priv.PublicKey.Y) == 0, nil
	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		return ok && string(pub) == string(priv.Public().(ed25519.PublicKey)), nil
	default:
		return false, fmt.Errorf("unsupported private key type %T", key)
	}
}

func parsePrivateKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported or invalid private key PEM")
}
