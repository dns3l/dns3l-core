package state

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
)

const (
	TlsCustomConfigName = "dns3ld-db-custom"
)

type SQLDBTLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	MinVersion         string `yaml:"minVersion"`
	TrustedChainPEM    string `yaml:"trustedChainPEM"`
	TrustedChainFile   string `yaml:"trustedChainFile"`
	ServerName         string `yaml:"serverName"`
}

func (c *SQLDBProviderDefault) initTLSConfig() error {
	tlsConfig, err := c.getTLSConfig()
	if err != nil {
		return err
	}

	if tlsConfig == nil {
		// no TLS configured
		return nil
	}
	if c.Type == "mysql" {
		mysql.DeregisterTLSConfig(TlsCustomConfigName)
		if err := mysql.RegisterTLSConfig(TlsCustomConfigName, tlsConfig); err != nil {
			return fmt.Errorf("failed to register custom SQL DB TLS config: %w", err)
		}
	} else {
		return fmt.Errorf("TLS config given, but unsupported DB type: %s", c.Type)
	}

	return nil
}

func parseTLSMinVersion(minVersion string) (uint16, error) {
	v := strings.ToLower(strings.TrimSpace(minVersion))
	switch v {
	case "", "default":
		return 0, nil
	case "1.0", "tls1.0", "tls10":
		return tls.VersionTLS10, nil
	case "1.1", "tls1.1", "tls11":
		return tls.VersionTLS11, nil
	case "1.2", "tls1.2", "tls12":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3", "tls13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported SQL DB TLS minimum version '%s'", minVersion)
	}
}

func (c *SQLDBProviderDefault) getTrustedChainPEM() ([]byte, error) {
	if c.TLS == nil {
		return nil, nil
	}
	pemData := strings.TrimSpace(c.TLS.TrustedChainPEM)
	file := strings.TrimSpace(c.TLS.TrustedChainFile)

	if pemData != "" && file != "" {
		return nil, errors.New("both db.tls.trustedChainPEM and db.tls.trustedChainFile are set, choose exactly one")
	}
	if pemData != "" {
		return []byte(pemData), nil
	}
	if file != "" {
		return os.ReadFile(file)
	}
	return nil, nil
}

func (c *SQLDBProviderDefault) getTLSConfig() (*tls.Config, error) {
	if c.TLS == nil {
		// no TLS configured
		return nil, nil
	}

	minVersion, err := parseTLSMinVersion(c.TLS.MinVersion)
	if err != nil {
		return nil, err
	}
	trustedChainPEM, err := c.getTrustedChainPEM()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.TLS.InsecureSkipVerify,
		MinVersion:         minVersion,
		ServerName:         c.TLS.ServerName,
	}

	if !c.TLS.InsecureSkipVerify || len(trustedChainPEM) > 0 {
		var pool *x509.CertPool
		if len(trustedChainPEM) > 0 {
			pool = x509.NewCertPool()
			if ok := pool.AppendCertsFromPEM(trustedChainPEM); !ok {
				return nil, errors.New("failed to parse custom trusted chain PEM")
			}
		} else {
			pool, err = x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("failed to load system certificate pool: %w", err)
			}
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}
