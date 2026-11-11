package state

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
)

// ISRG Root X1
const testTLSRootPEM = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
`

func TestParseTLSMinVersion(t *testing.T) {
	tests := map[string]uint16{
		"":        0,
		"default": 0,
		"1.2":     tls.VersionTLS12,
		"tls1.3":  tls.VersionTLS13,
	}

	for input, expected := range tests {
		got, err := parseTLSMinVersion(input)
		if err != nil {
			t.Fatalf("parseTLSMinVersion(%q) returned unexpected error: %v", input, err)
		}
		if got != expected {
			t.Fatalf("parseTLSMinVersion(%q)=%d, expected %d", input, got, expected)
		}
	}

	_, err := parseTLSMinVersion("1.9")
	if err == nil {
		t.Fatal("expected error for unsupported TLS min version")
	}
}

func TestGetTrustedChainPEMFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "ca.pem")
	err := os.WriteFile(pemPath, []byte(testTLSRootPEM), 0o600)
	if err != nil {
		t.Fatalf("failed to write test cert file: %v", err)
	}

	p := &SQLDBProviderDefault{
		TLS: &SQLDBTLSConfig{
			TrustedChainFile: pemPath,
		},
	}

	pemData, err := p.getTrustedChainPEM()
	if err != nil {
		t.Fatalf("getTrustedChainPEM() returned error: %v", err)
	}
	if len(pemData) == 0 {
		t.Fatal("expected trusted chain data to be loaded from file")
	}
}

func TestInitMySQLTLSConfig(t *testing.T) {
	p := &SQLDBProviderDefault{
		Type: "mysql",
		URL:  "user:password@tcp(127.0.0.1:3306)/dns3ld?parseTime=true&tls=dns3ld-db-custom",
		TLS: &SQLDBTLSConfig{
			MinVersion:      "1.2",
			TrustedChainPEM: testTLSRootPEM,
		},
	}

	err := p.initTLSConfig()
	if err != nil {
		t.Fatalf("initMySQLTLSConfig() returned error: %v", err)
	}
	t.Cleanup(func() {
		mysql.DeregisterTLSConfig(TlsCustomConfigName)
	})

	dsn, err := mysql.ParseDSN(p.URL)
	if err == nil {
		if dsn.TLSConfig != TlsCustomConfigName {
			t.Fatalf("expected DSN tls config %q, got %q", TlsCustomConfigName, dsn.TLSConfig)
		}
		return
	}
	t.Fatalf("expected mysql DSN parsing to succeed after TLS config registration, got error: %v", err)
}

func TestInitMySQLTLSConfigSysCert(t *testing.T) {
	p := &SQLDBProviderDefault{
		Type: "mysql",
		URL:  "user:password@tcp(127.0.0.1:3306)/dns3ld?parseTime=true&tls=dns3ld-db-custom",
		TLS: &SQLDBTLSConfig{
			MinVersion:      "1.2",
			TrustedChainPEM: "",
		},
	}

	err := p.initTLSConfig()
	if err != nil {
		t.Fatalf("initMySQLTLSConfig() returned error: %v", err)
	}
	t.Cleanup(func() {
		mysql.DeregisterTLSConfig(TlsCustomConfigName)
	})

	dsn, err := mysql.ParseDSN(p.URL)
	if err == nil {
		if dsn.TLSConfig != TlsCustomConfigName {
			t.Fatalf("expected DSN tls config %q, got %q", TlsCustomConfigName, dsn.TLSConfig)
		}
		return
	}
	t.Fatalf("expected mysql DSN parsing to succeed after TLS config registration, got error: %v", err)
}

func TestInitMySQLTLSConfigWrongName(t *testing.T) {
	p := &SQLDBProviderDefault{
		Type: "mysql",
		URL:  "user:password@tcp(127.0.0.1:3306)/dns3ld?parseTime=true&tls=wrongname",
		TLS: &SQLDBTLSConfig{
			MinVersion:      "1.2",
			TrustedChainPEM: testTLSRootPEM,
		},
	}

	err := p.initTLSConfig()
	if err != nil {
		t.Fatalf("initMySQLTLSConfig() returned error: %v", err)
	}
	t.Cleanup(func() {
		mysql.DeregisterTLSConfig(TlsCustomConfigName)
	})

	_, err = mysql.ParseDSN(p.URL)
	assert.ErrorContains(t, err, "unknown config name")

}

func TestInitMySQLTLSTrue(t *testing.T) {
	const tlsName = "dns3ltestcfg"
	p := &SQLDBProviderDefault{
		Type: "mysql",
		URL:  "user:password@tcp(127.0.0.1:3306)/dns3ld?parseTime=true&tls=true",
		TLS: &SQLDBTLSConfig{
			MinVersion:      "1.2",
			TrustedChainPEM: testTLSRootPEM,
		},
	}

	err := p.initTLSConfig()
	if err != nil {
		t.Fatalf("initMySQLTLSConfig() returned error: %v", err)
	}
	t.Cleanup(func() {
		mysql.DeregisterTLSConfig(tlsName)
	})

	_, err = mysql.ParseDSN(p.URL)
	assert.NoError(t, err)
}

func TestInitMySQLTLSPreferred(t *testing.T) {
	const tlsName = "dns3ltestcfg"
	p := &SQLDBProviderDefault{
		Type: "mysql",
		URL:  "user:password@tcp(127.0.0.1:3306)/dns3ld?parseTime=true&tls=preferred",
		TLS: &SQLDBTLSConfig{
			MinVersion:      "1.2",
			TrustedChainPEM: testTLSRootPEM,
		},
	}

	err := p.initTLSConfig()
	if err != nil {
		t.Fatalf("initMySQLTLSConfig() returned error: %v", err)
	}
	t.Cleanup(func() {
		mysql.DeregisterTLSConfig(tlsName)
	})

	_, err = mysql.ParseDSN(p.URL)
	assert.NoError(t, err)

}
