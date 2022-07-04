package infblx

import dns_types "github.com/dta4/dns3l-go/dns/types"

type Config struct {
	ID        string `yaml:"id"`
	Name      string `yaml:"name"`
	Host      string `yaml:"host"`
	Port      string `yaml:"port"`
	DNSView   string `ỳaml:"dnsview"`
	Version   string `yaml:"version"`
	SSLVerify string `yaml:"sslverify"`
	Auth      struct {
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"auth"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
