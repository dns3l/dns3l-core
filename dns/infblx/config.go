package infblx

import dns_types "github.com/dta4/dns3l-go/dns/types"

type Config struct {
	ID        string `yaml:"id" validate:"required,numeric"`
	Name      string `yaml:"name" validate:"required,numeric"`
	Host      string `yaml:"host" validate:"required,numeric"`
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
