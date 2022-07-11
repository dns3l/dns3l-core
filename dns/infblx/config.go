package infblx

import dns_types "github.com/dta4/dns3l-go/dns/types"

type Config struct {
	Name      string `yaml:"name" validate:"required"`
	Host      string `yaml:"host" validate:"required,fqdn"`
	Port      string `yaml:"port" validate:"required,gt=0,lt=65536"`
	DNSView   string `ỳaml:"dnsview" validate:"required,alphanumUnderscoreDashDot"`
	Version   string `yaml:"version" validate:"required,semver"`
	SSLVerify string `yaml:"sslverify" validate:"alphanumUnderscoreDashDot"`
	Auth      struct {
		User string `yaml:"user" validate:"required,alphanumUnderscoreDash"`
		Pass string `yaml:"pass" validate:"required"`
	} `yaml:"auth" validate:"required"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
