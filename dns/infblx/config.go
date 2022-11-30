package infblx

import dns_types "github.com/dns3l/dns3l-core/dns/types"

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
	TTL struct {
		Challenge uint32 `yaml:"challenge" validate:"numeric"`
		AutoDNS   uint32 `yaml:"autodns" validate:"numeric"`
	} `yaml:"ttl"`
	PreCheck dns_types.PrecheckConfig `yaml:"precheck"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
