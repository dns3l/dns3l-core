package bogus

import (
	dns_types "github.com/dns3l/dns3l-core/dns/types"
)

type Config struct {
	Name string `yaml:"name" validate:"required"`
	TTL  struct {
		Challenge uint32 `yaml:"challenge" validate:"numeric"`
		AutoDNS   uint32 `yaml:"autodns" validate:"numeric"`
	} `yaml:"ttl"`
	PreCheck dns_types.PrecheckConfig `yaml:"precheck"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
