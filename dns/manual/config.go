package manual

import (
	"time"

	dns_types "github.com/dns3l/dns3l-core/dns/types"
)

type Config struct {
	Name string `yaml:"name" validate:"required"`
	TTL  struct {
		AutoDNS uint32 `yaml:"autodns" validate:"numeric"`
	} `yaml:"ttl"`
	PreCheck dns_types.PrecheckConfig `yaml:"precheck"`
	WaitTime time.Duration            `yaml:"waitTime"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
