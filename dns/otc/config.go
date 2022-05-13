package otc

import dns_types "github.com/dta4/dns3l-go/dns/types"

type Config struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Auth struct {
		AccessKey string `yaml:"ak"`
		SecretKey string `yaml:"sk"`
	} `yaml:"auth"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
