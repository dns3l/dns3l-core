package otc

import dns_types "github.com/dta4/dns3l-go/dns/types"

type Config struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Auth struct {
		AuthURL     string `yaml:"authurl"`
		ProjectName string `yaml:"projectname"`
		ProjectID   string `yaml:"projectid"`
		AccessKey   string `yaml:"ak"`
		SecretKey   string `yaml:"sk"`
	} `yaml:"auth"`
	OSRegion string `yaml:"os-region"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
