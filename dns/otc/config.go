package otc

import dns_types "github.com/dns3l/dns3l-core/dns/types"

type Config struct {
	Name string `yaml:"name" validate:"required"`
	Auth struct {
		AuthURL     string `yaml:"authurl" validate:"required,url"`
		ProjectName string `yaml:"projectname" validate:"alphanumUnderscoreDash"`
		ProjectID   string `yaml:"projectid" validate:"alphanumUnderscoreDash"`
		AccessKey   string `yaml:"ak" validate:"required,alphanum"`
		SecretKey   string `yaml:"sk" validate:"required,alphanum"`
	} `yaml:"auth" validate:"required"`
	OSRegion string `yaml:"os-region" validate:"alphanumUnderscoreDash"`
}

func (c *Config) NewInstance() (dns_types.DNSProvider, error) {
	return &DNSProvider{c}, nil
}
