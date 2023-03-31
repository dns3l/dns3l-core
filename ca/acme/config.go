package acme

import (
	ca_types "github.com/dns3l/dns3l-core/ca/types"
)

type Config struct {
	Name   string `yaml:"name" validate:"required"`
	CAType string `yaml:"catype" validate:"required,alpha"` //public or private only...
	API    string `yaml:"api" validate:"required,url"`
	URL    string `yaml:"url" validate:"url"`
	EAB    struct {
		KID  string `yaml:"kid" validate:"alphanumUnderscoreDashDot"`
		HMAC string `yaml:"hmac"`
	} `yaml:"eab"`
	Roots                    string `yaml:"roots"`
	DaysRenewBeforeExpiry    int    `yaml:"daysRenewBeforeExpiry" default:"16" validate:"required"`
	Description              string `yaml:"description"`
	LogoPath                 string `yaml:"logopath" validate:"url|remotefile"`
	HTTPInsecureSkipVerify   bool   `yaml:"httpInsecureSkipVerify"`
	ACMERegisterWithoutEMail bool   `yaml:"acmeRegisterWithoutEmail"`
	ACMEUserScheme           string `yaml:"acmeUserScheme"` //key, user, or one
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{C: c}, nil
}
