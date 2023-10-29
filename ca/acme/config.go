package acme

import (
	"github.com/dns3l/dns3l-core/ca/common"
	ca_types "github.com/dns3l/dns3l-core/ca/types"
)

type Config struct {
	Name     string `yaml:"name" validate:"required"`
	Disabled bool   `yaml:"disabled"`
	CAType   string `yaml:"catype" validate:"required,alpha"` //public or private only...
	API      string `yaml:"api" validate:"required,url"`
	URL      string `yaml:"url" validate:"url"`
	EAB      struct {
		KID  string `yaml:"kid" validate:"alphanumUnderscoreDashDot"`
		HMAC string `yaml:"hmac"`
	} `yaml:"eab"`
	Roots                      string           `yaml:"roots"`
	RelativeLifetimeUntilRenew float64          `yaml:"relativeLifetimeUntilRenew" default:"0.7" validate:"required"`
	Description                string           `yaml:"description"`
	LogoPath                   string           `yaml:"logopath" validate:"url|remotefile"`
	HTTPInsecureSkipVerify     bool             `yaml:"httpInsecureSkipVerify"`
	ACMERegisterWithoutEMail   bool             `yaml:"acmeRegisterWithoutEmail"`
	ACMEUserScheme             string           `yaml:"acmeUserScheme"` //key, user, or one
	DisableWildcards           bool             `yaml:"disableWildcards"`
	DisableSAN                 bool             `yaml:"disableSAN"`
	TTL                        common.TTLConfig `yaml:"ttl"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{C: c}, nil
}
