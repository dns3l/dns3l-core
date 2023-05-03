package bogus

import (
	ca_types "github.com/dns3l/dns3l-core/ca/types"
)

type Config struct {
	Name        string `yaml:"name" validate:"required"`
	Disabled    bool   `yaml:"disabled"`
	CAType      string `yaml:"catype" validate:"required,alpha"`
	URL         string `yaml:"url" validate:"url"`
	Roots       string `yaml:"roots"`
	Description string `yaml:"description"`
	LogoPath    string `yaml:"logopath" validate:"url|remotefile"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{C: c}, nil
}
