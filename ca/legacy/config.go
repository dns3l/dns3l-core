package legacy

import (
	ca_types "github.com/dns3l/dns3l-core/ca/types"
)

type Config struct {
	Name        string `yaml:"name" validate:"required"`
	CAType      string `yaml:"catype" validate:"required,alpha"` //public or private only...
	Roots       string `yaml:"roots" validate:"required,url"`
	Description string `yaml:"description"`
	LogoPath    string `yaml:"logopath" validate:"url"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{c}, nil
}
