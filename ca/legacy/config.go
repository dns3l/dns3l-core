package legacy

import (
	ca_types "github.com/dta4/dns3l-go/ca/types"
)

type Config struct {
	Name   string `yaml:"name" validate:"required"`
	CAType string `yaml:"catype" validate:"required,alpha"` //public or private only...
	Roots  string `yaml:"roots" validate:"required,url"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{c}, nil
}
