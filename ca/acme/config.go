package acme

import (
	ca_types "github.com/dta4/dns3l-go/ca/types"
)

type Config struct {
	Type   string `yaml:"type"`
	Name   string `yaml:"name"`
	CAType string `yaml:"catype"` //public or private only...
	URL    string `yaml:"url"`
	Auth   struct {
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"auth"`
	Roots                 string `yaml:"roots"`
	DaysRenewBeforeExpiry int    `yaml:"daysRenewBeforeExpiry" default:"16"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{c: c}, nil
}
