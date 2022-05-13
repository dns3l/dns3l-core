package legacy

import ca_types "github.com/dta4/dns3l-go/ca/types"

type Config struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	CAType string `yaml:"catype"` //public or private only...
	Roots  string `yaml:"roots"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{c}, nil
}
