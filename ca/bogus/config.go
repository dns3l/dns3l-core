package bogus

import (
	"github.com/dns3l/dns3l-core/ca/common"
	ca_types "github.com/dns3l/dns3l-core/ca/types"
)

type Config struct {
	Name          string           `yaml:"name" validate:"required"`
	Disabled      bool             `yaml:"disabled"`
	CAType        string           `yaml:"catype" validate:"required,alpha"`
	URL           string           `yaml:"url" validate:"url"`
	Roots         string           `yaml:"roots"`
	Description   string           `yaml:"description"`
	LogoPath      string           `yaml:"logopath" validate:"url|remotefile"`
	TTL           common.TTLConfig `yaml:"ttl"`
	CAPrivateKey  string           `yaml:"ca_private_key"`
	CACertificate string           `yaml:"ca_certificate"`
	SerialOffset  uint64           `yaml:"serial_offset"`
}

func (c *Config) NewInstance() (ca_types.CAProvider, error) {
	return &CAProvider{C: c}, nil
}
