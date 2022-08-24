package dns

import (
	"fmt"

	"github.com/dns3l/dns3l-core/dns/types"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Providers map[string]*ProviderInfo `yaml:"providers" validate:"required,dive"` //configured DNS providers mapped with their ID
}

type ProviderInfo struct {
	Type string            `yaml:"type" validate:"required,alphanumUnderscoreDash"`
	Prov types.DNSProvider `validate:"required"`
}

var _ yaml.Unmarshaler = &ProviderInfo{}

func (f *ProviderInfo) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var t struct {
		Type string `yaml:"type"`
	}
	err := unmarshal(&t)
	if err != nil {
		return err
	}
	bf, exists := DNSProviderBuilders[t.Type]
	if !exists {
		return fmt.Errorf("no DNS provider found for %s", t.Type)
	}
	builder := bf()
	err = unmarshal(builder)
	if err != nil {
		return err
	}
	f.Type = t.Type
	f.Prov, err = builder.NewInstance()
	if err != nil {
		return err
	}

	return nil

}
