package ca

import (
	"fmt"

	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/dns"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Providers map[string]*ProviderInfo //configured DNS providers mapped with their ID
}

type ProviderInfo struct {
	Type      string `yaml:"type"`
	Prov      types.CAProvider
	RootZones []*dns.RootZone
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
	bf, exists := CAProviderBuilders[t.Type]
	if !exists {
		return fmt.Errorf("no CA provider found for %s", t.Type)
	}
	builder := bf()
	err = unmarshal(builder)
	if err != nil {
		return err
	}
	f.Prov, err = builder.NewInstance()
	if err != nil {
		return err
	}

	return nil

}

func (f *ProviderInfo) AddAllowedRootZone(rootzone *dns.RootZone) {
	if f.RootZones == nil {
		f.RootZones = make([]*dns.RootZone, 0, 10)
	}
	f.RootZones = append(f.RootZones, rootzone)
}

func (f *ProviderInfo) GetRootZonesAsString() []string {
	rzs := make([]string, 0, len(f.RootZones))
	for _, rz := range f.RootZones {
		rzs = append(rzs, rz.Root)
	}
	return rzs
}
