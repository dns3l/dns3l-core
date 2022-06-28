package ca

import (
	"errors"
	"fmt"

	castate "github.com/dta4/dns3l-go/ca/state"
	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/dns"
	dnstypes "github.com/dta4/dns3l-go/dns/types"
	"github.com/dta4/dns3l-go/state"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Providers map[string]*ProviderInfo //configured DNS providers mapped with their ID
	Functions *CAFunctionHandler
}

type ProviderInfo struct {
	Type      string `yaml:"type"`
	Prov      types.CAProvider
	RootZones dns.RootZones
}

type ProviderConfigurationContextImpl struct {
	provKey  string
	stateMgr types.CAStateManager
	ctx      types.CAConfigurationContext
	pinfo    *ProviderInfo
}

//Can spawn a new instance of a DNS provider.
//Provider-specific config is unmarshaled into the builder's implementing struct.
type CAProviderBuilder interface {
	NewInstance() (types.CAProvider, error)
}

var _ yaml.Unmarshaler = &ProviderInfo{}

func (c *Config) Init(ctx types.CAConfigurationContext) error {

	//construct CAFunctionHandler + State

	sm, err := makeCAStateManager(ctx.GetStateProvider())
	if err != nil {
		return err
	}

	c.Functions = &CAFunctionHandler{
		Config: c,
		State:  sm,
	}

	for k, v := range c.Providers {
		err := v.Prov.Init(&ProviderConfigurationContextImpl{
			provKey:  k,
			stateMgr: sm,
			ctx:      ctx,
			pinfo:    v,
		})
		if err != nil {
			return err
		}
	}

	log.Debugf("CA providers initialized")

	return nil

}

func makeCAStateManager(sprov state.StateProvider) (types.CAStateManager, error) {
	switch sprovinst := sprov.(type) {
	case state.SQLDBProvider:
		return &castate.CAStateManagerSQL{Prov: sprovinst}, nil
	default:
		return nil, errors.New("only supporting SQL DB providers at the moment")
	}
}

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

func (f *ProviderInfo) DomainIsInAllowedRootZone(dom string) bool {

	for _, rz := range f.RootZones {
		if rz.DomainIsInZone(dom) {
			return true
		}
	}
	return false
}

func (sm *ProviderConfigurationContextImpl) GetCAID() string {
	return sm.provKey
}
func (sm *ProviderConfigurationContextImpl) GetStateMgr() types.CAStateManager {
	return sm.stateMgr
}

/*
func (sm *ProviderConfigurationContextImpl) GetDNSProvider(provID string) (dnstypes.DNSProvider, bool) {
	return sm.ctx.GetDNSProvider(provID)
}
*/

func (sm *ProviderConfigurationContextImpl) GetDNSProviderForDomain(domain string, challenge bool) (dnstypes.DNSProvider, error) {

	rz, err := sm.pinfo.RootZones.GetLowestRZForDomain(domain)
	if err != nil {
		return nil, err
	}

	var prov dnstypes.DNSProvider
	var exists bool
	if challenge {
		prov, exists = sm.ctx.GetDNSProvider(rz.DNSProvAcme)

	} else {
		prov, exists = sm.ctx.GetDNSProvider(rz.DNSProvAutoDNS)
	}

	if !exists {
		return nil, fmt.Errorf("DNS provider for domain '%s' not configured", domain)
	}

	return prov, nil

}
