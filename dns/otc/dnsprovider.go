package otc

import (
	"github.com/dns3l/dns3l-core/dns/types"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:        p.C.Name,
		Feature:     []string{"A", "TXT"},
		ZoneNesting: true,
	}

}

func (p *DNSProvider) GetPrecheckConfig() *types.PrecheckConfig {
	conf := &p.C.PreCheck
	conf.SetDefaults()
	return conf
}
