package otc

import "github.com/dta4/dns3l-go/dns/types"

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
