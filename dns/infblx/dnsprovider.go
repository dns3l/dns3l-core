package infblx

import "github.com/dta4/dns3l-go/dns/types"

type DNSProvider struct {
	c *Config
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:        p.c.Name,
		Feature:     []string{"A", "TXT"},
		ZoneNesting: true, //TODO
	}

}
