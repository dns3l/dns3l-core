package acme

import "github.com/dta4/dns3l-go/ca/types"

type CAProvider struct {
	c *Config
}

func (p *CAProvider) GetInfo() *types.CAProviderInfo {

	return &types.CAProviderInfo{
		Name:        p.c.Name,
		Type:        p.c.CAType,
		Description: "foo <TODO where does this come from?>",
		LogoPath:    "bar <TODO where does this come from?>",
		URL:         p.c.URL,
		Roots:       p.c.Roots,
		IsAcme:      true,
	}

}

func (p *CAProvider) AddAllowedRootZone() int {

	return 42 //TODO

}

func (p *CAProvider) GetTotalValid() int {

	return 42 //TODO

}

func (p *CAProvider) GetTotalIssued() int {

	return 68 //TODO

}

func (p *CAProvider) IsEnabled() bool {

	return true //TODO

}
