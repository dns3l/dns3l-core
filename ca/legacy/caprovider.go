package legacy

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
		URL:         "",
		Roots:       p.c.Roots,
		IsAcme:      false,
	}

}

func (p *CAProvider) GetTotalValid() int {

	return 23 //TODO

}

func (p *CAProvider) GetTotalIssued() int {

	return 34 //TODO

}

func (p *CAProvider) IsEnabled() bool {

	return true //TODO

}
