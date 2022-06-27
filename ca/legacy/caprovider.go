package legacy

import (
	"errors"

	"github.com/dta4/dns3l-go/ca/types"
)

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

func (p *CAProvider) Init(c types.ProviderConfigurationContext) error {

	//nothing to do yet

	return nil

}

func (p *CAProvider) ClaimCertificate(cinfo *types.CertificateClaimInfo) error {

	return errors.New("ClaimCertificate(..) not yet implemented")

}

func (p *CAProvider) CleanupBeforeDeletion(keyID string) error {

	return errors.New("CleanupBeforeDeletion(..) not yet implemented")

}
