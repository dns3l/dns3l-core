package legacy

import (
	"errors"

	"github.com/dta4/dns3l-go/ca/types"
)

type CAProvider struct {
	C *Config `validate:"required"`
}

func (p *CAProvider) GetInfo() *types.CAProviderInfo {

	return &types.CAProviderInfo{
		Name:        p.C.Name,
		Type:        p.C.CAType,
		Description: p.C.Description,
		LogoPath:    p.C.LogoPath,
		URL:         "",
		Roots:       p.C.Roots,
		IsAcme:      false,
	}

}

func (p *CAProvider) GetTotalValid() uint {

	return 23 //TODO

}

func (p *CAProvider) GetTotalIssued() uint {

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
