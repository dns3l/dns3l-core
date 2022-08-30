package acme

import (
	"errors"
	"fmt"

	castate "github.com/dns3l/dns3l-core/ca/state"
	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
)

type CAProvider struct {
	engine *Engine
	C      *Config `validate:"required"`
	ID     string
}

func (p *CAProvider) GetInfo() *types.CAProviderInfo {

	return &types.CAProviderInfo{
		Name:        p.C.Name,
		Type:        p.C.CAType,
		Description: p.C.Description,
		LogoPath:    p.C.LogoPath,
		URL:         p.C.URL,
		Roots:       p.C.Roots,
		IsAcme:      true,
	}

}

func (p *CAProvider) Init(c types.ProviderConfigurationContext) error {

	p.ID = c.GetCAID()

	smgr, err := makeACMEStateManager(c)
	if err != nil {
		return err
	}

	p.engine = &Engine{
		CAID:              p.ID,
		Conf:              p.C,
		Context:           c,
		State:             smgr,
		RecalcRenewalDate: false,
	}

	log.Debugf("ACME CA provider initialized.")

	return nil

}

func makeACMEStateManager(c types.ProviderConfigurationContext) (ACMEStateManager, error) {
	switch sprovinst := c.GetStateMgr().(type) {
	case *castate.CAStateManagerSQL:
		return &ACMEStateManagerSQL{c.GetCAID(), sprovinst.Prov}, nil
	default:
		return nil, errors.New("only supporting SQL DB providers at the moment")
	}
}

func (p *CAProvider) AddAllowedRootZone() int {

	return 42 //TODO

}

func (p *CAProvider) GetTotalValid() uint {

	return 42 //TODO

}

func (p *CAProvider) GetTotalIssued() uint {

	return 68 //TODO

}

func (p *CAProvider) IsEnabled() bool {

	return true //TODO

}

func (p *CAProvider) ClaimCertificate(cinfo *types.CertificateClaimInfo) error {

	acmeuser := "acme-" + cinfo.Name

	return p.engine.TriggerUpdate(acmeuser, cinfo.Name, cinfo.NameRZ, cinfo.Domains,
		cinfo.IssuedBy, cinfo.IssuedByEmail)

}

func (p *CAProvider) RenewCertificate(cinfo *types.CertificateRenewInfo) error {

	if p.ID != cinfo.CAID {
		return &common.InvalidInputError{Msg: fmt.Sprintf(
			"Certificate to renew (caID '%s') does not belong to CA provider '%s'", cinfo.CAID, p.ID)}
	}

	return p.engine.TriggerUpdate("", cinfo.CertKey, "", nil, "", "")

}

func (p *CAProvider) CleanupAfterDeletion(keyID string) error {

	acmeuser := "acme-" + keyID

	return p.engine.DeleteACMEUser(acmeuser)

}
