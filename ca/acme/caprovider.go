package acme

import (
	"errors"
	"fmt"

	castate "github.com/dns3l/dns3l-core/ca/state"
	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/util"
)

type CAProvider struct {
	engine     *Engine
	userScheme ACMEUserScheme
	C          *Config `validate:"required"`
	ID         string
	Ctxt       types.ProviderConfigurationContext
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
	p.Ctxt = c

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

	p.userScheme, err = GetACMEUserScheme(p.C.ACMEUserScheme)
	if err != nil {
		return err
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

func (p *CAProvider) IsEnabled() bool {

	return !p.C.Disabled

}

func (p *CAProvider) PrecheckClaimCertificate(cinfo *types.CertificateClaimInfo) error {
	if p.C.DisableSAN {
		if len(cinfo.Domains) > 1 {
			return &common.InvalidInputError{Msg: "Subject Alternative names (SANs) provided but not permitted for this CA provider."}
		}
	}
	if p.C.DisableWildcards {
		for _, domain := range cinfo.Domains {
			if util.IsWildcard(domain) {
				return &common.InvalidInputError{Msg: fmt.Sprintf("Domain '%s' is a wildcard domain, not permitted for this CA provider.", domain)}
			}
		}
	}
	return nil
}

func (p *CAProvider) ClaimCertificate(cinfo *types.CertificateClaimInfo) error {

	acmeuser := p.userScheme.GetUserFor(cinfo.Name, cinfo.IssuedBy)

	return p.engine.TriggerUpdate(acmeuser, cinfo.Name, cinfo.Domains,
		cinfo.IssuedBy)

}

func (p *CAProvider) RenewCertificate(cinfo *types.CertificateRenewInfo) error {

	if p.ID != cinfo.CAID {
		return &common.InvalidInputError{Msg: fmt.Sprintf(
			"Certificate to renew (caID '%s') does not belong to CA provider '%s'", cinfo.CAID, p.ID)}
	}

	return p.engine.TriggerUpdate("", cinfo.CertKey, nil, nil)

}

func (p *CAProvider) CleanupAfterDeletion(keyID string, crt *types.CACertInfo) error {

	//TODO check this func to be executed only if actual deletion occurred.

	acmeuser, err := p.userScheme.GetUserToDelete(keyID, crt.IssuedBy, p.Ctxt)
	if err != nil {
		return err
	}
	if acmeuser == "" {
		//shall not be deleted
		return nil
	}

	return p.engine.DeleteACMEUser(acmeuser)

}
