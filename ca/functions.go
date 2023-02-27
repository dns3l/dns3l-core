package ca

import (
	"fmt"
	"time"

	"github.com/dns3l/dns3l-core/ca/common"
	"github.com/dns3l/dns3l-core/ca/types"
	cmn "github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/util"
	"github.com/sirupsen/logrus"
)

// Provides API-close functions with
type CAFunctionHandler struct {
	Config *Config
	State  types.CAStateManager
}

func (h *CAFunctionHandler) ClaimCertificate(caID string, cinfo *types.CertificateClaimInfo) error {
	//TODO check exact semantics of name <> san relation and in case validate!

	prov, exists := h.Config.Providers[caID]
	if !exists {
		return fmt.Errorf("no CA provider with name '%s' exists", caID)
	}

	for _, san := range cinfo.Domains {
		if !prov.DomainIsInAllowedRootZone(util.GetDomainFQDNDot(san)) {
			return fmt.Errorf("subject alt name '%s' is not in the allowed root zones of CA provider '%s'",
				san, caID)
		}
	}

	err := prov.Prov.ClaimCertificate(cinfo)
	if err != nil {
		return err
	}

	h.Config.Providers[caID].TotalValid.Invalidate()
	h.Config.Providers[caID].TotalIssued.Invalidate()

	return nil

}

func (h *CAFunctionHandler) RenewCertificate(cinfo *types.CertificateRenewInfo) error {

	prov, exists := h.Config.Providers[cinfo.CAID]
	if !exists {
		return fmt.Errorf("no CA provider with name '%s' exists", cinfo.CAID)
	}

	err := prov.Prov.RenewCertificate(cinfo)
	if err != nil {
		return err
	}

	return nil

}

// if caID is "", list for all CAs
func (h *CAFunctionHandler) DeleteCertificate(caID, keyID string) error {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return err
	}

	prov, exists := h.Config.Providers[caID]
	if !exists {
		return fmt.Errorf("no CA provider with name '%s' exists", caID)
	}

	sess, err := h.State.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	err = sess.DelCACertByID(keyID, caID)
	if err != nil {
		return err
	}

	err = prov.Prov.CleanupAfterDeletion(keyID)
	if err != nil {
		log.WithError(err).WithField("caID", caID).Errorf("Problems cleaning up after deletion")
	}

	h.Config.Providers[caID].TotalValid.Invalidate()
	h.Config.Providers[caID].TotalIssued.Invalidate()

	return nil

}

func (h *CAFunctionHandler) GetCertificateResources(keyID, caID string) (*types.CertificateResources, error) {

	log.WithFields(logrus.Fields{"keyID": keyID, "caID": caID}).Debug("Request for certificate resources")

	return h.getResourcesNoUpd(keyID, caID)

}

func (h *CAFunctionHandler) GetCertificateResource(keyID, caID, objectType string) (*common.PEMResource, error) {

	log.WithFields(logrus.Fields{
		"keyID":      keyID,
		"caID":       caID,
		"objectType": objectType},
	).Debug("Request for certificate resource")

	return h.getResourceNoUpd(keyID, caID, objectType)

}

// GetResources returns all autokey-obtained resources (key, cert, issuer etc..) to the user
// of the autokey service. The GetUpdate function must be called first, otherwise
// GetObject will return NotFoundError because the resources are not yet present.
func (h *CAFunctionHandler) getResourcesNoUpd(keyID, caID string) (*types.CertificateResources, error) {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return nil, err
	}

	log.Debugf("Request for resources belonging to key ID '%s'", keyID)

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	domains, err := sess.GetDomains(keyID, caID)
	if err != nil {
		return nil, err
	}

	res, err := sess.GetResources(keyID, caID, "priv_key", "cert", "issuer_cert")

	if err != nil {
		return nil, err
	}

	return &types.CertificateResources{
		Domains:     domains,
		Certificate: res[1],
		Key:         res[0],
		Chain:       res[2],
		FullChain:   res[1] + res[2],
	}, nil

}

// GetResource returns an autokey-obtained resource (key, cert, issuer etc..) to the user
// of the autokey service. The GetUpdate function must be called first, otherwise
// GetObject will return NotFoundError because the resources are not yet present.
func (h *CAFunctionHandler) getResourceNoUpd(keyID, caID, objectType string) (*common.PEMResource, error) {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return nil, err
	}

	log.Debugf("Request for resource '%s' belonging to key ID '%s'",
		objectType, keyID)

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	domains, err := sess.GetDomains(keyID, caID)
	if err != nil {
		return nil, err
	}

	switch objectType {
	case "key":
		//"resourceName" of sess.GetResource must never be user input > not validated!
		res, err := sess.GetResource(keyID, caID, "priv_key")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res,
			ContentType: "application/x-pem-file",
			Domains:     domains,
			CanBePublic: false,
		}, nil
	case "crt":
		res, err := sess.GetResource(keyID, caID, "cert")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res,
			ContentType: "application/x-pem-file",
			Domains:     domains,
			CanBePublic: true,
		}, nil
	case "chain":
		res, err := sess.GetResource(keyID, caID, "issuer_cert")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res,
			ContentType: "application/x-pem-file",
			Domains:     domains,
			CanBePublic: true,
		}, nil
	case "root":
		res, err := sess.GetResource(keyID, caID, "issuer_cert")
		if err != nil {
			return nil, err
		}
		root, err := common.ExtractRootCertPEM(res)
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     root,
			ContentType: "application/x-pem-file",
			Domains:     domains,
			CanBePublic: true,
		}, nil
	case "fullchain":
		res, err := sess.GetResources(keyID, caID, "cert", "issuer_cert")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res[0] + "\n" + res[1],
			ContentType: "application/x-pem-file",
			Domains:     domains,
			CanBePublic: true,
		}, nil
	}
	return nil, &cmn.NotFoundError{RequestedResource: objectType}

}

func (h *CAFunctionHandler) GetCertificateInfos(caID string, keyID string,
	authzedDomains []string, pginfo *util.PaginationInfo) ([]types.CACertInfo, error) {

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.ListCACerts(keyID, caID, authzedDomains, "", pginfo) //TODO extend api with user query

}

func (h *CAFunctionHandler) GetCertificateInfo(caID string, keyID string) (*types.CACertInfo, error) {

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.GetCACertByID(keyID, caID)

}

func (h *CAFunctionHandler) ListExpiring(expiredAt time.Time, limit uint) ([]types.CertificateRenewInfo, error) {

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.ListExpired(expiredAt, limit)

}

func (h *CAFunctionHandler) ListCertsToRenew(limit uint) ([]types.CertificateRenewInfo, error) {

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.ListToRenew(time.Now(), limit)

}

func (h *CAFunctionHandler) DeleteCertificatesAllCA(keyID string) error {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return err
	}

	sess, err := h.State.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	err = sess.DeleteCertAllCA(keyID)
	if err != nil {
		return err
	}

	for id, prov := range h.Config.Providers {
		err = prov.Prov.CleanupAfterDeletion(keyID)
		if err != nil {
			if _, is := err.(*cmn.NotFoundError); is {
				log.WithError(err).WithField("caID", keyID).Debugf("Provider '%s' not managing "+
					"key '%s', this is normal.", id, keyID)
			} else {
				log.WithError(err).WithField("caID", keyID).Errorf("Problems cleaning up for provider '%s' before deletion "+
					"of key '%s', continuing nevertheless...", id, keyID)
			}
		}
	}

	for _, prov := range h.Config.Providers {
		prov.TotalValid.Invalidate()
		prov.TotalIssued.Invalidate()
	}

	return nil

}

func (h *CAFunctionHandler) GetTotalValid(caID string) (uint, error) {
	return h.Config.Providers[caID].TotalValid.GetCached(func() (uint, error) {

		sess, err := h.State.NewSession()
		if err != nil {
			return 0, err
		}

		return sess.GetNumberOfCerts(caID, true, time.Now())
	})
}

func (h *CAFunctionHandler) GetTotalIssued(caID string) (uint, error) {
	return h.Config.Providers[caID].TotalIssued.GetCached(func() (uint, error) {
		sess, err := h.State.NewSession()
		if err != nil {
			return 0, err
		}

		return sess.GetNumberOfCerts(caID, false, time.Time{})
	})
}
