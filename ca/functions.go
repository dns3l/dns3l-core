package ca

import (
	"fmt"

	"github.com/dta4/dns3l-go/ca/common"
	"github.com/dta4/dns3l-go/ca/types"
	cmn "github.com/dta4/dns3l-go/common"
	"github.com/dta4/dns3l-go/util"
	"github.com/sirupsen/logrus"
)

//Provides API-close functions with
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

	return prov.Prov.ClaimCertificate(cinfo)

}

//if caID is "", list for all CAs
func (h *CAFunctionHandler) DeleteCertificate(caID, keyID string) error {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return err
	}

	prov, exists := h.Config.Providers[caID]
	if !exists {
		return fmt.Errorf("no CA provider with name '%s' exists", caID)
	}

	err = prov.Prov.CleanupBeforeDeletion(keyID)
	if err != nil {
		log.WithError(err).Errorf("Problems cleaning up before deletion")
	}

	sess, err := h.State.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.DelCACertByID(keyID, caID)

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

	res, domains, err := sess.GetResources(keyID, caID, "priv_key", "cert", "issuer_cert")

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

	switch objectType {
	case "key":
		//"resourceName" of sess.GetResource must never be user input > not validated!
		res, domains, err := sess.GetResource(keyID, caID, "priv_key")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res,
			ContentType: "application/x-pem-file",
			Domains:     domains,
		}, nil
	case "crt":
		res, domains, err := sess.GetResource(keyID, caID, "cert")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res,
			ContentType: "application/x-pem-file",
			Domains:     domains,
		}, nil
	case "issuer-cert":
		res, domains, err := sess.GetResource(keyID, caID, "issuer_cert")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res,
			ContentType: "application/x-pem-file",
			Domains:     domains,
		}, nil
	case "fullchain":
		res, domains, err := sess.GetResources(keyID, caID, "cert", "issuer_cert")
		if err != nil {
			return nil, err
		}
		return &common.PEMResource{
			PEMData:     res[0] + "\n" + res[1],
			ContentType: "application/x-pem-file",
			Domains:     domains,
		}, nil
	}
	return nil, &cmn.NotFoundError{RequestedResource: keyID}

}

func (h *CAFunctionHandler) GetCertificateInfos(caID string, keyID string,
	rzFilter []string, pginfo *util.PaginationInfo) ([]types.CACertInfo, error) {

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.ListCACerts(keyID, caID, rzFilter, pginfo)

}

func (h *CAFunctionHandler) GetCertificateInfo(caID string, keyID string) (*types.CACertInfo, error) {

	sess, err := h.State.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.GetCACertByID(keyID, caID)

}

func (h *CAFunctionHandler) DeleteCertificatesAllCA(keyID string) error {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return err
	}

	for id, prov := range h.Config.Providers {
		err = prov.Prov.CleanupBeforeDeletion(keyID)
		if err != nil {
			log.WithError(err).Errorf("Problems cleaning up for provider '%s' before deletion"+
				"of key '%s', continuing nevertheless...", id, keyID)
		}
	}

	sess, err := h.State.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.DeleteCertAllCA(keyID)

}
