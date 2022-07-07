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

	for _, san := range cinfo.SubjectAltNames {
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

func (h *CAFunctionHandler) GetCertificateInfo(name string,
	subjectAltNames []string) error {

	return fmt.Errorf("GetCertificateInfo(...) not implemented yet")

}

//if caID is "", list for all CAs
func (h *CAFunctionHandler) ListCertificates(caID string, rootZonesFilter []string) error {
	//TODO pagination?

	return fmt.Errorf("ListCertificates(...) not implemented yet")

}

func (h *CAFunctionHandler) GetCertificateResources(keyID, caID string) (*types.CertificateResources, error) {

	log.WithFields(logrus.Fields{"keyID": keyID, "caID": caID}).Debug("Request for certificate resources")

	return h.getResourcesNoUpd(keyID, caID)

}

func (h *CAFunctionHandler) GetCertificateResource(keyID, caID, objectType string) (string, string, error) {

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

	res, err := sess.GetResources(keyID, caID, "priv_key", "cert", "issuer_cert")

	if err != nil {
		return nil, err
	}

	return &types.CertificateResources{
		Certificate: res[1],
		Key:         res[0],
		Chain:       res[2],
		FullChain:   res[1] + res[2],
	}, nil

}

// GetResource returns an autokey-obtained resource (key, cert, issuer etc..) to the user
// of the autokey service. The GetUpdate function must be called first, otherwise
// GetObject will return NotFoundError because the resources are not yet present.
func (h *CAFunctionHandler) getResourceNoUpd(keyID, caID, objectType string) (string, string, error) {

	err := common.ValidateKeyName(keyID)
	if err != nil {
		return "", "", err
	}

	log.Debugf("Request for resource '%s' belonging to key ID '%s'",
		objectType, keyID)

	sess, err := h.State.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()

	switch objectType {
	case "key":
		//"resourceName" of sess.GetResource must never be user input > not validated!
		res, err := sess.GetResource(keyID, caID, "priv_key")
		return res, "application/x-pem-file", err
	case "crt":
		res, err := sess.GetResource(keyID, caID, "cert")
		return res, "application/x-pem-file", err
	case "issuer-cert":
		res, err := sess.GetResource(keyID, caID, "issuer_cert")
		return res, "application/x-pem-file", err
	case "fullchain":
		res, err := sess.GetResources(keyID, caID, "cert", "issuer_cert")
		return res[0] + "\n" + res[1], "application/x-pem-file", err
	}
	return "", "", &cmn.NotFoundError{RequestedResource: keyID}

}
