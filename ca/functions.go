package ca

import (
	"github.com/dta4/dns3l-go/ca/common"
	"github.com/dta4/dns3l-go/ca/types"
)

//Provides API-close functions with
type CAFunctionHandler struct {
	Config *Config
	State  types.CAStateManager
}

func (h *CAFunctionHandler) GetResource(keyID, caID, objectType string) (string, string, error) {

	return h.getResourceNoUpd(keyID, caID, objectType)

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
	return "", "", &types.NotFoundError{}

}
