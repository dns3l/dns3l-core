package types

import (
	"time"
)

type CAStateManager interface {
	NewSession() (CAStateManagerSession, error)
}

type CAStateManagerSession interface {
	Close() error

	//returns privKey, expiryTime, error
	GetCACertByID(keyID string, caID string) (*CACertInfo, error)

	DelCACertByID(keyID string, caID string) error

	PutCACertData(update bool, keyname string, caid string, info *CACertInfo, certStr, issuerCertStr string) error

	GetResource(keyID string, caid string, resourceName string) (string, error)

	GetResources(keyID string, caid string, resourceNames ...string) ([]string, error)
}

//A NotFoundError is thrown if the requested resource was not found or is not supposed
//to exist at all
type NotFoundError struct{}

func (e *NotFoundError) Error() string {
	return "Requested resource not found"
}

type CACertInfo struct {
	PrivKey        string
	IssuedByUser   string
	ValidStartTime time.Time
	ExpiryTime     time.Time
	Domains        []string
	ACMEUser       string
}
