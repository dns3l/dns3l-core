package types

import (
	"time"
)

type CAStateManager interface {
	NewSession() (CAStateManagerSession, error)
}

type CAStateManagerSession interface {
	Close() error

	GetCACertsByCAID(caid string) ([]CACertInfo, error)

	GetCACertsByKeyName(keyName string) ([]CACertInfo, error)

	GetAllCACerts() ([]CACertInfo, error)

	//returns privKey, expiryTime, error
	GetCACertByID(keyID string, caID string) (*CACertInfo, error)

	DelCACertByID(keyID string, caID string) error

	PutCACertData(update bool, keyname string, caid string, info *CACertInfo, certStr, issuerCertStr string, claimTime time.Time) error

	GetResource(keyID string, caid string, resourceName string) (string, error)

	GetResources(keyID string, caid string, resourceNames ...string) ([]string, error)
}

type CACertInfo struct {
	Name           string
	PrivKey        string
	IssuedByUser   string
	ClaimTime      time.Time
	RenewTime      time.Time
	ValidStartTime time.Time
	ValidEndTime   time.Time
	Domains        []string
	ACMEUser       string
	CertPEM        string
	RenewCount     uint
}
