package types

import (
	"time"

	"github.com/dta4/dns3l-go/util"
)

type CAStateManager interface {
	NewSession() (CAStateManagerSession, error)
}

type CAStateManagerSession interface {
	Close() error

	ListCACerts(keyName string, caid string, rzFilter []string,
		pginfo *util.PaginationInfo) ([]CACertInfo, error)

	//returns privKey, expiryTime, error
	GetCACertByID(keyID string, caID string) (*CACertInfo, error)

	DelCACertByID(keyID string, caID string) error

	PutCACertData(update bool, keyname string, keyrz string, caid string, info *CACertInfo, certStr, issuerCertStr string) error

	GetResource(keyID string, caid string, resourceName string) (string, []string, error)

	GetResources(keyID string, caid string, resourceNames ...string) ([]string, []string, error)

	GetNumberOfCerts(caID string, validonly bool, currentTime time.Time) (uint, error)

	DeleteCertAllCA(keyID string) error
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
