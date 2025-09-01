package types

import (
	"time"

	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/util"
)

type CAStateManager interface {
	NewSession() (CAStateManagerSession, error)
}

type CAStateManagerSession interface {
	Close() error

	ListCACerts(keyName string, caid string, authzedDomains []string, queryFilter string,
		pginfo *util.PaginationInfo) ([]CACertInfo, error)

	GetCACertByID(keyID string, caID string) (*CACertInfo, error)

	DelCACertByID(keyID string, caID string) error

	PutCACertData(keyname string, caid string, info *CACertInfo, certStr, issuerCertStr string) error

	UpdateCACertData(keyname string, caid string, renewedTime, nextRenewalTime,
		validStartTime, validEndTime time.Time, certStr, issuerCertStr string) error

	GetResource(keyID string, caid string, resourceName string) (string, error)

	GetResources(keyID string, caid string, resourceNames ...string) ([]string, error)

	GetNumberOfCerts(caID string, validonly bool, currentTime time.Time) (uint, error)

	DeleteCertAllCA(keyID string) error

	ListExpired(atTime time.Time, limit uint) ([]CertificateRenewInfo, error)

	ListToRenew(atTime time.Time, limit uint) ([]CertificateRenewInfo, error)

	GetDomains(keyName, caid string) ([]string, error)

	UserHasCerts(user *authtypes.UserInfo, caid string) (bool, error)
}

type CACertInfo struct {
	Name            string
	PrivKey         string
	IssuedBy        *authtypes.UserInfo
	ClaimTime       time.Time
	RenewedTime     time.Time
	NextRenewalTime time.Time
	ValidStartTime  time.Time
	ValidEndTime    time.Time
	LastAccessTime  time.Time
	Domains         []string
	ACMEUser        string
	CertPEM         string
	RenewCount      uint
	AccessCount     uint
	TTLSelected     time.Duration
}
