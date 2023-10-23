package types

import (
	"fmt"
	"time"

	dnstypes "github.com/dns3l/dns3l-core/dns/types"
	"github.com/dns3l/dns3l-core/service/auth"
	"github.com/dns3l/dns3l-core/state"
)

type CertificateResources struct {
	Domains     []string
	Certificate string
	Key         string
	RootChain   string
	FullChain   string
}

type CertificateClaimInfo struct {
	Name        string
	NameRZ      string
	Domains     []string
	IssuedBy    *auth.UserInfo
	TTLSelected time.Duration
}

type CertificateRenewInfo struct {
	CAID        string
	CertKey     string
	ExpiresAt   time.Time
	NextRenewal time.Time
	TTLSelected time.Duration
}

func (c *CertificateRenewInfo) String() string {
	return fmt.Sprintf("%s, %s, exp=%s rnw=%s", c.CAID, c.CertKey, c.ExpiresAt.Format(time.RFC3339), c.NextRenewal.Format(time.RFC3339))
}

type CAConfigurationContext interface {
	GetStateProvider() state.StateProvider
	GetDNSProvider(provID string) (dnstypes.DNSProvider, bool)
}
