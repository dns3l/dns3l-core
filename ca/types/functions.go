package types

import (
	"fmt"
	"time"

	dnstypes "github.com/dta4/dns3l-go/dns/types"
	"github.com/dta4/dns3l-go/state"
)

type CertificateResources struct {
	Domains     []string
	Certificate string
	Key         string
	Chain       string
	FullChain   string
}

type CertificateClaimInfo struct {
	Name          string
	NameRZ        string
	Domains       []string
	IssuedBy      string
	IssuedByEmail string
	//TODO implement hints
}

type CertificateRenewInfo struct {
	CAID        string
	CertKey     string
	ExpiresAt   time.Time
	NextRenewal time.Time
}

func (c *CertificateRenewInfo) String() string {
	return fmt.Sprintf("%s, %s, exp=%s rnw=%s", c.CAID, c.CertKey, c.ExpiresAt.Format(time.RFC3339), c.NextRenewal.Format(time.RFC3339))
}

type CAConfigurationContext interface {
	GetStateProvider() state.StateProvider
	GetDNSProvider(provID string) (dnstypes.DNSProvider, bool)
}
