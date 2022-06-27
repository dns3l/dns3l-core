package types

import dnstypes "github.com/dta4/dns3l-go/dns/types"

type CAProviderInfo struct {
	Name        string
	Description string
	LogoPath    string
	URL         string
	Roots       string
	Type        string
	IsAcme      bool
}

type CAProvider interface {
	//triggered after construction form config to init things
	Init(ctx ProviderConfigurationContext) error

	GetInfo() *CAProviderInfo
	GetTotalValid() int
	GetTotalIssued() int
	IsEnabled() bool

	ClaimCertificate(cinfo *CertificateClaimInfo) error
	CleanupBeforeDeletion(keyID string) error
}

type ProviderConfigurationContext interface {
	GetCAID() string
	GetStateMgr() CAStateManager
	//GetDNSProvider(provID string) (dnstypes.DNSProvider, bool)
	GetDNSProviderForDomain(domain string, challenge bool) (dnstypes.DNSProvider, error)
}
