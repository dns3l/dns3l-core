package types

type AuthorizationInfo interface {

	//If the client is allowed to read public PKI material
	ChkAuthReadDomainPublic(domain string) error
	ChkAuthReadDomainsPublic(domains []string) error

	//If the client is allowed to read private PKI material
	ChkAuthReadDomain(domain string) error
	ChkAuthReadDomains(domains []string) error

	//If the client is allowed to write-access the given domain
	ChkAuthWriteDomain(domain string) error
	ChkAuthWriteDomains(domains []string) error

	GetDomainsAllowed() []string
	CanListPublicData() bool

	GetUserInfo() *UserInfo
	IsAuthzDisabled() bool

	String() string
}
