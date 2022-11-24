package types

import "net"

//Can spawn a new instance of a DNS provider.
//Provider-specific config is unmarshaled into the builder's implementing struct.
type DNSProviderBuilder interface {
	NewInstance() (DNSProvider, error)
}

type DNSProviderInfo struct {
	Name        string
	Feature     []string
	ZoneNesting bool
}

type DNSProvider interface {
	GetInfo() *DNSProviderInfo
	GetPrecheckConfig() *PrecheckConfig
	SetRecordAcmeChallenge(domainName string, challenge string) error
	SetRecordA(domainName string, ttl uint32, addr net.IP) error
	DeleteRecordAcmeChallenge(domainName string) error
	DeleteRecordA(domainName string) error
}
