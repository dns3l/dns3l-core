package manual

import (
	"net"
	"time"

	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/sirupsen/logrus"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:              p.C.Name,
		Feature:           []string{"A", "TXT"},
		ZoneNesting:       true,
		DefaultAutoDNSTTL: dnscommon.ValidateSetDefaultTTL(p.C.TTL.AutoDNS, 3600),
	}

}

func (p *DNSProvider) GetPrecheckConfig() *types.PrecheckConfig {
	conf := &p.C.PreCheck
	conf.SetDefaults()
	return conf
}

func (s *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {

	log.WithFields(logrus.Fields{"domainName": domainName, "challenge": challenge}).Warnf(
		"ACTION NEEDED: You must set %s to \"%s\" (sleeping %s time)...", domainName, challenge, s.C.WaitTime)
	time.Sleep(s.C.WaitTime)
	log.WithFields(logrus.Fields{"domainName": domainName, "challenge": challenge}).Debug(
		"Sleeping time ended.")

	return nil

}

func (s *DNSProvider) SetRecordA(domainName string, ttl uint32, addr net.IP) error {

	return nil

}

func (s *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {

	log.WithFields(logrus.Fields{"domainName": domainName}).Warn("NOT Deleting manual ACME challenge record.")

	return nil

}

func (s *DNSProvider) DeleteRecordA(domainName string) error {

	return nil

}
