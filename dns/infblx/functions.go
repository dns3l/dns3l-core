package infblx

import (
	"fmt"
	"net"
	"strings"

	"github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/util"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/sirupsen/logrus"
)

func (p *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	dName, err := common.EnsureAcmeChallengeFormat(domainName)
	if err != nil {
		return err
	}

	ttl := common.ValidateSetDefaultTTL(p.C.TTL.Challenge, 300)

	log.WithFields(logrus.Fields{"domainName": dName, "ttl": ttl, "challenge": challenge}).Debug("Setting ACME challenge record.")

	c, err := p.getIBConnector()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, c.Logout)

	// _, err = p.getHighestPrefixZoneFor(c, p.c.DNSView, domainName)
	// if err != nil {
	// 	return err
	// }

	dNameDot := util.GetDomainNoFQDNDot(dName)
	_, err = c.CreateObject(
		ibclient.NewRecordTXT(
			p.C.DNSView,
			"",
			dNameDot,
			challenge,
			ttl,
			true,
			"Created by dns3l",
			make(ibclient.EA)),
	)

	if err != nil {
		return err
	}

	return nil

}

func (p *DNSProvider) SetRecordA(domainName string, ttl uint32, addr net.IP) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{"domainName": domainName, "ttl": ttl, "addr": addr}).Debug("Setting A record.")

	c, err := p.getIBConnector()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, c.Logout)

	// _, err = p.getHighestPrefixZoneFor(c, p.c.DNSView, domainName)
	// if err != nil {
	// 	return err
	// }

	_, err = c.CreateObject(ibclient.NewRecordA(p.C.DNSView,
		"", util.GetDomainNoFQDNDot(domainName), addr.String(), ttl, true, "Created by dns3l", make(ibclient.EA), ""))
	if err != nil {
		return err
	}

	return nil

}

func (p *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {
	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	dName, err := common.EnsureAcmeChallengeFormat(domainName)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{"domainName": dName}).Debug("Deleting ACME challenge record.")

	c, err := p.getIBConnector()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, c.Logout)

	sf := map[string]string{
		"view": p.C.DNSView,
		"name": util.GetDomainNoFQDNDot((dName)),
	}

	recordTXT := ibclient.NewEmptyRecordTXT()
	var res []ibclient.RecordTXT

	queryParams := ibclient.NewQueryParams(false, sf)
	err = c.GetObject(recordTXT, "", queryParams, &res)

	if err != nil {
		return err
	} else if len(res) <= 0 {
		log.WithField("domainName", dName).Warn("No TXT record could be found, ignoring deletion request.")
	} else if len(res) > 1 {
		log.WithField("domainName", domainName).Warnf("Query resulted in more than one TXT record (%d records), not deleting anything for safety.", len(res))
	}

	_, err = c.DeleteObject(res[0].Ref)

	return err
}

func (p *DNSProvider) DeleteRecordA(domainName string) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{"domainName": domainName}).Debug("Deleting A record.")

	c, err := p.getIBConnector()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, c.Logout)

	sf := map[string]string{
		"view": p.C.DNSView,
		"name": util.GetDomainNoFQDNDot((domainName)),
	}

	recordA := ibclient.NewEmptyRecordA()
	var res []ibclient.RecordA

	queryParams := ibclient.NewQueryParams(false, sf)
	err = c.GetObject(recordA, "", queryParams, &res)

	if err != nil {
		return err
	} else if len(res) <= 0 {
		log.WithField("domainName", domainName).Warn("No A record could be found, ignoring deletion request.")
	} else if len(res) > 1 {
		log.WithField("domainName", domainName).Warnf("Query resulted in more than one A record (%d records), not deleting anything for safety.", len(res))
	}

	_, err = c.DeleteObject(res[0].Ref)

	return err

}

// Will probably be used in the future
// nolint:unused
func (p *DNSProvider) getHighestPrefixZoneFor(c ibclient.IBConnector, dnsView,
	domainName string) (*ibclient.ZoneAuth, error) {

	var res []ibclient.ZoneAuth
	obj := ibclient.NewZoneAuth(ibclient.ZoneAuth{})
	err := c.GetObject(obj, "", &ibclient.QueryParams{}, &res)
	if err != nil {
		return nil, err
	}

	var longestZone *ibclient.ZoneAuth
	for _, zone := range res {

		if strings.HasSuffix(domainName, zone.Fqdn) {
			if longestZone == nil || len(longestZone.Fqdn) < len(zone.Fqdn) {
				longestZone = &zone
			}
		}
	}

	if longestZone == nil {
		return nil, fmt.Errorf("no appropriate zone could be found for domain name %s", domainName)
	}

	return longestZone, nil

}
