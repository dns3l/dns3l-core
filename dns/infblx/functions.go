package infblx

import (
	"errors"
	"net"

	"github.com/dta4/dns3l-go/dns/common"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

func (s *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	dName, err := common.EnsureAcmeChallengeFormat(domainName)
	if err != nil {
		return err
	}

	c, err := s.getIBConnector()
	if err != nil {
		return err
	}

	_, err = c.CreateObject(ibclient.NewRecordTXT(ibclient.RecordTXT{
		View: "TODOdnsView",
		Name: dName,
		Text: challenge,
		Ttl:  360,
	}))

	if err != nil {
		return err
	}

	return nil

}

func (s *DNSProvider) SetRecordA(domainName string, ttl uint32, addr net.IP) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	c, err := s.getIBConnector()
	if err != nil {
		return err
	}

	_, err = c.CreateObject(ibclient.NewRecordA("TODOdnsView",
		"TODOzone", domainName, addr.String(), ttl, true, "TODOcomment", make(ibclient.EA), ""))
	if err != nil {
		return err
	}

	return nil

}

func (s *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {
	return errors.New("not implemented yet")
}

func (s *DNSProvider) DeleteRecordA(domainName string) error {
	return errors.New("not implemented yet")
}
