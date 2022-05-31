package infblx

import "errors"

func (s *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {
	return errors.New("not implemented yet")
}

func (s *DNSProvider) SetRecordA(domainName string, ipv4 string) error {
	return errors.New("not implemented yet")
}

func (s *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {
	return errors.New("not implemented yet")
}

func (s *DNSProvider) DeleteRecordA(domainName string) error {
	return errors.New("not implemented yet")
}
