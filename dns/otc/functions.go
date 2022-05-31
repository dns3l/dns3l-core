package otc

import (
	"fmt"
	"log"
	"strings"

	"github.com/dta4/dns3l-go/dns/common"
	"github.com/huaweicloud/golangsdk"
	"github.com/huaweicloud/golangsdk/openstack"
	"github.com/huaweicloud/golangsdk/openstack/dns/v2/recordsets"
	"github.com/huaweicloud/golangsdk/openstack/dns/v2/zones"
)

const logPrefixFunctions = "[OTCFunctions] "

// DNSSetter is an implementation of the dns01.DNSSetter interface which uses Huawei's
// gophercloud OpenStack client fork to set/remove a DNS01 challenge in the OTC's
// DNS service.

// SetAcmeChallengeRecord sets a DNS01 challenge TXT record in the OTC's DNS service.
// Automatically determines the zone which needs to be changed.
func (s *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {

	err := common.ValidateAcmeChallengeInput(challenge)
	if err != nil {
		return err
	}

	err = common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	dName, err := common.EnsureAcmeChallengeFormat(domainName)
	if err != nil {
		return err
	}

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.c.OSRegion})
	if err != nil {
		return fmt.Errorf("error while getting DNS API endpoint: %v", err)
	}

	zone, err := getManagingZone(client, dName)
	if err != nil {
		return fmt.Errorf("error while getting managing zone: %v", err)
	}

	err = setRecordInZone(client, zone.ID, dName, "TXT", 3600, fmt.Sprintf("\"%s\"", challenge))
	if err != nil {
		return fmt.Errorf("error while setting TXT record in zone: %v", err)
	}

	return nil

}

// SetAcmeChallengeRecord sets a DNS01 challenge TXT record in the OTC's DNS service.
// Automatically determines the zone which needs to be changed.
func (s *DNSProvider) SetRecordA(domainName string, ipv4 string) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	//TODO: IPv4 validation!

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.c.OSRegion})
	if err != nil {
		return fmt.Errorf("error while getting DNS API endpoint: %v", err)
	}

	zone, err := getManagingZone(client, domainName)
	if err != nil {
		return fmt.Errorf("error while getting managing zone: %v", err)
	}

	err = setRecordInZone(client, zone.ID, domainName, "A", 3600, fmt.Sprintf("\"%s\"", ipv4))
	if err != nil {
		return fmt.Errorf("error while setting TXT record in zone: %v", err)
	}

	return nil

}

// DeleteTXTRecord removes a previously set DNS01 challenge TXT
// record in the OTC's DNS service. Automatically determines the zone
// which needs to be changed.
func (s *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	dName, err := common.EnsureAcmeChallengeFormat(domainName)
	if err != nil {
		return err
	}

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.c.OSRegion})
	if err != nil {
		return err
	}

	zone, err := getManagingZone(client, dName)
	if err != nil {
		return err
	}

	err = deleteRecordInZone(client, zone.ID, dName, "TXT")
	if err != nil {
		return err
	}

	return nil

}

// DeleteTXTRecord removes a previously set DNS01 challenge TXT
// record in the OTC's DNS service. Automatically determines the zone
// which needs to be changed.
func (s *DNSProvider) DeleteRecordA(domainName string) error {

	err := common.ValidateDomainName(domainName)
	if err != nil {
		return err
	}

	dName, err := common.EnsureAcmeChallengeFormat(domainName)
	if err != nil {
		return err
	}

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.c.OSRegion})
	if err != nil {
		return err
	}

	zone, err := getManagingZone(client, dName)
	if err != nil {
		return err
	}

	err = deleteRecordInZone(client, zone.ID, dName, "A")
	if err != nil {
		return err
	}

	return nil

}

func getManagingZone(client *golangsdk.ServiceClient, domainName string) (*zones.Zone, error) {

	listOpts := zones.ListOpts{}
	allPages, err := zones.List(client, listOpts).AllPages()
	if err != nil {
		return nil, fmt.Errorf("error while listing zones: %v", err)
	}
	allZones, err := zones.ExtractZones(allPages)
	if err != nil {
		return nil, err
	}
	for _, zone := range allZones {
		if strings.HasSuffix(domainName, zone.Name) {
			return &zone, nil
		}
	}

	return nil, fmt.Errorf("no appropriate zone could be found for domain name %s", domainName)
}

func setRecordInZone(sc *golangsdk.ServiceClient, zoneID string, domainName string, rtype string, ttl int, challenge string) error {

	listOpts := recordsets.ListOpts{
		Type:  rtype,
		Name:  domainName,
		Limit: 1,
	}

	allPages, err := recordsets.ListByZone(sc, zoneID, listOpts).AllPages()
	if err != nil {
		return fmt.Errorf("error while listing records in zone: %v", err)
	}
	allRRs, err := recordsets.ExtractRecordSets(allPages)
	if err != nil {
		return fmt.Errorf("error while extracting record sets: %v", err)
	}

	for _, rr := range allRRs {
		if strings.HasPrefix(rr.Description, "dns3l") {
			log.Printf("%sDeleting previously existing record set by dns3l %s", logPrefixFunctions, rr.Name)
			err := recordsets.Delete(sc, zoneID, rr.ID).ExtractErr()
			if err != nil {
				return fmt.Errorf("error while deleting previously existing TXT record set: %v", err)
			}
		}
	}

	createOpts := recordsets.CreateOpts{
		Name:        domainName,
		Type:        rtype,
		TTL:         ttl,
		Description: fmt.Sprintf("dns3l: autogenerated for %s", domainName),
		Records:     []string{challenge},
	}
	_, err = recordsets.Create(sc, zoneID, createOpts).Extract()
	if err != nil {
		return fmt.Errorf("error while creating TXT record set in zone: %v", err)
	}

	return nil

}

func deleteRecordInZone(sc *golangsdk.ServiceClient, zoneID string, domainName string, rtype string) error {

	listOpts := recordsets.ListOpts{
		Type:  rtype,
		Name:  domainName,
		Limit: 1,
	}

	allPages, err := recordsets.ListByZone(sc, zoneID, listOpts).AllPages()
	if err != nil {
		return fmt.Errorf("error while listing TXT records in zone: %v", err)
	}
	allRRs, err := recordsets.ExtractRecordSets(allPages)
	if err != nil {
		return fmt.Errorf("error while extracting record sets: %v", err)
	}

	for _, rr := range allRRs {
		if strings.HasPrefix(rr.Description, "dns3l") {
			log.Printf("%sDeleting record set by dns3l %s", logPrefixFunctions, rr.Name)
			return recordsets.Delete(sc, zoneID, rr.ID).ExtractErr()
		}
	}
	log.Printf("%sNo record exists with domain name %s, nothing to clean up, fine", logPrefixFunctions, domainName)
	return nil

}
