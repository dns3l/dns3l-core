package otc

import (
	"fmt"
	"net"
	"strings"

	"github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/util"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/dns/v2/recordsets"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/dns/v2/zones"
	"github.com/sirupsen/logrus"
)

// Only allows legal TTL range.
func validateTTL(ttl uint32) error {
	if ttl < 0x80000000 {
		//msb must not be set -> can blow up e.g. OTC module
		return nil
	}
	return fmt.Errorf("TTL of %d exceeds limit of 2^31", ttl)
}

// DNSSetter is an implementation of the dns01.DNSSetter interface which uses the
// gophertelekomcloud OpenStack client fork to set/remove a DNS01 challenge in the OTC's
// DNS service.

// SetAcmeChallengeRecord sets a DNS01 challenge TXT record in the OTC's DNS service.
// Automatically determines the zone which needs to be changed.
func (s *DNSProvider) SetRecordAcmeChallenge(domainName string, challenge string) error {

	err := common.ValidateAcmeChallengeInput(challenge)
	if err != nil {
		return err
	}

	dName := util.GetDomainFQDNDot(domainName)

	err = common.ValidateDomainName(dName)
	if err != nil {
		return err
	}

	dName, err = common.EnsureAcmeChallengeFormat(dName)
	if err != nil {
		return err
	}

	ttl := common.ValidateSetDefaultTTL(s.C.TTL.Challenge, 300)

	log.WithFields(logrus.Fields{"domainName": dName, "ttl": ttl, "challenge": challenge}).Debug("Setting ACME challenge record.")

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.C.OSRegion})
	if err != nil {
		return fmt.Errorf("error while getting DNS API endpoint: %v", err)
	}

	zone, err := getManagingZone(client, dName)
	if err != nil {
		return fmt.Errorf("error while getting managing zone: %v", err)
	}

	err = setRecordInZone(
		client, zone.ID, dName, "TXT", ttl,
		fmt.Sprintf("\"%s\"", challenge))
	if err != nil {
		return fmt.Errorf("error while setting TXT record in zone: %v", err)
	}

	return nil

}

// SetAcmeChallengeRecord sets a DNS01 challenge TXT record in the OTC's DNS service.
// Automatically determines the zone which needs to be changed.
func (s *DNSProvider) SetRecordA(domainName string, ttl uint32, addr net.IP) error {

	err := validateTTL(ttl)
	if err != nil {
		return err
	}

	dName := util.GetDomainFQDNDot(domainName)

	err = common.ValidateDomainName(dName)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{"domainName": dName, "ttl": ttl, "addr": addr}).Debug("Setting A record.")

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.C.OSRegion})
	if err != nil {
		return fmt.Errorf("error while getting DNS API endpoint: %v", err)
	}

	zone, err := getManagingZone(client, dName)
	if err != nil {
		return fmt.Errorf("error while getting managing zone: %v", err)
	}

	err = setRecordInZone(client, zone.ID, dName, "A", ttl, addr.String())
	if err != nil {
		return fmt.Errorf("error while setting TXT record in zone: %v", err)
	}

	return nil

}

// DeleteTXTRecord removes a previously set DNS01 challenge TXT
// record in the OTC's DNS service. Automatically determines the zone
// which needs to be changed.
func (s *DNSProvider) DeleteRecordAcmeChallenge(domainName string) error {

	dName := util.GetDomainFQDNDot(domainName)

	err := common.ValidateDomainName(dName)
	if err != nil {
		return err
	}

	dName, err = common.EnsureAcmeChallengeFormat(dName)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{"domainName": dName}).Debug("Deleting ACME challenge record.")

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.C.OSRegion})
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

	dName := util.GetDomainFQDNDot(domainName)

	err := common.ValidateDomainName(dName)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{"domainName": dName}).Debug("Deleting A record.")

	provider, err := s.Auth()
	if err != nil {
		return err
	}

	client, err := openstack.NewDNSV2(provider, golangsdk.EndpointOpts{Region: s.C.OSRegion})
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
	var longestZone *zones.Zone
	for i := range allZones {
		zone := &allZones[i]
		if strings.HasSuffix(domainName, zone.Name) {
			if longestZone == nil || len(longestZone.Name) < len(zone.Name) {
				longestZone = zone
			}
		}
	}

	if longestZone == nil {
		return nil, fmt.Errorf("no appropriate zone could be found for domain name %s", domainName)
	}

	log.WithField("zoneName", longestZone.Name).WithField("domain", domainName).Debug("Selected zone.")

	return longestZone, nil
}

func setRecordInZone(sc *golangsdk.ServiceClient, zoneID string, domainName string, rtype string, ttl uint32, challenge string) error {

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
		if rr.Name != domainName {
			// somehow the filter in listOpts does not work
			continue
		}
		if strings.HasPrefix(rr.Description, "dns3l") {
			log.Infof("Deleting previously existing record set by dns3l %s", rr.Name)
			err := recordsets.Delete(sc, zoneID, rr.ID).ExtractErr()
			if err != nil {
				return fmt.Errorf("error while deleting previously existing TXT record set: %v", err)
			}
		}
	}

	createOpts := recordsets.CreateOpts{
		Name:        domainName,
		Type:        rtype,
		TTL:         int(ttl),
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
		if rr.Name != domainName {
			// somehow the filter in listOpts does not work
			continue
		}
		if strings.HasPrefix(rr.Description, "dns3l") {
			log.Debugf("Deleting record set by dns3l %s", rr.Name)
			return recordsets.Delete(sc, zoneID, rr.ID).ExtractErr()
		}
	}
	log.Infof("No record exists with domain name %s, nothing to clean up, fine", domainName)
	return nil

}
