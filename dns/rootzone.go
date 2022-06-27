package dns

import (
	"fmt"
	"strings"
)

type RootZone struct {
	Root           string   `yaml:"root"`
	DNSProvAutoDNS string   `yaml:"autodns"`
	DNSProvAcme    string   `yaml:"acmedns"`
	CAs            []string `yaml:"ca"`
}

type RootZones []*RootZone

func (rz *RootZone) DomainIsInZone(domainName string) bool {
	return strings.HasSuffix(domainName, rz.Root)
}

func (rz RootZones) GetLowestRZForDomain(domainName string) (*RootZone, error) {

	var longestZone *RootZone
	for _, zone := range rz {
		if zone.DomainIsInZone(domainName) {
			if longestZone == nil || len(longestZone.Root) < len(zone.Root) {
				longestZone = zone
			}
		}
	}

	if longestZone == nil {
		return nil, fmt.Errorf("no appropriate zone could be found for domain name %s", domainName)
	}

	return longestZone, nil
}
