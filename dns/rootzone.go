package dns

import (
	"fmt"
	"strings"

	"github.com/dta4/dns3l-go/util"
)

type RootZone struct {
	Root           string   `yaml:"root" validate:"required,fqdnDotAtEnd"`
	DNSProvAutoDNS string   `yaml:"autodns" validate:"alphanumUnderscoreDash,lt=32"`
	DNSProvAcme    string   `yaml:"acmedns" validate:"alphanumUnderscoreDash,lt=32"`
	CAs            []string `yaml:"ca" validate:"dive,required,alphanumUnderscoreDash|wildcard"`
}

type RootZones []*RootZone

func (rz *RootZone) DomainIsInZone(domainName string) bool {
	return strings.HasSuffix(util.GetDomainFQDNDot(domainName), rz.Root)
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
		return nil, fmt.Errorf("no appropriate zone is configured for domain name %s", domainName)
	}

	return longestZone, nil
}
