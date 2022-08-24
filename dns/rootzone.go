package dns

import (
	"fmt"
	"strings"

	"github.com/dns3l/dns3l-core/util"
)

type RootZone struct {
	Root           string   `yaml:"root" validate:"required,fqdnDotAtEnd"`
	DNSProvAutoDNS string   `yaml:"autodns" validate:"alphanumUnderscoreDash,lt=32"`
	DNSProvAcme    string   `yaml:"acmedns" validate:"alphanumUnderscoreDash,lt=32"`
	CAs            []string `yaml:"ca" validate:"dive,required,alphanumUnderscoreDash|wildcard"`
}

type RootZones []*RootZone

func (rz *RootZone) DomainIsInZone(domainName string) bool {
	domainSanitized := util.GetDomainFQDNDot(domainName)
	zoneSuffix := ensurePrependDot(rz.Root)
	return len(domainSanitized) > len(zoneSuffix) &&
		strings.HasSuffix(domainSanitized, zoneSuffix)
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

func ensurePrependDot(zoneroot string) string {
	if strings.HasPrefix(zoneroot, ".") {
		return zoneroot
	}
	return fmt.Sprintf(".%s", zoneroot)
}
