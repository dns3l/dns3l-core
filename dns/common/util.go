package common

import (
	"errors"
	"fmt"
	"regexp"
)

var domainNameRe = regexp.MustCompile(`^[A-Za-z0-9-_\.]{1,253}$`)
var domainNameWildcardRe = regexp.MustCompile(`^[A-Za-z0-9-_\.\*]{1,253}$`)

// ValidateDomainName checks if the parameter 'domain' is a valid domain name.
func ValidateDomainName(domain string) error {
	if domain == "" {
		return errors.New("please provide \"domain_name\"")
	}
	if domainNameRe.MatchString(domain) {
		return nil
	}
	return fmt.Errorf("domain name string '%s' has invalid format or is too long", domain)
}

// ValidateDomainNameWildcard checks if the parameter 'domain' is a valid
// domain name including the wildcard character used in wildcard certificates
// as the Common Name (CN) or Subject Alternative Name (SAN)
func ValidateDomainNameWildcard(domain string) error {
	if domain == "" {
		return errors.New("please provide \"domain_name\"")
	}
	if domainNameWildcardRe.MatchString(domain) {
		return nil
	}
	return fmt.Errorf("domain name string '%s' has invalid format or is too long", domain)
}

const maxTTL uint32 = 604800

func ValidateSetDefaultTTL(configuredTTL, defaultTTL uint32) uint32 {

	if configuredTTL <= 0 {
		return defaultTTL
	}

	if configuredTTL > maxTTL {
		return maxTTL
	}

	return configuredTTL

}
