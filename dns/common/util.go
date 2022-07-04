package common

import (
	"errors"
	"regexp"
)

var domainNameRe = regexp.MustCompile(`^[A-Za-z0-9-_\.]{1,253}\.$`)
var domainNameWildcardRe = regexp.MustCompile(`^[A-Za-z0-9-_\.\*]{1,253}\.$`)

// ValidateDomainName checks if the parameter 'domain' is a valid domain name.
func ValidateDomainName(domain string) error {
	if domain == "" {
		return errors.New("please provide \"domain_name\"")
	}
	if domainNameRe.MatchString(domain) {
		return nil
	}
	return errors.New("domain name string has invalid format or is too long")
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
	return errors.New("domain name string has invalid format or is too long")
}
