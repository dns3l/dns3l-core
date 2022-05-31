package common

import (
	"errors"
	"regexp"
)

var domainNameRe = regexp.MustCompile(`^[A-Za-z0-9-_\.]{1,253}$`)

// ValidateDomainName checks if the parameter 'domain' is a valid domain name.
func ValidateDomainName(domain string) error {
	if domain == "" {
		return errors.New("Please provide \"domain_name\"")
	}
	if domainNameRe.MatchString(domain) {
		return nil
	}
	return errors.New("Domain name string has invalid format or is too long")
}
