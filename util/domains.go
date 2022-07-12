package util

import "strings"

// This is default notation in dns3l
func GetDomainFQDNDot(d string) string {
	if !strings.HasSuffix(d, ".") {
		d = d + "."
	}

	return d
}

//Some providers like Infoblox don't want the dot despite being a FQDN...
func GetDomainNoFQDNDot(d string) string {
	return strings.TrimSuffix(d, ".")
}

func IsWildcard(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}
