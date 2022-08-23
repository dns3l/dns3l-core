package clitypes

import (
	"fmt"
)

/*DNSQueryType ----------------------------------------------------------------------------------
   	query    Query DNS backend
   			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
			Options:
  				-p, --provider  | DNS backend [$DNS3L_DNS]
  				-a, --api       | DNS backend API endpoint [$DNS3L_DNSAPI]
----------------------------------------------------------------------------------------- */
type DNSQueryType struct {
	Verbose    bool
	JSONOutput bool
	Backend    string
	User       string
	Pass       string
	FQDN       string
}

// PrintParams prints the parameters of the command dns del
func (DnsQuery DNSQueryType) PrintParams() {
	if DnsQuery.Verbose {
		fmt.Printf("Command DNS query called \n")
		PrintViperConfigDNS()
		fmt.Printf("JsonOutput      '%t' \n", DnsQuery.JSONOutput)
		fmt.Printf("Backend      	'%s' \n", DnsQuery.Backend)
		fmt.Printf("dnsFQDN         '%s' is OK '%t' \n", DnsQuery.FQDN, CheckTypeOfFQDN(DnsQuery.FQDN))
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command dns del
func (DnsQuery DNSQueryType) CheckParams() bool {
	OK := true
	if !CheckTypeOfFQDN(DnsQuery.FQDN) {
		OK = false
		fmt.Printf("dnsFQDN  '%s' is not valid \n", DnsQuery.FQDN)
	}
	return OK
}
