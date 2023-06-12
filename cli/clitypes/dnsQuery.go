package clitypes

import (
	"fmt"
	"os"
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
	UsePWSafe  bool
	FQDN       string
}

// PrintParams prints the parameters of the command dns query
func (DnsQuery *DNSQueryType) PrintParams() {
	if DnsQuery.Verbose {
		fmt.Fprintf(os.Stderr, "Command DNS QUERY called \n")
		PrintViperConfigDNS()
		fmt.Fprintf(os.Stderr, "JsonOutput      '%t' \n", DnsQuery.JSONOutput)
		fmt.Fprintf(os.Stderr, "Backend      	'%s' \n", DnsQuery.Backend)
		fmt.Fprintf(os.Stderr, "dnsFQDN         '%s' Check:='%t'\n", DnsQuery.FQDN, CheckTypeOfFQDN(DnsQuery.FQDN))
		fmt.Fprintf(os.Stderr, "use password safe     '%t' \n", DnsQuery.UsePWSafe)
	}
}

// CheckParams prints the parameters of the command dns query
func (DnsQuery *DNSQueryType) CheckParams() error {
	OK := true
	var errText string
	if !CheckTypeOfFQDN(DnsQuery.FQDN) {
		OK = false
		errText = fmt.Sprintf("ERROR: Command DNS QUERY dnsFQDN  '%s' is not valid \n", DnsQuery.FQDN)
	}
	if !OK {
		return NewValueError(1301, fmt.Errorf(errText))
	}
	return nil
}
