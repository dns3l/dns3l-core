package clitypes

import (
	"fmt"
	// "github.com/dns3l/dns3l-core/dns/otc"
	"github.com/dns3l/dns3l-core/dns/types"
)

/*DNSDelType --------------------------------------------------------------------------------
dns:
   add     	Add A, CNAME, TXT, ... to DNS backend
   			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
  				TYPE: A|TXT|CNAME|... Resource record type
  				DATA: IP|STR|NAME IP address, string or canonical name based on TYPE
			Options:
  				-b, --backend   | Name of the sections in the config.yaml, which contains the configuration for this DNS backend
				-i, --id  		| id e.g. username or accesskey depends on the type of the DNS backend
				-s  --secret  	| password or secret depends on the type of the DNS backend
---------------------------------------------------------------------------------------- */
type DNSDelType struct {
	Verbose    bool
	JSONOutput bool
	Backend    string
	ID         string
	Secret     string
	FQDN       string
	Type       string
	Data       string
	P          types.DNSProvider
}

// Init inits the parameters of the command dns del
func (dnsDel *DNSDelType) Init(verbose bool, jsonOutput bool, backend string, id string, secret string, args []string) {
	dnsDel.Verbose = verbose
	dnsDel.JSONOutput = jsonOutput
	dnsDel.Backend = backend
	dnsDel.ID = id
	dnsDel.Secret = secret
	dnsDel.FQDN = args[0]
	dnsDel.Type = args[1]
	dnsDel.Data = args[2]
	// viper read the config from the requested DNS provider from the yaml file with the help of viper
	dnsDel.P = setProvider(backend, id, secret)

}

// PrintParams prints the parameters of the command dns del
func (dnsDel DNSDelType) PrintParams() {
	if dnsDel.Verbose {
		fmt.Printf("Command DNS Del called \n")
		PrintViperConfigDNS()
		fmt.Printf("JsonOutput 	'%t' \n", dnsDel.JSONOutput)
		fmt.Printf("Backend  	'%s' \n", dnsDel.Backend)
		fmt.Printf("User / Id 	      '%s' \n", dnsDel.ID)
		fmt.Printf("Password / Secret '%s' \n", dnsDel.Secret)
		fmt.Printf("dnsFQDN         '%s' is OK '%t' \n", dnsDel.FQDN, CheckTypeOfFQDN(dnsDel.FQDN))
		fmt.Printf("dnsType         '%s'  is OK '%t'\n", dnsDel.Type, CheckTypeOfDNSRecord(dnsDel.Type))
		fmt.Printf("dnsData         '%s'  is OK '%t'\n", dnsDel.Data, CheckTypeOfData(dnsDel.Data, dnsDel.Type))
		PrintDNSProvider(dnsDel.P)
	}
}

// CheckParams prints the parameters of the command dns del
func (dnsDel DNSDelType) CheckParams() bool {
	OK := true
	if !CheckTypeOfFQDN(dnsDel.FQDN) {
		OK = false
		fmt.Printf("dnsFQDN  '%s' is not valid \n", dnsDel.FQDN)
	}
	if !CheckTypeOfDNSRecord(dnsDel.Type) {
		OK = false
		fmt.Printf("dnsType  '%s'  is not valid \n", dnsDel.Type)
	}
	if !CheckTypeOfData(dnsDel.Data, dnsDel.Type) {
		OK = false
		fmt.Printf("dnsData  '%s'  is not valid \n", dnsDel.Data)
	}
	return OK
}
