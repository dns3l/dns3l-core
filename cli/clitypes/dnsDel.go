package clitypes

import (
	"fmt"
	"os"

	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/spf13/viper"
)

/*DNSDelType --------------------------------------------------------------------------------
dns:
   add     	Delete RR from DNS backend
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
	UseTresor  bool
	FQDN       string
	Type       string
	Data       string
	P          types.DNSProvider
}

// Init inits the parameters of the command dns del
func (dnsDel *DNSDelType) Init(verbose bool, jsonOutput bool, backend string, id string, secret string, useTresor bool, args []string) {
	dnsDel.Verbose = verbose
	dnsDel.JSONOutput = jsonOutput
	dnsDel.Backend = backend
	dnsDel.ID = id
	dnsDel.Secret = secret
	dnsDel.UseTresor = useTresor
	dnsDel.FQDN = args[0]
	dnsDel.Type = args[1]
	dnsDel.Data = args[2]
	// viper read the config from the requested DNS provider from the yaml file with the help of viper
	dnsDel.P = setProvider(backend, id, secret, useTresor, verbose)

}

// PrintParams prints the parameters of the command dns del
func (dnsDel *DNSDelType) PrintParams() {
	if dnsDel.Verbose {
		fmt.Fprintf(os.Stderr, "Command DNS DEL called \n")
		PrintViperConfigDNS()
		fmt.Fprintf(os.Stderr, "JsonOutput 	'%t' \n", dnsDel.JSONOutput)
		fmt.Fprintf(os.Stderr, "Backend  	'%s' \n", dnsDel.Backend)
		fmt.Fprintf(os.Stderr, "User / Id 	      '%s' \n", dnsDel.ID)
		fmt.Fprintf(os.Stderr, "Password / Secret '%s' \n", dnsDel.Secret)
		fmt.Fprintf(os.Stderr, "Use Tresor	'%v' \n", dnsDel.UseTresor)
		fmt.Fprintf(os.Stderr, "dnsFQDN         '%s' Check:='%t' \n", dnsDel.FQDN, CheckTypeOfFQDN(dnsDel.FQDN))
		fmt.Fprintf(os.Stderr, "dnsType         '%s' Check:='%t'\n", dnsDel.Type, CheckTypeOfDNSRecord(dnsDel.Type))
		fmt.Fprintf(os.Stderr, "dnsData         '%s' Check:='%t'\n", dnsDel.Data, CheckTypeOfData(dnsDel.Data, dnsDel.Type))
		PrintDNSProvider(dnsDel.P)
	}
}

// CheckParams prints the parameters of the command dns del
func (dnsDel *DNSDelType) CheckParams() bool {
	OK := true
	if !CheckTypeOfFQDN(dnsDel.FQDN) {
		OK = false
		fmt.Fprintf(os.Stderr, "ERROR: Command DNS DEL dnsFQDN  '%s' is not valid \n", dnsDel.FQDN)
	}
	if !CheckTypeOfDNSRecord(dnsDel.Type) {
		OK = false
		fmt.Fprintf(os.Stderr, "ERROR: Command DNS DEL dnsType  '%s'  is not valid \n", dnsDel.Type)
	}
	if !CheckTypeOfData(dnsDel.Data, dnsDel.Type) {
		OK = false
		fmt.Fprintf(os.Stderr, "ERROR: Command DNS DEL dnsData  '%s'  is not valid \n", dnsDel.Data)
	}
	vip := viper.GetViper()
	host := vip.GetString("dns.providers." + dnsDel.Backend + ".host")
	if host == "" {
		fmt.Fprintf(os.Stderr, "ERROR DNS DEl dns provider not in config '%s' \n", "dns.providers."+dnsDel.Backend+".host")
		OK = false
	}
	return OK
}
