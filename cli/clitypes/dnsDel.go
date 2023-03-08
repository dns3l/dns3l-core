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
	UsePWSafe  bool
	FQDN       string
	Type       string
	P          types.DNSProvider
}

// Init inits the parameters of the command dns del
func (dnsDel *DNSDelType) Init(verbose bool, jsonOutput bool, backend string, id string, secret string, usePWSafe bool, args []string) error {
	dnsDel.Verbose = verbose
	dnsDel.JSONOutput = jsonOutput
	dnsDel.Backend = backend
	dnsDel.ID = id
	dnsDel.Secret = secret
	dnsDel.UsePWSafe = usePWSafe
	dnsDel.FQDN = args[0]
	dnsDel.Type = args[1]
	var err error
	// viper read the config from the requested DNS provider from the yaml file with the help of viper
	dnsDel.P , err = setProvider(backend, id, secret, usePWSafe, verbose)
	if err != nil {
		return err
	}
	return nil

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
		fmt.Fprintf(os.Stderr, "Use Password Safe	'%v' \n", dnsDel.UsePWSafe)
		fmt.Fprintf(os.Stderr, "dnsFQDN         '%s' Check:='%t' \n", dnsDel.FQDN, CheckTypeOfFQDN(dnsDel.FQDN))
		fmt.Fprintf(os.Stderr, "dnsType         '%s' Check:='%t'\n", dnsDel.Type, CheckTypeOfDNSRecord(dnsDel.Type))
		PrintDNSProvider(dnsDel.P)
	}
}

// CheckParams prints the parameters of the command dns del
func (dnsDel *DNSDelType) CheckParams() error {
	OK := true
	var errText string
	if !CheckTypeOfFQDN(dnsDel.FQDN) {
		OK = false
		errText = fmt.Sprintf("Command DNS DEL dnsFQDN  '%s' is not valid \n", dnsDel.FQDN)
	}
	if !CheckTypeOfDNSRecord(dnsDel.Type) {
		OK = false
		errText = fmt.Sprintf("Command DNS DEL dnsType  '%s'  is not valid \n", dnsDel.Type)
	}
	vip := viper.GetViper()
	host := vip.GetString("dns.providers." + dnsDel.Backend + ".host")
	if host == "" {
		errText = fmt.Sprintf("Command DNS DEl dns provider not in config '%s' \n", "dns.providers."+dnsDel.Backend+".host")
		OK = false
	}
	if !OK {
		return NewValueError(2101, fmt.Errorf(errText))
	}
	return nil
}
