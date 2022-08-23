package clitypes

import (
	"fmt"
	"strconv"

	// "github.com/dta4/dns3l-go/dns/otc"

	"github.com/dta4/dns3l-go/dns/types"
)

/*DNSAddType ---------------------------------------------------------------------------------
dns:
   add     	Add A, CNAME, TXT, ... to DNS backend
   			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
  				TYPE: A|TXT|CNAME|... Resource record type
  				DATA: IP|STR|NAME IP address, string or canonical name based on TYPE
				SECONDS: UINT, TTL in seconds
			Options:
  				-b, --backend   | Name of the sections in the config.yaml, which contains the configuration for this DNS backend
  				-f, --force     | Change existing DATA
				-i, --id  		| id e.g. username or accesskey depends on the type of the DNS backend
				-s  --secret  	| password or secret depends on the type of the DNS backend
---------------------------------------------------------------------------------------- */
type DNSAddType struct {
	Verbose    bool
	JSONOutput bool
	Provider   string
	Backend    string
	Force      bool
	ID         string
	Secret     string
	FQDN       string
	Type       string
	Data       string
	Seconds    int
	P          types.DNSProvider
}

// Init inits the parameters of the command dns add
func (dnsAdd *DNSAddType) Init(verbose bool, jsonOutput bool, backend string, force bool, id string, secret string, args []string) {
	dnsAdd.Verbose = verbose
	dnsAdd.JSONOutput = jsonOutput
	dnsAdd.Backend = backend
	dnsAdd.Force = force
	dnsAdd.ID = id
	dnsAdd.Secret = secret
	dnsAdd.FQDN = args[0]
	dnsAdd.Type = args[1]
	dnsAdd.Data = args[2]
	if val, err := strconv.Atoi(args[3]); err == nil {
		dnsAdd.Seconds = val
	} else {
		fmt.Printf("Command DNS add Argument for Seconds is not valid!! Set to 300 \n")
		dnsAdd.Seconds = 300
	}
	// viper read the config from the requested DNS provider from the yaml file with the help of viper
	dnsAdd.P = setProvider(backend, id, secret)

}

// PrintParams prints the parameters of the command dns add
func (dnsAdd *DNSAddType) PrintParams() {
	if dnsAdd.Verbose {
		fmt.Printf("Command DNS add called \n")
		PrintViperConfigDNS()
		fmt.Printf("JsonOutput 	'%t' \n", dnsAdd.JSONOutput)
		fmt.Printf("Backend  	'%s' \n", dnsAdd.Backend)
		fmt.Printf("User 	    '%s' \n", dnsAdd.ID)
		fmt.Printf("Password 	'%s' \n", dnsAdd.Secret)
		fmt.Printf("Force         	'%t' \n", dnsAdd.Force)
		fmt.Printf("dnsFQDN         '%s'  is Check:= '%t' \n", dnsAdd.FQDN, CheckTypeOfFQDN(dnsAdd.FQDN))
		fmt.Printf("dnsType         '%s'  is Check:= '%t'\n", dnsAdd.Type, CheckTypeOfDNSRecord(dnsAdd.Type))
		fmt.Printf("dnsData         '%s'  is Check:= '%t'\n", dnsAdd.Data, CheckTypeOfData(dnsAdd.Data, dnsAdd.Type))
		// print params of dns provider
		PrintDNSProvider(dnsAdd.P)
	}
}

// CheckParams prints the parameters of the command dns add
func (dnsAdd *DNSAddType) CheckParams() bool {
	// check provider
	// check api
	OK := true
	if !CheckTypeOfFQDN(dnsAdd.FQDN) {
		OK = false
		fmt.Printf("dnsFQDN  '%s' is not valid \n", dnsAdd.FQDN)
	}
	if !CheckTypeOfDNSRecord(dnsAdd.Type) {
		OK = false
		fmt.Printf("dnsType  '%s'  is not valid \n", dnsAdd.Type)
	}
	if !CheckTypeOfData(dnsAdd.Data, dnsAdd.Type) {
		OK = false
		fmt.Printf("dnsData  '%s'  is not valid \n", dnsAdd.Data)
	}
	// dnsAdd.Provider
	/* if dnsAdd.Provider == dnsProviders[0]
	{
		viper.BindEnv("dns.api", viperShellPrefix+"_DNS__API")
		viper.BindEnv("dns.provider", viperShellPrefix+"_DNS_PROVIDER")
	} */
	return OK
}
