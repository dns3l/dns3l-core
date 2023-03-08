package clicmd

import (
	"fmt"
	"net"
	"os"

	//	"github.com/dta4/dns3l-go/cli/clitypes"

	"github.com/dns3l/dns3l-core/cli/clitypes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/* Sub commands dns
remark: the -h, --help  | Show this message and exit works for all, because there is an auto help!


With the help of CreateObject from IBConnector
CreateObject(ibclient.
	NewRecordA(p.C.DNSView,"", util.GetDomainNoFQDNDot(domainName), addr.String(), ttl, true, "Created by dns3l", make(ibclient.EA), ""))
func NewRecordA( view string, zone string, name string, ipAddr string, ttl uint32, useTTL bool, comment string, eas EA, ref string) *RecordA
NewRecordPTR( dnsView string, ptrdname string, useTtl bool, ttl uint32, comment string, ea EA) *RecordPTR

With IBOObjectManager
CreateARecord(		netView string, dnsView string, name     string, cidr string,
	ipAddr string, ttl uint32, useTTL bool, comment string, ea EA) (*RecordA, error)
CreatePTRRecord(networkView string, dnsView string, ptrdname string, recordName string, cidr string,
	ipAddr string, useTtl bool, ttl uint32, comment string, eas EA) (*RecordPTR, error)
-----------------------------------------------------------------------------------------
dns:
   add     	Add A, CNAME, TXT, ... to DNS backend
   			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
  				TYPE: A|TXT|CNAME|... Resource record type
  				DATA: IP|STR|NAME IP address, string or canonical name based on TYPE
			Options:
  				-b, --backend   | Name of the sections in the config.yaml, which contains the configuration for this DNS backend
  				-f, --force     | Change existing DATA
				-i, --id  		| id e.g. username or accesskey depends on the type of the DNS backend
				-s  --secret  	| password or secret depends on the type of the DNS backend

-----------------------------------------------------------------------------------------
   del     	Delete RR from DNS backend
			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
  				TYPE: A|TXT|CNAME|... Resource record type
  				DATA: IP|STR|NAME IP address, string or canonical name based on TYPE
			Options:
   				-b, --backend   | Name of the sections in the config.yaml, which contains the configuration for this DNS backend
				-i, --id  		| id e.g. username or accesskey depends on the type of the DNS backend
				-s  --secret  	| password or secret depends on the type of the DNS backend

-----------------------------------------------------------------------------------------
    list    List DNS backends in the config file

			test connectivity / login ????
-----------------------------------------------------------------------------------------
   	query    Query DNS backend
   			Arguments:
  				FQDN: Fully qualified domain name, potential zone nesting is reflected
			Options:
  				-b, --backend   | Name of the sections in the config.yaml, which contains the configuration for this DNS backend
				-i, --id  		| id e.g. username or accesskey depends on the type of the DNS backend
				-s  --secret  	| password or secret depends on the type of the DNS backend

-----------------------------------------------------------------------------------------
options 	-b 										is used with 	query, 	del, Add
options     -i, 									is used with 	query, 	del, Add
options     -s, 									is used with 	query, 	del, Add
argument   FQDN										is used with 	query, 	del, Add
argument   type and data							is used with 		 	del, Add

for all
-u   --user username:password for login

*/

//  powershell := set of a shell variable is done with
//  $env:$DNS3L_DEBUG=true
// show all enviroment variables
//  dir env:

// ----------------------
// Flags  Flags  Flags
// -------------------

// Backend DNS backend API endpoint
// -b, --backend       | DNS backend API endpoint [$DNS3L_DNS_BACKEND]
var Backend string

var backendDefaultNoOpt = "Infoblox"

// DNSProviderID id or username for login
// -i   --id id or username for login [$DNS3L_DNS_ID]
var DNSProviderID string

// DNSProviderSecret secret e.g. password for login
// -s   --secret  secret e.g. password for login [$DNS3L_DNS_SECRET]
var DNSProviderSecret string

// Use the Secret from the PasswordSafe LINUX Keyring Windows not implemented
var DNSUsePWSafe bool

// ----------------------
// args args args
// --------------_-------
// FQDN: Fully qualified domain name, potential zone nesting is reflected
// var DNS_FQDN string

// TYPE: A|TXT|CNAME|... Resource record type
// var DNS_Type string

// DATA: IP|STR|NAME IP address, string or canonical name based on TYPE
// var DNS_Data string

// DNSAddCmdCb ------------------------------------
// implementation of [dns add]
// Args: FQDN TYPE DATA
// net.IPv4allrouter.IsInterfaceLocalMulticast()
func DNSAddCmdCb(ccmd *cobra.Command, args []string) error {
	if len(args) != 4 {
		return clitypes.NewValueError(1001, fmt.Errorf("DNS ADD requires 4 Arguments but found %d \n", len(args)))
	}
	var dnsAdd clitypes.DNSAddType
	var err error
	err = dnsAdd.Init(Verbose, JSONOutput, Backend, Force, DNSProviderID, DNSProviderSecret, DNSUsePWSafe, args)
	if err != nil {
		return err
	}
	dnsAdd.PrintParams()
	err = dnsAdd.CheckParams()
	if err != nil {
		return err
	}
	// see dnsTypeList in file util.go
	// Ip-Address -> type "a"
	if dnsAdd.Type == string("a") {
		ipAddr := net.ParseIP(dnsAdd.Data)
		if Force {
			var dnsDel clitypes.DNSDelType
			dnsDel.Init(Verbose, JSONOutput, Backend, DNSProviderID, DNSProviderSecret, DNSUsePWSafe, args)
			err := dnsDel.P.DeleteRecordA(dnsDel.FQDN)
			if err != nil {
				// delete fails but the flag force is set and it is not an error
				fmt.Fprintf(os.Stderr, "Info: DNS ADD Delete of the A Record fails '%v' continue with add\n", err.Error())
				fmt.Fprintf(os.Stderr, "Info: DNS ADD This occures due to Flag force, which try to delete the record")
			} else {
				fmt.Fprintf(os.Stderr, "INFO: DNS ADD DNS record A deleted successfully due to Flag force\n")
			}
		}
		err := dnsAdd.P.SetRecordA(dnsAdd.FQDN, uint32(dnsAdd.Seconds), ipAddr)
		if err != nil {
			return clitypes.NewValueError(1005, err)
		}
		fmt.Fprintf(os.Stdout, "OK\n Add DNS record := '%v'", dnsAdd.FQDN)
	}
	return nil
}

// DNSAddCommand DNS add cobra command
var DNSAddCommand = &cobra.Command{
	Use:   "add",
	Short: "Add A, CNAME, TXT, ... to DNS backend",
	Long:  ``,
	RunE:  DNSAddCmdCb,
}

// DNSDelCmdCb ------------------------------------
// implementation of [dns del]
// Args: FQDN TYPE DATA
func DNSDelCmdCb(ccmd *cobra.Command, args []string) error {
	if len(args) != 3 {
		return clitypes.NewValueError(2001, fmt.Errorf("DNS DEL requires 3 Arguments but found %d \n", len(args)))
	}
	var dnsDel clitypes.DNSDelType
	var err error
	err = dnsDel.Init(Verbose, JSONOutput, Backend, DNSProviderID, DNSProviderSecret, DNSUsePWSafe, args)
	if err != nil {
		return err
	}
	dnsDel.PrintParams()
	err = dnsDel.CheckParams()
	if err != nil {
		return err
	}
	// see dnsTypeList in file util.go
	// Ip-Address -> type "a"
	if dnsDel.Type == string("a") {
		err := dnsDel.P.DeleteRecordA(dnsDel.FQDN)
		if err != nil {
			return clitypes.NewValueError(2002, fmt.Errorf("DNS DEL record failed: '%s' not deleted '%v'\n", dnsDel.FQDN, err.Error()))
		}
		if Verbose {
			fmt.Fprintf(os.Stderr, "SUCCESS: DNS record deletet %s \n", dnsDel.FQDN)
		}
	}
	return nil
}

// DNSDelCommand DNS delete cobra command
var DNSDelCommand = &cobra.Command{
	Use:   "del ",
	Short: "Delete RR from DNS backend",
	Long:  ``,
	RunE:  DNSDelCmdCb,
}

// DNSListCmdCb ------------------------------------
// implementation of [dns list]
func DNSListCmdCb(ccmd *cobra.Command, args []string) error {
	clitypes.NotImplemented()
	if len(args) != 0 {
		return clitypes.NewValueError(3001, fmt.Errorf("DNS LIST requires 0 Arguments but found %d \n", len(args)))
	}
	var dnsList = clitypes.DNSListType{Verbose: Verbose, JSONOutput: JSONOutput}
	dnsList.PrintParams()
	err := dnsList.CheckParams()
	if err != nil {
		return clitypes.NewValueError(3002, err)
	}
	// ExitCodes are set in function CheckParams
	return clitypes.NewValueError(3003, fmt.Errorf("ERROR: Command DNS LIST not implemented !\n"))
}

// DNSListCommand DNS list cobra command
var DNSListCommand = &cobra.Command{
	Use:   "list",
	Short: "List DNS backends",
	Long:  ``,
	RunE:  DNSQueryCmdCb,
}

// DNSQueryCmdCb ------------------------------------
// implementation of [dns query]
func DNSQueryCmdCb(ccmd *cobra.Command, args []string) error {
	clitypes.NotImplemented()
	if len(args) != 1 {
		return clitypes.NewValueError(4001, fmt.Errorf("DNS QUERY requires 1 Arguments but found %d \n", len(args)))
	}
	var dnsQuery = clitypes.DNSQueryType{Verbose: Verbose, JSONOutput: JSONOutput,
		Backend: Backend, User: DNSProviderID, Pass: DNSProviderSecret, UsePWSafe: DNSUsePWSafe, FQDN: args[0]}
	dnsQuery.PrintParams()
	err := dnsQuery.CheckParams()
	if err != nil {
		return clitypes.NewValueError(4002, err)
	}
	return clitypes.NewValueError(4003, fmt.Errorf("DNS LIST not implemented !\n"))
}

// DNSQueryCommand DNS query cobra command
var DNSQueryCommand = &cobra.Command{
	Use:   "query",
	Short: "Query DNS backend",
	Long:  ``,
	RunE:  DNSQueryCmdCb,
}

// DNSCommand ------------------------------------
// DNS HEAD COMMAND without a subcommand
var DNSCommand = &cobra.Command{
	Use:   "dns",
	Short: "Deal with DNS3L DNS backends",
	Long:  ``,
	RunE:  DNSCmdCb,
}

// DNSCmdCb this is only called if "add del list or query is missing!!!!"
// and this is not allowed -> exit
func DNSCmdCb(ccmd *cobra.Command, args []string) error {
	return clitypes.NewValueError(3, fmt.Errorf("Reason: DNS command is used without necessary subcommand \n "))
}

func initDNS() {
	vip := viper.GetViper()
	rootCmd.AddCommand(DNSCommand)
	DNSCommand.AddCommand(DNSAddCommand)
	DNSCommand.AddCommand(DNSDelCommand)
	DNSCommand.AddCommand(DNSListCommand)
	DNSCommand.AddCommand(DNSQueryCommand)
	// backend
	DNSCommand.PersistentFlags().StringVarP(&Backend, "backend", "b", vip.GetString("dns.backend"), "points to the configuration for this DNS backend [$DNS3L_DNS_BACKEND]")
	DNSCommand.PersistentFlags().Lookup("backend").NoOptDefVal = backendDefaultNoOpt
	// DNSProvider
	DNSCommand.PersistentFlags().StringVarP(&DNSProviderID, "id", "i", vip.GetString("dns.id"), " Id / User of the DNS backend [$DNS3L_DNS_ID]")
	DNSCommand.PersistentFlags().StringVarP(&DNSProviderSecret, "secret", "s", vip.GetString("dns.secret"), "Secret e.g. password of the DNS backend [$DNS3L_DNS_SECRET]")

	DNSCommand.PersistentFlags().BoolVarP(&DNSUsePWSafe, "PWSafe", "", false, "Use the Password or Secret of the PasswordSafe in case of Linux(Keyring) Windows(not implemented)")
	// we want no NoOptdefault !
	// DNSCommand.PersistentFlags().Lookup("PWSafe").NoOptDefVal = "true"

}
