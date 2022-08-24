package cli

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
func DNSAddCmdCb(ccmd *cobra.Command, args []string) {
	if len(args) != 4 {
		fmt.Printf(" DNS ADD requires 4 Arguments but found %d \n", len(args))
		return
	}
	var dnsAdd clitypes.DNSAddType
	dnsAdd.Init(Verbose, JSONOutput, Backend, Force, DNSProviderID, DNSProviderSecret, args)
	dnsAdd.PrintParams()
	if !dnsAdd.CheckParams() {
		if nil != ccmd.Usage() {
			println("Internal Error")
		}
		return
	}
	// see dnsTypeList in file util.go
	// Ip-Address -> type "a"
	if dnsAdd.Type == string("a") {
		ipAddr := net.ParseIP(dnsAdd.Data)
		if Force {
			var dnsDel clitypes.DNSDelType
			dnsDel.Init(Verbose, JSONOutput, Backend, DNSProviderID, DNSProviderSecret, args)
			err := dnsDel.P.DeleteRecordA(dnsDel.FQDN)
			if err != nil {
				fmt.Println(err.Error())
				fmt.Println("This error occures due to Flag force /n which force a delete of the A Record /n this delete fails continue with add")
			} else {
				fmt.Println("DNS record A deleted due to Flag force")
			}
		}
		// fmt.Println(ipAddr)
		err := dnsAdd.P.SetRecordA(dnsAdd.FQDN, uint32(dnsAdd.Seconds), ipAddr)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Printf("DNS record added %s  %s %d\n", dnsAdd.FQDN, ipAddr.String(), dnsAdd.Seconds)
		}
	}
}

// DNSAddCommand DNS add cobra command
var DNSAddCommand = &cobra.Command{
	Use:   "add",
	Short: "Add A, CNAME, TXT, ... to DNS backend",
	Long:  ``,
	Run:   DNSAddCmdCb,
}

// DNSDelCmdCb ------------------------------------
// implementation of [dns del]
// Args: FQDN TYPE DATA
func DNSDelCmdCb(ccmd *cobra.Command, args []string) {
	if len(args) != 3 {
		fmt.Printf(" DNS DEL requires 3 Arguments but found %d \n", len(args))
		return
	}
	var dnsDel clitypes.DNSDelType
	dnsDel.Init(Verbose, JSONOutput, Backend, DNSProviderID, DNSProviderSecret, args)
	dnsDel.PrintParams()
	if !dnsDel.CheckParams() {
		if nil != ccmd.Usage() {
			println("Internal Error")
		}
		return
	}
	// see dnsTypeList in file util.go
	// Ip-Address -> type "a"
	if dnsDel.Type == string("a") {
		// ipAddr := net.ParseIP(dnsDel.Data)
		// fmt.Println(ipAddr)
		err := dnsDel.P.DeleteRecordA(dnsDel.FQDN)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("DNS record deleted")
		}
	}
}

// DNSDelCommand DNS delete cobra command
var DNSDelCommand = &cobra.Command{
	Use:   "del ",
	Short: "Delete RR from DNS backend",
	Long:  ``,
	Run:   DNSDelCmdCb,
}

// DNSListCmdCb ------------------------------------
// implementation of [dns list]
func DNSListCmdCb(ccmd *cobra.Command, args []string) {
	clitypes.NotImplemented()
	if len(args) != 0 {
		fmt.Printf(" DNS LIST requires 0 Arguments but found %d \n", len(args))
		return
	}
	var dnsList = clitypes.DNSListType{Verbose: Verbose, JSONOutput: JSONOutput}
	dnsList.PrintParams()
	if !dnsList.CheckParams() {
		if nil != ccmd.Usage() {
			println("Internal Error")
		}
		return
	}

}

// DNSListCommand DNS list cobra command
var DNSListCommand = &cobra.Command{
	Use:   "list",
	Short: "List DNS backends",
	Long:  ``,
	Run:   DNSQueryCmdCb,
}

// DNSQueryCmdCb ------------------------------------
// implementation of [dns query]
func DNSQueryCmdCb(ccmd *cobra.Command, args []string) {
	clitypes.NotImplemented()
	if len(args) != 1 {
		fmt.Printf(" DNS QUERY requires 1 Arguments but found %d \n", len(args))
		return
	}
	var dnsQuery = clitypes.DNSQueryType{Verbose: Verbose, JSONOutput: JSONOutput,
		Backend: Backend, User: DNSProviderID, Pass: DNSProviderSecret, FQDN: args[0]}
	dnsQuery.PrintParams()
	if !dnsQuery.CheckParams() {
		if nil != ccmd.Usage() {
			println("Internal Error")
		}
		return
	}
}

// DNSQueryCommand DNS query cobra command
var DNSQueryCommand = &cobra.Command{
	Use:   "query",
	Short: "Query DNS backend",
	Long:  ``,
	Run:   DNSQueryCmdCb,
}

// DNSCommand ------------------------------------
// DNS HEAD COMMAND without a subcommand
var DNSCommand = &cobra.Command{
	Use:   "dns",
	Short: "Deal with DNS3L DNS backends",
	Long:  ``,
	Run:   DNSCmdCb,
}

// DNSCmdCb this is only called if "add del list or query is missing!!!!"
// and this is not allowed -> exit
func DNSCmdCb(ccmd *cobra.Command, args []string) {
	fmt.Fprintf(os.Stderr, "ERROR!  reason: command DNS is used without add, del, list or query \n ")
	if nil != ccmd.Usage() {
		println("Internal Error")
	}
	os.Exit(1)
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

	// -u --user
	DNSCommand.PersistentFlags().StringVarP(&DNSProviderID, "id", "i", vip.GetString("dns.id"), " Id / User of the DNS backend [$DNS3L_DNS_ID]")
	// -p --pass
	DNSCommand.PersistentFlags().StringVarP(&DNSProviderSecret, "secret", "s", vip.GetString("dns.secret"), "Secret e.g. password of the DNS backend [$DNS3L_DNS_SECRET]")
}
