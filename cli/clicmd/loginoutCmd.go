package clicmd

import (
	"fmt"

	"github.com/dns3l/dns3l-core/cli/clitypes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RingDNSProviderID id or username for login
// -i   --id id or username for login [$DNS3L_DNS_ID]
var LoginDNSID string
var LoginDNSSecret string
var LoginDNSBackend string

var LoginACMEID string
var LoginACMESecret string

var LoginForceOStream bool
var GetPasswordFromTerminal bool

// DNSQueryCmdCb ------------------------------------
// implementation of [dns query]
func LoginDNSCb(ccmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		// fmt.Fprintf(os.Stderr, "ERROR: store login DNS backend requires 0 Arguments but found %d \n", len(args))
		return clitypes.NewValueError(501, fmt.Errorf("Login DNS backend requires 0 Arguments but found %d \n", len(args)))
	}
	var loginDNS clitypes.LoginDNSType
	loginDNS.Init(Verbose, LoginDNSBackend, LoginDNSID, LoginDNSSecret, LoginForceOStream, GetPasswordFromTerminal)
	loginDNS.PrintParams()
	err := loginDNS.CheckParams()
	if err != nil {
		return err
	}
	return loginDNS.DoCommand()
}

// DNSQueryCommand DNS query cobra command
var LoginDNS = &cobra.Command{
	Use:   "dns",
	Short: "store the login data of the DNS backend into a PasswordSafe (supported  linux keyring) ",
	Long:  ``,
	RunE:  LoginDNSCb,
}

// DNSQueryCmdCb ------------------------------------
// implementation of [dns query]
func LoginACMECb(ccmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return clitypes.NewValueError(601, fmt.Errorf("login ACME: requires 0 Arguments but found %d \n %v \n", len(args), args))
	}
	var loginACME clitypes.LoginACMEType
	loginACME.Init(Verbose, LoginACMEID, LoginACMESecret, LoginForceOStream, GetPasswordFromTerminal)
	loginACME.PrintParams()
	err := loginACME.CheckParams()
	if err != nil {
		return err
	}
	return loginACME.DoCommand()
}

// DNSQueryCommand DNS query cobra command
var LoginACME = &cobra.Command{
	Use:   "acme",
	Short: "store the login data of the ACME application into a PasswordSafe (supported linux keyring) ",
	Long:  ``,
	RunE:  LoginACMECb,
}

// KeyringAddCommand ------------------------------------
// keyring Add HEAD COMMAND without a subcommand
var LoginCommand = &cobra.Command{
	Use:   "login",
	Short: "store secrets of DNS backend / ACME in a PasswordSafe, lifetime(this session)  (supported linux keyring)",
	Long:  ``,
	RunE:  LoginCmdCb,
}

// KeyringAddCmdCb this is only called if subcommand is missing!!!!
// and this is not allowed -> exit
func LoginCmdCb(ccmd *cobra.Command, args []string) error {
	return clitypes.NewValueError(3, fmt.Errorf("Reason: command is used without necessary subcommand \n "))
}

func initLogin() {
	vip := viper.GetViper()
	rootCmd.AddCommand(LoginCommand)
	LoginCommand.AddCommand(LoginACME)
	LoginCommand.AddCommand(LoginDNS)

	LoginCommand.PersistentFlags().BoolVarP(&LoginForceOStream, "stdout", "", false, "Force the output of the token to stdout")
	LoginCommand.PersistentFlags().Lookup("stdout").NoOptDefVal = "true"
	LoginCommand.PersistentFlags().BoolVarP(&GetPasswordFromTerminal, "terminal", "", false, "Force the input of the password/token from stdin")
	LoginCommand.PersistentFlags().Lookup("terminal").NoOptDefVal = "true"
	// ACME
	LoginACME.PersistentFlags().StringVarP(&LoginACMEID, "id", "i", vip.GetString("acme.user"), "Id/User of ACME [$DNS3L_ACME_ID] ")
	LoginACME.PersistentFlags().StringVarP(&LoginACMESecret, "secret", "s", vip.GetString("acme.pass"), " Secret/password of ACME [$DNS3L_ACME_SECRET] ")
	// DNS
	LoginDNS.PersistentFlags().StringVarP(&LoginDNSID, "id", "i", vip.GetString("dns.id"), "Id/User of DNS backend [$DNS3L_DNS_ID] ")
	LoginDNS.PersistentFlags().StringVarP(&LoginDNSSecret, "secret", "s", vip.GetString("dns.secret"), "Secret/pass of  DNS Backend [$DNS3L_DNS_SECRET] ")
	LoginDNS.PersistentFlags().StringVarP(&LoginDNSBackend, "backend", "b", vip.GetString("dns.backend"), "points to the configuration for this DNS backend [$DNS3L_DNS_BACKEND]")
	LoginDNS.PersistentFlags().Lookup("backend").NoOptDefVal = backendDefaultNoOpt

}
