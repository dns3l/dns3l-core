package clicmd

import (
	"fmt"
	"os"

	"github.com/dns3l/dns3l-core/cli/clitypes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/* Sub commands cert
cert:
ca
   		List all certificate authorities (CA) utilized by DNS3L
============================================
list
   		List all certificates managed by DNS3L
============================================
claim ... FQDN [SAN [SAN [...]]]
   		Obtain cert from DNS3L ACME CAs
	flags
		-w, --wildcard  | Create a wildcard (cannot be used with -d)
  		-d, --autodns   | Create an A record (cannot be used with -w)
	args:
		FQDN: FQDN as certificate name
  		SAN: optional list of SAN
============================================
get   ... FQDN
   		Get PEM certificate (chain) from DNS3L
	flags
		-m, --mode  | Chain mode, full = cert + chain (default: full)
	args:
		FQDN: FQDN as certificate name
============================================
del   ... FQDN
		Delete cert managed by DNS3L
	args:
		FQDN: FQDN as certificate name
============================================
csr	... FQDN
		Create CSR and unencrypted private key for DNS3L none ACME CAs
	flags:
	 -f, --force | Overwrite existing CSR/key
	args:
		FQDN: FQDN as certificate name
============================================
push  ... FQDN CRT.pem CHN.pem
		Push cert to DNS3L none ACME CAs
	flags:
	 -f, --force | Overwrite existing CSR/key
	args:
		FQDN: 		FQDN as certificate name
		CRT.pem 	Leaf cert PEM
		CHN.pem		Concatenated intermediate and root cert chain PEM
============================================
Flags for aLL commands
	-a, --api   	| DNS3L API endpoint [$DNS3L_CERT_API]
	-c, --ca        | Claim from a specific ACME CA [$DNS3L_CERT_CA]
	-t, --tok       | Access token for ACME


All Arguments
		FQDN: FQDN as certificate name
  		SAN: optional list of SAN
		CRT.pem 	Leaf cert PEM
		CHN.pem		Concatenated intermediate and root cert chain PEM

*/

// CertAPIEndPoint DNS3L backend API endpoint
// -a, --api       | DNS backend API endpoint [$DNS3L_CERT_API]
var CertAPIEndPoint string

// CertAPIEndPointDefaultNoOpt DNS backend API endpoint noOpt default
var CertAPIEndPointDefaultNoOpt = "NoOptDefault_Cert_APIEndPoint"

// CertCA Claim from a specific ACME CA
// -c, --ca        | Claim from a specific ACME CA [$DNS3L_CERT_CA]
// -c is omitted, because it is already used by --config -> -c
var CertCA string

// CertCADefaultNoOpt  Claim from a specific ACME
var CertCADefaultNoOpt = "NoOptDefault_Cert_APIEndPoint"

// CertWildcard Create a wildcard
// -w, --wildcard  | Create a wildcard (cannot be used with -d)
var CertWildcard bool

// CertAutoDNS  Create an A record
// -d, --autodns   | Create an A record (cannot be used with -w)
var CertAutoDNS string

// CertModeFull Chain mode
// 	-m, --mode  | Chain mode, full = cert + chain (default: full)
//  allowed Values
// 	Cert        the leaf certificate PEM encoded
//	privateKey  the unencrypted private key PEM encoded
//	Chain       All intermediate certificate(s) PEM encoded
//	Root        The root certificate PEM encoded
//  Full	    cert + chain + root PEM encoded
var CertMode string

//  accesstoken for the ACME
//  -t, --tok       | Access token for ACME [$DNS3L_CERT_ACCESSTOKEN]
var CertAccessToken string

// search string for List cert com anndo
// -s --search
var CertSearchFilter string

// hints section in the configfile which will be used for claims
// -h --hints
var CertHintsSection string

// ===========================================================
// cert ca =========================================
var certCaCommand = &cobra.Command{
	Use:   "ca",
	Short: "List all certificate authorities (CA) utilized by DNS3L",
	Long:  ``,
	Run:   certCaCmdCb,
}

func certCaCmdCb(ccmd *cobra.Command, args []string) {
	// 	Verbose bool,  JSONOutput  bool,  APIEndPoint string
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT CA requires 0 Arguments but found %d \n", len(args))
		return
	}
	var certCa clitypes.CertCaType
	certCa.Init(Verbose, JSONOutput, CertAPIEndPoint, CertAccessToken)
	certCa.PrintParams()
	if !certCa.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT CA Internal Error in ccmd.Usage()")
		}
		return
	}
	certCa.DoCommand()
}

// ===========================================================
// cert list =========================================
var certListCommand = &cobra.Command{
	Use:   "list",
	Short: "List all certificates managed by DNS3L",
	Long:  ``,
	Run:   certListCmdCb,
}

func certListCmdCb(ccmd *cobra.Command, args []string) {
	// Verbose bool, JSONOutput bool,  APIEndPoint string,  CA  string
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT LIST requires 0 Arguments but found %d \n", len(args))
		return
	}
	var CertList = clitypes.CertListType{Verbose: Verbose, JSONOutput: JSONOutput, APIEndPoint: CertAPIEndPoint, AccessToken: CertAccessToken, CA: CertCA, Filter: CertSearchFilter}
	CertList.PrintParams()
	if !CertList.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT LIST Internal Error in ccmd.Usage()")
		}
		return
	}
	CertList.DoCommand()
}

// ===========================================================
// cert claim =========================================
var certClaimCommand = &cobra.Command{
	Use:   "claim",
	Short: "Obtain cert from DNS3L ACME CAs",
	Long:  ``,
	Run:   certClaimCmdCb,
}

func certClaimCmdCb(ccmd *cobra.Command, args []string) {
	// 	Verbose bool, JSONOutput  bool, APIEndPoint string, CA string, Wildcard bool, AutoDNS bool, FQDN string, SAN []string
	//  SAN has to be checked
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT CLAIM requires 2 or more Arguments but found %d \n", len(args))
		return
	}
	var CertClaim clitypes.CertClaimType
	CertClaim.Init(Verbose, JSONOutput, CertAPIEndPoint, CertAccessToken, CertCA, CertWildcard, CertAutoDNS, args[0], args[1:], CertHintsSection)
	CertClaim.PrintParams()
	if !CertClaim.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT CLAIM Internal Error in ccmd.Usage()")
		}
		return
	}
	CertClaim.DoCommand()
}

// ===========================================================
// cer get =========================================
var certGetCommand = &cobra.Command{
	Use:   "get",
	Short: "Get PEM certificate (chain) from DNS3L",
	Long:  ``,
	Run:   certGetCmdCb,
}

func certGetCmdCb(ccmd *cobra.Command, args []string) {
	// 	Verbose bool, JSONOutput bool, APIEndPoint string, CA string, Mode string, FQDN string
	// clitypes.NotImplemented()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT GET requires 1 Arguments but found %d \n", len(args))
		return
	}
	var CertGet = clitypes.CertGetType{Verbose: Verbose, JSONOutput: JSONOutput, APIEndPoint: CertAPIEndPoint,
		AccessToken: CertAccessToken, CA: CertCA, Mode: clitypes.Mode2Enum(CertMode), FQDN: args[0]}
	CertGet.PrintParams()
	if !CertGet.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT GET Internal Error in ccmd.Usage()")
		}
		return
	}
	CertGet.DoCommand()
}

// ===========================================================
// cert del =========================================
var certDelCommand = &cobra.Command{
	Use:   "del",
	Short: "Delete cert managed by DNS3L",
	Long:  ``,
	Run:   certDelCmdCb,
}

func certDelCmdCb(ccmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT DEL requires 1 Arguments but found %d \n", len(args))
		return
	}
	var CertDel = clitypes.CertDelType{Verbose: Verbose, JSONOutput: JSONOutput, APIEndPoint: CertAPIEndPoint, AccessToken: CertAccessToken, CA: CertCA, FQDN: args[0]}
	CertDel.PrintParams()
	if !CertDel.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT DEL Internal Error in ccmd.Usage()")
		}
		return
	}
	CertDel.DoCommand()
}

// ===========================================================
// cert csr =========================================
var certCsrCommand = &cobra.Command{
	Use:   "csr",
	Short: "Create CSR and unencrypted private key for DNS3L none ACME CAs",
	Long:  ``,
	Run:   certCsrCmdCb,
}

func certCsrCmdCb(ccmd *cobra.Command, args []string) {
	// 	Verbose bool, JSONOutput  bool, Force  bool, APIEndPoint string, CA string, FQDN string
	clitypes.NotImplemented()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT CSR requires 1 Arguments but found %d \n", len(args))
		return
	}
	var CertCSR = clitypes.CertCSRType{Verbose: Verbose, JSONOutput: JSONOutput, Force: Force,
		APIEndPoint: CertAPIEndPoint, AccessToken: CertAccessToken, CA: CertCA, FQDN: args[0]}
	CertCSR.PrintParams()
	if !CertCSR.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT CSR Internal Error in ccmd.Usage()")
		}
		return
	}
}

// ===========================================================
// cert push =========================================
var certPushCommand = &cobra.Command{
	Use:   "push",
	Short: "Deal with DNS3L X.509 certificates",
	Long:  ``,
	Run:   certPushCmdCb,
}

func certPushCmdCb(ccmd *cobra.Command, args []string) {
	// Verbose bool, JSONOutput bool, Force bool, APIEndPoint string, CA string, FQDN string, CRTpem string, CHNpem string
	clitypes.NotImplemented()
	if len(args) != 3 {
		fmt.Fprintf(os.Stderr, "ERROR: CERT PUSH requires 3 Arguments but found %d \n", len(args))
		return
	}
	var CertPush = clitypes.CertPushType{Verbose: Verbose, JSONOutput: JSONOutput, Force: Force,
		APIEndPoint: CertAPIEndPoint, AccessToken: CertAccessToken, CA: CertCA, FQDN: args[0], CRTpem: args[1], CHNpem: args[2]}
	CertPush.PrintParams()
	if !CertPush.CheckParams() {
		if nil != ccmd.Usage() {
			fmt.Fprintf(os.Stderr, "ERROR: CERT PUSH Internal Error in ccmd.Usage()")
		}
		return
	}
}

// ===========================================================
// cert main command =========================================
var certCommand = &cobra.Command{
	Use:   "cert",
	Short: "Push cert to DNS3L none ACME CAs",
	Long:  ``,
	Run:   certCmdCb,
}

func certCmdCb(ccmd *cobra.Command, args []string) {
	fmt.Fprintf(os.Stderr, "ERROR!  reason: command CERT <????> is used without ca, list, claim, get, del, csr, push or query \n ")
	if nil != ccmd.Usage() {
		fmt.Fprintf(os.Stderr, "ERROR: CERT <????> Internal Error in ccmd.Usage()")
	}
	os.Exit(1)
}

func initCert() {
	vip := viper.GetViper()
	rootCmd.AddCommand(certCommand)
	certCommand.AddCommand(certCaCommand)
	certCommand.AddCommand(certListCommand)
	certCommand.AddCommand(certClaimCommand)
	certCommand.AddCommand(certGetCommand)
	certCommand.AddCommand(certDelCommand)
	certCommand.AddCommand(certCsrCommand)
	certCommand.AddCommand(certPushCommand)

	certCommand.PersistentFlags().StringVarP(&CertAPIEndPoint, "api", "u", vip.GetString("cert.api"), "CERT backend API endpoint [$DNS3L_CERT_API]")
	certCommand.PersistentFlags().Lookup("api").NoOptDefVal = CertAPIEndPointDefaultNoOpt

	certCommand.PersistentFlags().StringVarP(&CertCA, "ca", "", vip.GetString("cert.ca"), "Claim from a specific ACME CA [$DNS3L_CERT_CA]")
	certCommand.PersistentFlags().Lookup("ca").NoOptDefVal = CertCADefaultNoOpt

	certCommand.PersistentFlags().BoolVarP(&CertWildcard, "wildcard", "w", vip.GetBool("cert.wildcard"), "Create a wildcard (cannot be used with -d")
	certCommand.PersistentFlags().Lookup("wildcard").NoOptDefVal = "false"

	certCommand.PersistentFlags().StringVarP(&CertAutoDNS, "autodns", "d", vip.GetString("cert.autodns"), "Create an A record (cannot be used with -w)")
	certCommand.PersistentFlags().Lookup("autodns").NoOptDefVal = ""

	certCommand.PersistentFlags().StringVarP(&CertMode, "mode", "m", vip.GetString("cert.modeFull"), "Chain mode, full = cert + chain (default: full)")
	certCommand.PersistentFlags().Lookup("mode").NoOptDefVal = "full"

	certCommand.PersistentFlags().StringVarP(&CertSearchFilter, "search", "s", vip.GetString("cert.search"), "searche filter for cert list commando e.g. *.dom2.dom1.com")
	certCommand.PersistentFlags().Lookup("mode").NoOptDefVal = "*"

	certCommand.PersistentFlags().StringVarP(&CertHintsSection, "hints", "", "default", "hints section of the configfile to be used for claim default=default")
	certCommand.PersistentFlags().Lookup("hints").NoOptDefVal = "default"

	// if someone fill the ring
	// use the value out of the ring as default value in the command line
	var aToken string
	// we test if somethink is stored in the keyring
	rTok, inErr := clitypes.GetPasswordfromRing("CertAccountToken", false)
	if inErr == nil {
		aToken = string(rTok)
	} else {
		aToken = ""
	}
	envToken := vip.GetString("cert.accessToken")
	if envToken != "" {
		aToken = envToken
	}
	certCommand.PersistentFlags().StringVarP(&CertAccessToken, "tok", "t", aToken, "access token acme ")

}
