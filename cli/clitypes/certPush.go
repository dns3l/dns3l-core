package clitypes

import (
	"fmt"
	"os"
)

/*CertPushType  ---------------------------------------------------------------------------------
 cert	Push
	Push cert to DNS3L none ACME CAs
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]
	-f, --force     | Overwrite existing CSR/key
args
	FQDN: FQDN as certificate name
	CRT.pem 	Leaf cert PEM
	CHN.pem		Concatenated intermediate and root cert chain PEM
----------------------------------------------------------------------------------------- */
type CertPushType struct {
	Verbose     bool
	JSONOutput  bool
	Force       bool
	APIEndPoint string
	AccessToken string
	CA          string
	FQDN        string
	CRTpem      string
	CHNpem      string
}

// PrintParams prints the parameters of the command cert push
func (CertPush *CertPushType) PrintParams() {
	if CertPush.Verbose {
		fmt.Fprintf(os.Stderr, "Command Cert Push called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "JsonOut 	'%t' \n", CertPush.JSONOutput)
		fmt.Fprintf(os.Stderr, "Force         	'%t' \n", CertPush.Force)
		fmt.Fprintf(os.Stderr, "Api EndPoint  	'%s' \n", CertPush.APIEndPoint)
		fmt.Fprintf(os.Stderr, "AccessToken  (4 < len)='%t' \n", (len(CertPush.AccessToken) > 4))
		fmt.Fprintf(os.Stderr, "CA          	'%s' \n", CertPush.CA)
		fmt.Fprintf(os.Stderr, "FQDN         '%s' is OK '%t' \n", CertPush.FQDN, CheckTypeOfFQDN(CertPush.FQDN))
		fmt.Fprintf(os.Stderr, "CRT.pem      '%s' \n", CertPush.CRTpem)
		fmt.Fprintf(os.Stderr, "CHN.pem,     '%s' \n", CertPush.CHNpem)
	}
	fmt.Fprintf(os.Stderr, "this command is not implemented yet\n")
}

// CheckParams prints the parameters of the command cert push
func (CertPush *CertPushType) CheckParams() bool {
	// check api
	// check CA
	// check CRT.pem
	// check CHN.pem
	OK := true
	if !CheckTypeOfFQDN(CertPush.FQDN) {
		OK = false
		fmt.Printf("Cert FQDN  '%s' is not valid \n", CertPush.FQDN)
	}
	if len(CertPush.AccessToken) <= 4 {
		OK = false
		fmt.Fprintf(os.Stderr, "ERRORE: Cert AccessToken  heuristic check failed \n")
	}

	return OK
}
