package clitypes

import (
	"fmt"
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
	CA          string
	FQDN        string
	CRTpem      string
	CHNpem      string
}

// PrintParams prints the parameters of the command cert push
func (CertPush CertPushType) PrintParams() {
	if CertPush.Verbose {
		fmt.Printf("Command Cert Push called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	'%t' \n", CertPush.JSONOutput)
		fmt.Printf("Force         	'%t' \n", CertPush.Force)
		fmt.Printf("Api EndPoint  	'%s' \n", CertPush.APIEndPoint)
		fmt.Printf("CA          	'%s' \n", CertPush.CA)
		fmt.Printf("FQDN         '%s' is OK '%t' \n", CertPush.FQDN, CheckTypeOfFQDN(CertPush.FQDN))
		fmt.Printf("CRT.pem      '%s' \n", CertPush.CRTpem)
		fmt.Printf("CHN.pem,     '%s' \n", CertPush.CHNpem)
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command cert push
func (CertPush CertPushType) CheckParams() bool {
	// check api
	// check CA
	// check CRT.pem
	// check CHN.pem
	OK := true
	if !CheckTypeOfFQDN(CertPush.FQDN) {
		OK = false
		fmt.Printf("Cert FQDN  '%s' is not valid \n", CertPush.FQDN)
	}

	return OK
}
