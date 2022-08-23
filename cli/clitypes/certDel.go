package clitypes

import (
	"fmt"
)

/*CertDelType ---------------------------------------------------------------------------------
 cert	del
 	Delete cert managed by DNS3L
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]
Args
	FQDN: FQDN as certificate name
----------------------------------------------------------------------------------------- */
type CertDelType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	CA          string
	FQDN        string
}

// PrintParams prints the parameters of the command cert del
func (CertDel CertDelType) PrintParams() {
	if CertDel.Verbose {
		fmt.Printf("Command Cert Delete called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	'%t' \n", CertDel.JSONOutput)
		fmt.Printf("Api EndPoint  	'%s' \n", CertDel.APIEndPoint)
		fmt.Printf("CA          	'%s' \n", CertDel.CA)
		fmt.Printf("FQDN         '%s' is OK '%t' \n", CertDel.FQDN, CheckTypeOfFQDN(CertDel.FQDN))
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command cert del
func (CertDel CertDelType) CheckParams() bool {
	// check api
	// check CA
	OK := true
	if !CheckTypeOfFQDN(CertDel.FQDN) {
		OK = false
		fmt.Printf("Cert FQDN  '%s' is not valid \n", CertDel.FQDN)
	}

	return OK
}
