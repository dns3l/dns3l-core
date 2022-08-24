package clitypes

import (
	"fmt"
)

/*CertListType ---------------------------------------------------------------------------------
 cert	ca
 	List all certificate authorities (CA) utilized by DNS3L
  Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]

----------------------------------------------------------------------------------------- */
type CertListType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	CA          string
}

// PrintParams prints the parameters of the command cert list
func (CertList CertListType) PrintParams() {
	if CertList.Verbose {
		fmt.Printf("Command Cert List called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	'%t' \n", CertList.JSONOutput)
		fmt.Printf("Api EndPoint  	'%s' \n", CertList.APIEndPoint)
		fmt.Printf("CA          	'%s' \n", CertList.CA)
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command cert list
func (CertList CertListType) CheckParams() bool {
	// check api
	// check CA
	OK := true
	return OK
}
