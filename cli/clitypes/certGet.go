package clitypes

import (
	"fmt"
)

/*CertGetType -------------------------------------------------------------------------------
 cert	get
 	Get PEM certificate (chain) from DNS3L
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	   , --ca        | Claim from a specific ACME CA [$DNS3L_CA]
	-m, --mode      | Chain mode, full = cert + chain (default: full)
Args
	FQDN: FQDN as certificate name
----------------------------------------------------------------------------------------- */
type CertGetType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	CA          string
	Mode        bool
	FQDN        string
}

// PrintParams prints the parameters of the command cert get
func (CertGet CertGetType) PrintParams() {
	if CertGet.Verbose {
		fmt.Printf("Command Cert Delete called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	'%t' \n", CertGet.JSONOutput)
		fmt.Printf("Api EndPoint  	'%s' \n", CertGet.APIEndPoint)
		fmt.Printf("CA          	'%s' \n", CertGet.CA)
		fmt.Printf("Mode          	'%t' \n", CertGet.Mode)
		fmt.Printf("FQDN         '%s' is OK '%t' \n", CertGet.FQDN, CheckTypeOfFQDN(CertGet.FQDN))
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command cert get
func (CertGet CertGetType) CheckParams() bool {
	// check api
	// check CA
	// mode
	OK := true
	if !CheckTypeOfFQDN(CertGet.FQDN) {
		OK = false
		fmt.Printf("Cert FQDN  '%s' is not valid \n", CertGet.FQDN)
	}

	return OK
}
