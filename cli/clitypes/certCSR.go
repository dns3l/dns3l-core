package clitypes

import (
	"fmt"
	"os"
)

/*CertCSRType hold the data for command cert Csr
cert	CSR
 	Create CSR and unencrypted private key for DNS3L none ACME CAs
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]
	-f, --force     | Overwrite existing CSR/key
args
	FQDN: FQDN as certificate name
----------------------------------------------------------------------------------------- */
type CertCSRType struct {
	Verbose     bool
	JSONOutput  bool
	Force       bool
	APIEndPoint string
	AccessToken string
	CA          string
	FQDN        string
}

// PrintParams prints the parameters of the command cert csr
func (CertCSR *CertCSRType) PrintParams() {
	if CertCSR.Verbose {
		fmt.Printf("Command Cert CSR called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	'%t' \n", CertCSR.JSONOutput)
		fmt.Printf("Force         	'%t' \n", CertCSR.Force)
		fmt.Printf("Api EndPoint  	'%s' \n", CertCSR.APIEndPoint)
		fmt.Fprintf(os.Stderr, "AccessToken  (4 < len)='%t' \n", (len(CertCSR.AccessToken) > 4))
		fmt.Printf("CA          	'%s' \n", CertCSR.CA)
		fmt.Printf("FQDN         '%s' is OK '%t' \n", CertCSR.FQDN, CheckTypeOfFQDN(CertCSR.FQDN))
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams  checks the parameters of the command cert csr
func (CertCSR *CertCSRType) CheckParams() bool {
	// check api
	// check CA
	OK := true
	if !CheckTypeOfFQDN(CertCSR.FQDN) {
		OK = false
		fmt.Printf("Cert FQDN  '%s' is not valid \n", CertCSR.FQDN)
	}
	if len(CertCSR.AccessToken) <= 4 {
		OK = false
		fmt.Fprintf(os.Stderr, "ERRORE: Cert AccessToken  heuristic check failed \n")
	}

	return OK
}
