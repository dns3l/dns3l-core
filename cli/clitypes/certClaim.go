package clitypes

import (
	"fmt"
)

/*CertClaimType ---------------------------------------------------------------------------
 cert	del
 	Delete cert managed by DNS3L
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]
	-w, --wildcard  | Create a wildcard (cannot be used with -d)
	-d, --autodns   | Create an A record (cannot be used with -w)

Args
	FQDN: FQDN as certificate name
	SAN: optional list of SAN       [SAN [SAN [...]]]
----------------------------------------------------------------------------------------- */
type CertClaimType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	CA          string
	Wildcard    bool
	AutoDNS     bool
	FQDN        string
	SAN         []string
}

// PrintParams  prints the parameters of the command cert claim
func (CertClaim CertClaimType) PrintParams() {
	if CertClaim.Verbose {
		fmt.Printf("Command Cert Delete called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	 '%t' \n", CertClaim.JSONOutput)
		fmt.Printf("Api EndPoint '%s' \n", CertClaim.APIEndPoint)
		fmt.Printf("CA           '%s' \n", CertClaim.CA)
		fmt.Printf("Wildcard     '%t' \n", CertClaim.Wildcard)
		fmt.Printf("AutoDNS      '%t' \n", CertClaim.AutoDNS)
		fmt.Printf("FQDN         '%s' is OK '%t' \n", CertClaim.FQDN, CheckTypeOfFQDN(CertClaim.FQDN))
		//
		fmt.Printf("SAN          '%s'\n", CertClaim.SAN)
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams  checks the parameters of the command cert claim
func (CertClaim CertClaimType) CheckParams() bool {
	// check api
	// check CA
	// Wildcard & AutoDNS schließen sich aus
	// SAN
	OK := true
	if !CheckTypeOfFQDN(CertClaim.FQDN) {
		OK = false
		fmt.Printf("Cert FQDN  '%s' is not valid \n", CertClaim.FQDN)
	}

	return OK
}
