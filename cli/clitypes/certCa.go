package clitypes

import (
	"fmt"
)

/*CertCaType ----------------------------------------------------------------------------
 cert	ca
 List all certificate authorities (CA) utilized by DNS3L
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
----------------------------------------------------------------------------------------- */
type CertCaType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
}

// PrintParams prints the parameters of the command cert ca
func (CertCa CertCaType) PrintParams() {
	if CertCa.Verbose {
		fmt.Printf("Command Cert CA called \n")
		PrintViperConfigCert()
		fmt.Printf("JsonOut 	'%t' \n", CertCa.JSONOutput)
		fmt.Printf("Api EndPoint  	'%s' \n", CertCa.APIEndPoint)
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams  checks the parameters of the command cert ca
func (CertCa CertCaType) CheckParams() bool {
	// check CertCA
	OK := true
	return OK
}
