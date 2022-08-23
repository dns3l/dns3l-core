package clitypes

import (
	"fmt"
)

/*DNSListType ----------------------------------------------------------------------------------
    list    List DNS backends
----------------------------------------------------------------------------------------- */
type DNSListType struct {
	Verbose    bool
	JSONOutput bool
}

// PrintParams prints the parameters of the command dns del
func (dnsList DNSListType) PrintParams() {
	if dnsList.Verbose {
		fmt.Printf("Command DNS list called \n")
		PrintViperConfigDNS()
		fmt.Printf("JsonOut 	'%t' \n", dnsList.JSONOutput)
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command dns del
func (dnsList DNSListType) CheckParams() bool {
	OK := true
	return OK
}
