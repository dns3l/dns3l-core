package clitypes

import (
	"fmt"
	"os"
)

/*DNSListType ----------------------------------------------------------------------------------
    list    List DNS backends
----------------------------------------------------------------------------------------- */
type DNSListType struct {
	Verbose    bool
	JSONOutput bool
}

// PrintParams prints the parameters of the command dns list
func (dnsList *DNSListType) PrintParams() {
	if dnsList.Verbose {
		fmt.Fprintf(os.Stderr, "Command DNS list called \n")
		PrintViperConfigDNS()
		fmt.Fprintf(os.Stderr, "JsonOut 	'%t' \n", dnsList.JSONOutput)
	}
	fmt.Printf("THIS COMMAND IS NOT IMPLEMENTED YET\n")
}

// CheckParams prints the parameters of the command dns list
func (dnsList *DNSListType) CheckParams() bool {
	OK := true
	return OK
}
