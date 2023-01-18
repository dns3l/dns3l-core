package clitypes

import (
	"fmt"
	"net/http"
	"os"
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
	AccessToken string
	CA          string
	FQDN        string
}

// PrintParams prints the parameters of the command cert del
func (CertDel *CertDelType) PrintParams() {
	if CertDel.Verbose {
		fmt.Fprintf(os.Stderr, "Command Cert Delete called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "JsonOut 	           '%t' \n", CertDel.JSONOutput)
		fmt.Fprintf(os.Stderr, "Api EndPoint  	       '%s' \n", CertDel.APIEndPoint)
		fmt.Fprintf(os.Stderr, "AccessToken  (4 < len)='%t' \n", (len(CertDel.AccessToken) > 4))
		fmt.Fprintf(os.Stderr, "CA          	       '%s' \n", CertDel.CA)
		fmt.Fprintf(os.Stderr, "FQDN                   '%s' is OK '%t' \n", CertDel.FQDN, CheckTypeOfFQDN(CertDel.FQDN))
	}
}

// CheckParams prints the parameters of the command cert del
func (CertDel *CertDelType) CheckParams() bool {
	// check api
	// check CA
	OK := true
	if !CheckTypeOfFQDN(CertDel.FQDN) {
		OK = false
		fmt.Fprintf(os.Stderr, "ERROR: Cert FQDN  '%s' is not valid \n", CertDel.FQDN)
	}
	if len(CertDel.AccessToken) <= 4 {
		OK = false
		fmt.Fprintf(os.Stderr, "ERRORE: Cert AccessToken  heuristic check failed \n")
	}
	return OK
}

// var bearer = "Bearer " + FinalCertToken(CertDel.AccessToken)

func (CertDel *CertDelType) DoCommand() {
	var delCertUrl string
	if CertDel.APIEndPoint[len(CertDel.APIEndPoint)-1] == byte('/') {
		delCertUrl = CertDel.APIEndPoint + "crt/" + CertDel.FQDN
	} else {
		delCertUrl = CertDel.APIEndPoint + "/crt/" + CertDel.FQDN
	}
	req, err := http.NewRequest(http.MethodDelete, delCertUrl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command.CertDel: url='%v' Error'%v' \n", delCertUrl, err.Error())
	}
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertDel.AccessToken)
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command.CertDel: Request failed Error:= '%v' \n", err.Error())
		return
	}
	defer resp.Body.Close()
	if CertDel.Verbose || resp.StatusCode != 200 {
		PrintFullRespond("INFO: Command.CertDel: Request dump", resp)
	}
}
