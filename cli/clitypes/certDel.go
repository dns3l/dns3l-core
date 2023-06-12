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
200 = OK
404 = not found
Args
	FQDN: FQDN as certificate name
----------------------------------------------------------------------------------------- */
type CertDelType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	CertToken   string
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
		fmt.Fprintf(os.Stderr, "Token  (4 < len)=      '%t' \n", (len(CertDel.CertToken ) > 4))
		fmt.Fprintf(os.Stderr, "CA          	       '%s' \n", CertDel.CA)
		fmt.Fprintf(os.Stderr, "FQDN                   '%s' is OK '%t' \n", CertDel.FQDN, CheckTypeOfFQDN(CertDel.FQDN))
	}
}

// CheckParams prints the parameters of the command cert del
func (CertDel *CertDelType) CheckParams() error {
	// check api
	// check CA
	var errText string
	OK := true
	if !CheckTypeOfFQDN(CertDel.FQDN) {
		OK = false
		errText = fmt.Sprintf("cert del FQDN  '%s' is not valid", CertDel.FQDN)
	}
	if len(CertDel.CertToken ) <= 4 {
		OK = false
		errText = "cert del Token  heuristic check failed"
	}
	if !OK {
		return NewValueError(14301, fmt.Errorf(errText))
	}
	return nil
}

// var bearer = "Bearer " + FinalCertToken(CertDel.AccessToken)

func (CertDel *CertDelType) DoCommand() error {
	var delCertUrl string
	if CertDel.APIEndPoint[len(CertDel.APIEndPoint)-1] == byte('/') {
		delCertUrl = CertDel.APIEndPoint + "crt/" + CertDel.FQDN
	} else {
		delCertUrl = CertDel.APIEndPoint + "/crt/" + CertDel.FQDN
	}
	req, err := http.NewRequest(http.MethodDelete, delCertUrl, nil)
	if err != nil {
		return NewValueError(14401, fmt.Errorf("cert del: url='%v' Error'%v'", delCertUrl, err.Error()))
	}
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertDel.CertToken )
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if CertDel.Verbose {
			PrintFullRespond("INFO: Command.CertDel: Request dump", resp)
		}
		return NewValueError(14402, fmt.Errorf("cert del: Request failed Error:= '%v'", err.Error()))
	}
	defer resp.Body.Close()
	if CertDel.Verbose {
		PrintFullRespond("INFO: Command.CertDel: Request dump", resp)
	}
	if resp.StatusCode != 200 {
		return NewValueError(20000+resp.StatusCode, fmt.Errorf("request failed http statuscode:= '%v'", resp.StatusCode))
	}
	return nil
}
