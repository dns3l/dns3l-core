package clitypes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type PEMFullChainType struct {
	Cert       string `json:"cert"`      // the leaf certificate PEM encoded
	PrivateKey string `json:"key"`       // the unencrypted private key PEM encoded
	Chain      string `json:"chain"`     // All intermediate certificate(s) PEM encoded
	Root       string `json:"root"`      // The root certificate PEM encoded
	Fullchain  string `json:"fullchain"` // cert + chain + root PEM encoded
}

/*CertGetType -------------------------------------------------------------------------------
 cert	get
 	Get PEM certificate (chain) from DNS3L
 Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	   , --ca       | Claim from a specific ACME CA [$DNS3L_CA]
 	-m, --mode  | Chain mode, full = cert + chain (default: full)
       allowed Values
 	     cert        the leaf certificate PEM encoded
	     privatekey  the unencrypted private key PEM encoded
	     chain       All intermediate certificate(s) PEM encoded
	     root        The root certificate PEM encoded
         full	    cert + chain + root PEM encoded
Args
	FQDN: FQDN as certificate name

get /ca/{caId}/crt/{crtName}/pem
----------------------------------------------------------------------------------------- */

// we build a List of
const (
	cert = iota
	privatekey
	chain
	root
	full
)

var ModeVals []string = []string{"cert", "privatekey", "chain", "root", "full"}

func Mode2Enum(name string) int {
	for i, v := range ModeVals {
		if v == name {
			return i
		}
	}
	// this is the default value
	return full
}

func Mode2String(val int) string {
	return ModeVals[val]
}

type CertGetType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	AccessToken string
	CA          string
	Mode        int
	FQDN        string
}

/*
func (CertGet CertGetType) Init(verbose bool, jsonOutput bool, apiEndPoint string, accessToken string, ca string, mode string, args []string) {
	CertGet.Verbose = verbose
	CertGet.JSONOutput = jsonOutput
	CertGet.APIEndPoint = apiEndPoint
	CertGet.AccessToken = accessToken
	CertGet.CA = ca
	CertGet.Mode = Mode2Enum(mode)
	CertGet.FQDN = args[0]
}
*/

// PrintParams prints the parameters of the command cert get
func (CertGet *CertGetType) PrintParams() {
	if CertGet.Verbose {
		fmt.Fprintf(os.Stderr, "Command Cert Delete called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "JsonOut 	         '%t' \n", CertGet.JSONOutput)
		fmt.Fprintf(os.Stderr, "Api EndPoint  	     '%s' \n", CertGet.APIEndPoint)
		fmt.Fprintf(os.Stderr, "AccessToken not empty'%t' \n", (len(CertGet.AccessToken) > 4))
		fmt.Fprintf(os.Stderr, "CA          	     '%s' \n", CertGet.CA)
		fmt.Fprintf(os.Stderr, "Mode          	     '%s' \n", Mode2String(CertGet.Mode))
		fmt.Fprintf(os.Stderr, "FQDN                 '%s' is OK '%t' \n", CertGet.FQDN, CheckTypeOfFQDN(CertGet.FQDN))
	}
}

// CheckParams prints the parameters of the command cert get
func (CertGet *CertGetType) CheckParams() bool {
	// check api
	// check CA
	// mode
	OK := true
	if !CheckTypeOfFQDN(CertGet.FQDN) {
		OK = false
		fmt.Fprintf(os.Stderr, "ERROR: CERT GET FQDN  '%s' is not valid \n", CertGet.FQDN)
	}
	if len(CertGet.AccessToken) <= 4 {
		OK = false
		fmt.Fprintf(os.Stderr, "ERRORE: Cert AccessToken  heuristic check failed \n")
	}
	return OK
}

func (CertGet *CertGetType) DoCommand() {
	// using API Endpoint /ca/{caId}/crt/{crtName}/pem
	var getCertPemUrl string
	if CertGet.APIEndPoint[len(CertGet.APIEndPoint)-1] == byte('/') {
		getCertPemUrl = CertGet.APIEndPoint + "ca/" + CertGet.CA + "/crt/" + CertGet.FQDN + "/pem"
	} else {
		getCertPemUrl = CertGet.APIEndPoint + "/ca/" + CertGet.CA + "/crt/" + CertGet.FQDN + "/pem"
	}
	if CertGet.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command CERT GET: API-END_POINT'%v' \n", getCertPemUrl)
	}
	req, err := http.NewRequest("GET", getCertPemUrl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command cert get full chain: url='%v' Error'%v' \n", getCertPemUrl, err.Error())
	}
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertGet.AccessToken)
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command CERTGET full chain: Request failed Error:= '%v' \n", err.Error())
		return
	}
	defer resp.Body.Close()
	if CertGet.Verbose || resp.StatusCode != 200 {
		PrintFullRespond("INFO: Command CERT GET full chain: Request dump", resp)
	}
	var aPEMFullChain PEMFullChainType
	if err = json.NewDecoder(resp.Body).Decode(&aPEMFullChain); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command CERT GET full chain: No Data received \nUnmarshal Error '%v' \n ", err.Error())
		return
	}
	// extract the data coresponding to MODE FLAG
	var outData string
	switch CertGet.Mode {
	case cert:
		outData = aPEMFullChain.Cert
	case privatekey:
		outData = aPEMFullChain.PrivateKey
	case chain:
		outData = aPEMFullChain.Chain
	case root:
		outData = aPEMFullChain.Root
	case full:
		fallthrough
	default:
		outData = aPEMFullChain.Fullchain
	}
	// create Json Output
	outDataJSON, _ := json.MarshalIndent(outData, "\t", "\t")
	// Screen oder JSON File output
	if CertGet.JSONOutput {
		fmt.Fprintf(os.Stdout, "%v\n", string(outDataJSON))
	} else {
		fmt.Fprintf(os.Stdout, "%v\n", outData)
	}
}
