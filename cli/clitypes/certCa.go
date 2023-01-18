package clitypes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
	AccessToken string
}

type CAInfo struct {
	Id          string   `json:"id"`          // Unique supported CA ID
	Name        string   `json:"name"`        // 	Descriptive CA name
	Desc        string   `json:"desc"`        // 	CA description
	Logo        string   `json:"logo"`        // 	CA avatar URI
	Url         string   `json:"url"`         // 	CA URL
	Roots       string   `json:"roots"`       // 	CA root certificates program URL
	TotalValid  int32    `json:"totalValid"`  // Number of issued valid X.509 certificates
	TotalIssued int32    `json:"totalIssued"` // Total number of issued X.509 certificates
	Type        string   `json:"type"`        // Private or public (CT enforcing) CA Allowed: public┃private
	Acme        bool     `json:"acme"`        // 	ACME capable CA
	Rtzn        []string `json:"rtzn"`        // 	Root domain suffixes CA supports
	Enabled     bool     `json:"enable"`      // 	CA enabled for usage
}

// Init inits the parameters of the command cert ca
func (CertCa *CertCaType) Init(verbose bool, jsonOutput bool, certAPIEndPoint string, certAccessToken string) {
	CertCa.Verbose = verbose
	CertCa.JSONOutput = jsonOutput
	CertCa.APIEndPoint = certAPIEndPoint
	CertCa.AccessToken = certAccessToken
}

// PrintParams prints the parameters of the command cert ca
func (CertCa *CertCaType) PrintParams() {
	if CertCa.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command Cert CA called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "INFO: JsonOut 	'%t' \n", CertCa.JSONOutput)
		fmt.Fprintf(os.Stderr, "INFO:Api EndPoint  	'%s' \n", CertCa.APIEndPoint)
		fmt.Fprintf(os.Stderr, "AccessToken  (4 < len)='%t' \n", (len(CertCa.AccessToken) > 4))
	}
}

// CheckParams  checks the parameters of the command cert ca
func (CertCa *CertCaType) CheckParams() bool {
	// check CertCA
	OK := true
	if len(CertCa.AccessToken) <= 4 {
		fmt.Fprintf(os.Stderr, "ERRORE: Cert AccessToken  heuristic check failed \n")
		OK = false
	}
	return OK
}

func (CertCa *CertCaType) DoCommand() {
	var listCaUrl string
	if CertCa.APIEndPoint[len(CertCa.APIEndPoint)-1] == byte('/') {
		listCaUrl = CertCa.APIEndPoint + "ca"
	} else {
		listCaUrl = CertCa.APIEndPoint + "/ca"
	}
	req, err := http.NewRequest("GET", listCaUrl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command.certCA: url='%v' Error'%v' \n", listCaUrl, err.Error())
	}
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertCa.AccessToken)
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command.certCA: Request failed Error:= '%v' \n", err.Error())
		return
	}
	defer resp.Body.Close()
	if CertCa.Verbose {
		PrintFullRespond("INFO: Command.certCA: Request dump", resp)
	}
	var aCAList []CAInfo
	if err = json.NewDecoder(resp.Body).Decode(&aCAList); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Command.certCA: decoding error, no data received ?? '%v' \n ", err.Error())
		return
	}
	fmt.Fprintf(os.Stdout, "%v\n", resp.StatusCode)
	//Json Output
	caListJson, _ := json.MarshalIndent(aCAList, "\t", "\t")
	// Screen oder JSON File output
	if CertCa.JSONOutput {
		fmt.Fprintf(os.Stdout, "%v\n", string(caListJson))
	} else {
		fmt.Fprintf(os.Stdout, "%v\n", aCAList)
	}
}
