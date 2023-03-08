package clitypes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
)

/*CertListType ---------------------------------------------------------------------------------
 cert	ca
 	List all certificate authorities (CA) utilized by DNS3L
  Flags
	-a, --api   	| DNS3L API endpoint [$DNS3L_API]
	  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]

  curl -X GET "https://dns3l.example.com/api/v1/ca/4/crt?search=*.acme.com" -H "Accept: application/json"
	  ?search=*.acme.com
----------------------------------------------------------------------------------------- */
type CertListType struct {
	Verbose     bool
	JSONOutput  bool
	APIEndPoint string
	AccessToken string
	CA          string
	Filter      string
}

type CreatorInfo struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type CertInfo struct {
	Name       string      `json:"name"`       // 	FQDN as certificate name
	Creator    CreatorInfo `json:"claimedBy"`  //
	ClaimedOn  string      `json:"claimedOn"`  //
	ValidTo    string      `json:"validTo "`   //
	Valid      bool        `json:"valid"`      //
	RenewCount int32       `json:"renewCount"` //
	Wildcard   bool        `json:"wildcard"`   //
	SubjectCN  string      `json:"subjectCN"`  //
	IssuerCN   string      `json:"issuerCN"`   //
	Serial     string      `json:"serial"`     //
}

// PrintParams prints the parameters of the command cert list
func (CertList *CertListType) PrintParams() {
	if CertList.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command Cert List called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "INFO:JsonOut 	     '%t' \n", CertList.JSONOutput)
		fmt.Fprintf(os.Stderr, "INFO:Api EndPoint    '%s' \n", CertList.APIEndPoint)
		fmt.Fprintf(os.Stderr, "AccessToken  (4 < len)='%t' \n", (len(CertList.AccessToken) > 4))
		// the id of the CA, which can be obtained through the ca command
		fmt.Fprintf(os.Stderr, "INFO:CA          	 '%s' \n", CertList.CA)
		fmt.Fprintf(os.Stderr, "INFO:Filter          	 '%s' \n", CertList.Filter)

	}
	//
}

// CheckParams prints the parameters of the command cert list
func (CertList *CertListType) CheckParams() error  {
	// check api
	// check CA
	var errText string
	OK := true
	if len(CertList.AccessToken) <= 4 {
		OK = false
		errText = "cert AccessToken  heuristic check failed"
	}
	if !OK {
		return NewValueError(11301, fmt.Errorf(errText))
	}
	return nil
}

func (CertList *CertListType) DoCommand() error {
	client := &http.Client{}
	var listCaUrl string
	if CertList.APIEndPoint[len(CertList.APIEndPoint)-1] == byte('/') {
		listCaUrl = CertList.APIEndPoint + "ca/" + CertList.CA + "/crt"
	} else {
		listCaUrl = CertList.APIEndPoint + "/ca/" + CertList.CA + "/crt"
	}
	if CertList.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command.certList: API-END_POINT'%v' \n", listCaUrl)
	}
	req, err := http.NewRequest(http.MethodGet, listCaUrl, nil)
	if err != nil {
		return NewValueError(11401, fmt.Errorf("cert list: url='%v' Error'%v'", listCaUrl, err.Error()))
	}
	qVals := req.URL.Query()
	qVals.Add("search", CertList.Filter)
	req.URL.RawQuery = qVals.Encode()
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertList.AccessToken)
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	resp, err := client.Do(req)
	if err != nil {
		return NewValueError(11402, fmt.Errorf("cert list: Request failed Error:= '%v'", err.Error()))
	}
	defer resp.Body.Close()
	if CertList.Verbose {
		PrintFullRespond("INFO: Cert List: Request dump", resp)
	}
	var aCertList []CertInfo
	if err = json.NewDecoder(resp.Body).Decode(&aCertList); err != nil {
		return NewValueError(11403, fmt.Errorf("cert list: decoding Error '%v' No Data received", err.Error()))
	}
	var certListJson []byte
	filteredList := make([]CertInfo, 0, len(aCertList))
	if CertList.Filter !="" {
		pattern, compileErr := regexp.Compile(CertList.Filter)
		if compileErr == nil {
			for _, aVal := range aCertList {
				if pattern.MatchString(aVal.SubjectCN) {
					filteredList = append(filteredList, aVal)
				}
			}
			certListJson, _ = json.MarshalIndent(filteredList, "\t", "\t")
			aCertList = filteredList
		} else {
			return NewValueError(11405, fmt.Errorf("cert list: can not compile search pattern Error '%v'", compileErr.Error()))
		}
	} else {
		certListJson, err = json.MarshalIndent(aCertList, "\t", "\t")
		if err != nil {
			NewValueError(1140, fmt.Errorf("cert list: json marshal fails '%v'", err.Error()))
		}
	}
	// Screen oder JSON File output
	if CertList.JSONOutput {
		fmt.Fprintf(os.Stdout, "%v\n", string(certListJson))
	} else {
		fmt.Fprintf(os.Stdout, "%v\n", aCertList)
	}
	return nil
}
