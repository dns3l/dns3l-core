package clitypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// Private key type
// Default: RSA
// Allowed: RSA EC OKP
// kty: enum
var KtyAllowedValues = []string{"RSA", "EC", "OKP"}

func checkKty(theVal string) bool {
	if theVal == "" {
		return true
	}
	for _, aVal := range KtyAllowedValues {
		if aVal == theVal {
			return true
		}
	}
	fmt.Fprintf(os.Stderr, "ERROR: Cert Hints.Kty='%s':  unknown value, should be one out of \n", theVal)
	for _, v := range KtyAllowedValues {
		fmt.Fprintf(os.Stderr, "%s, ", v)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return false
}

// Private key curve
// Default: P-256
// Allowed: P-256 P-384 P-521 Ed25519
var CrvAllowedValues = []string{"P-256", "2P-384", "P-521", "Ed25519"}

func checkCrv(theVal string) bool {
	if theVal == "" {
		return true
	}
	for _, aVal := range CrvAllowedValues {
		if aVal == theVal {
			return true
		}
	}
	fmt.Fprintf(os.Stderr, "ERROR: Cert Hints.Crv='%s':  unknown value, should be one out of \n", theVal)
	for _, v := range CrvAllowedValues {
		fmt.Fprintf(os.Stderr, "%s, ", v)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return false
}

var KeyUsageAllowedValues = []string{"digitalSignature", "nonRepudiation", "keyEncipherment",
	"dataEncipherment", "keyAgreement", "keyCertSign",
	"cRLSign", "encipherOnly", "decipherOnly"}

func checkKeyUsage(theVal []string) bool {
	ok := true
	found := false
	if len(theVal) == 0 {
		return true
	}
	for _, aUsage := range theVal {
		if aUsage == "" {
			continue
		}
		found = false
		for _, aVal := range KeyUsageAllowedValues {
			if aVal == aUsage {
				found = true
				break
			}
		}
		if !found {
			ok = false
			fmt.Fprintf(os.Stderr, "ERROR: Cert Hints.KeyUsage %s:  unknown value '\n", aUsage)
		}
	}
	if ok {
		return true
	}
	fmt.Fprintf(os.Stderr, "ERROR: Cert Hints.KeyUsage='%s':  one or more unknown value, should be one out of \n", theVal)
	for _, v := range KeyUsageAllowedValues {
		fmt.Fprintf(os.Stderr, "%s, ", v)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return false
}

var ExtKeyUsageAllowedValues = []string{"serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "OCSPSigning", "critical"}

func checkExtKeyUsage(theVal []string) bool {
	ok := true
	found := false
	if len(theVal) == 0 {
		return true
	}
	for _, aUsage := range theVal {
		if aUsage == "" {
			continue
		}
		found = false
		for _, aVal := range ExtKeyUsageAllowedValues {
			if aVal == aUsage {
				found = true
				break
			}
		}
		if !found {
			ok = false
			fmt.Fprintf(os.Stderr, "ERROR: Cert Hints.ExtKeyUsage %s:  unknown value '\n", aUsage)
		}
	}
	if ok {
		return true
	}
	fmt.Fprintf(os.Stderr, "ERROR: Cert Hints.ExtKeyUsage='%s':  one or more unknown value, should be one out of \n", theVal)
	for _, v := range ExtKeyUsageAllowedValues {
		fmt.Fprintf(os.Stderr, "%s, ", v)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return false
}

type hintsType struct {
	// Kty  		KtyEnumType 	`json:"kty"`  // Default: RSA, Allowed: RSA┃EC┃OKP
	// Crv  		CrvEnumType 	`json:"crv"`  // Private key curve Default: P-256 Allowed: P-256┃P-384┃P-521┃Ed25519
	Kty  string `json:"kty"`  // Default: RSA, Allowed: RSA┃EC┃OKP
	Crv  string `json:"crv"`  // Private key curve Default: P-256 Allowed: P-256┃P-384┃P-521┃Ed25519
	Size uint32 `json:"size"` // Private key length Default: 2048
	TTL  string `json:"ttl"`  // Time to live 30d proposal
	// “Subject: C=AT, ST=Vienna, L=Vienna, O=Home, OU=Web Lab, CN=anywhere.com/Email=xyz@anywhere.com”
	// "C=DE,O=ACME Inc.,OU=DNS3L,CN=foo.bar.acme.org"
	Subject     string   `json:"subject"` // Subject proposal
	KeyUsage    []string `json:"keyUsage"`
	ExtKeyUsage []string `json:"extKeyUsage"`
}

type AutoDNSType struct {
	Ipv4 string `json:"ipv4"` // IP for FQDN  192.168.1.2

}

type claimRequestType struct {
	Name     string      `json:"name"`     // FQDN as certificate name
	Wildcard bool        `json:"wildcard"` // Ask for a wildcard i.e. add *.. No AutoDNS allowed Default: false
	San      []string    `json:"san"`      // List of additional DNS: SAN
	Autodns  AutoDNSType `json:"autodns"`  // no wildcard allowed if true??    true== valid IP  false==nil
	Hints    hintsType   `json:"hints"`    // Hints that DNS3L could follow for CSR
}

type claimWildcardRequestType struct {
	Name     string    `json:"name"`     // FQDN as certificate name
	Wildcard bool      `json:"wildcard"` // Ask for a wildcard i.e. add *.. No AutoDNS allowed Default: false
	San      []string  `json:"san"`      // List of additional DNS: SAN
	Hints    hintsType `json:"hints"`    // Hints that DNS3L could follow for CSR
}

/*
CertClaimType ---------------------------------------------------------------------------

	 cert	claim	post
	 	claim a cert with DNS3L
	 Flags
		-a, --api   	| DNS3L API endpoint [$DNS3L_API]
		  , --ca        | Claim from a specific ACME CA [$DNS3L_CA]
		-w, --wildcard  | Create a wildcard (cannot be used with -d)
		-d, --autodns   | Create an A record (cannot be used with -w)

200 = OK
400 = bad request
404 = not found

Args

	FQDN: FQDN as certificate name
	SAN: optional list of SAN       [SAN [SAN [...]]]

-----------------------------------------------------------------------------------------
*/
type CertClaimType struct {
	Verbose      bool
	JSONOutput   bool
	APIEndPoint  string
	CertToken    string
	CA           string
	Wildcard     bool
	AutoDNS      string
	FQDN         string
	SAN          []string
	HintsSection string
	Hints        hintsType
}

func (CertClaim *CertClaimType) Init(verbose bool, jsonOutput bool, apiEndPoint string, certToken string, ca string, wildcard bool, autoDNS string,
	aFQDN string, aSAN []string, hintsSectionstring string) {
	CertClaim.Verbose = verbose
	CertClaim.JSONOutput = jsonOutput
	CertClaim.APIEndPoint = apiEndPoint
	CertClaim.CertToken = certToken
	CertClaim.CA = ca
	CertClaim.Wildcard = wildcard
	CertClaim.AutoDNS = autoDNS
	CertClaim.FQDN = aFQDN
	CertClaim.SAN = aSAN
	CertClaim.HintsSection = hintsSectionstring
	if CertClaim.HintsSection != "" {
		CertClaim.Hints = SetCertClaimHints(CertClaim.HintsSection)
	}

}

// PrintParams  prints the parameters of the command cert claim
func (CertClaim *CertClaimType) PrintParams() {
	if CertClaim.Verbose {
		fmt.Fprintf(os.Stderr, "Command Cert Claim called \n")
		PrintViperConfigCert()
		fmt.Fprintf(os.Stderr, "JsonOut 	 '%t' \n", CertClaim.JSONOutput)
		fmt.Fprintf(os.Stderr, "Api EndPoint '%s' \n", CertClaim.APIEndPoint)
		fmt.Fprintf(os.Stderr, "Token 4<len'  %t' \n", (len(CertClaim.CertToken) > 4))
		fmt.Fprintf(os.Stderr, "CA           '%s' \n", CertClaim.CA)
		fmt.Fprintf(os.Stderr, "Wildcard     '%t' \n", CertClaim.Wildcard)
		fmt.Fprintf(os.Stderr, "AutoDNS      '%s' \n", CertClaim.AutoDNS)
		fmt.Fprintf(os.Stderr, "FQDN         '%s' is OK '%t' \n", CertClaim.FQDN, CheckTypeOfFQDN(CertClaim.FQDN))
		fmt.Fprintf(os.Stderr, "SAN          '%s'\n", CertClaim.SAN)
		fmt.Fprintf(os.Stderr, "Hints section'%s'\n", string(CertClaim.HintsSection))
		printCertClaimHints(CertClaim.Hints)
	}
}

// CheckParams  checks the parameters of the command cert claim
func (CertClaim *CertClaimType) CheckParams() error {
	// check api
	// check CA
	// Wildcard & AutoDNS are mutually exclusive
	// SAN
	var errText string
	OK := true
	if !CertClaim.Wildcard {
		if !CheckTypeOfFQDN(CertClaim.FQDN) {
			OK = false
			errText = fmt.Sprintf("cert claim FQDN  '%s' is not valid", CertClaim.FQDN)
		}
	}
	if CertClaim.AutoDNS != "" && !regExIPv4.MatchString(CertClaim.AutoDNS) {
		OK = false
		errText = fmt.Sprintf("cert claim AutoDNS.IP4_ADDR is not empty or a valid IP4 address  '%s'", CertClaim.AutoDNS)
	}
	if len(CertClaim.CertToken) <= 4 {
		OK = false
		errText = "cert claim AccessToken heuristic check failed"
	}
	//
	// do not check this values if they are empty!!
	if !checkKty(CertClaim.Hints.Kty) {
		errText = "cert claim Kty check failed"
		OK = false
	}
	if !checkCrv(CertClaim.Hints.Crv) {
		errText = "cert claim Crv check failed"
		OK = false
	}
	if !checkKeyUsage(CertClaim.Hints.KeyUsage) {
		errText = "cert claim Key usage check failed"
		OK = false
	}
	if !checkExtKeyUsage(CertClaim.Hints.ExtKeyUsage) {
		errText = "cert claim Key extended usage check failed"
		OK = false
	}
	// TTL  string e.g.  30d
	if !OK {
		return NewValueError(12301, fmt.Errorf(errText))
	}
	return nil
}

func (CertClaim *CertClaimType) DoCommand() error {
	// json body des requests erzeugen
	CertClaim.Hints.Subject = CertClaim.Hints.Subject + CertClaim.FQDN
	var jBody []byte
	if CertClaim.Wildcard || CertClaim.AutoDNS == "" {
		var claimRequest claimWildcardRequestType
		claimRequest.Name = CertClaim.FQDN
		claimRequest.Wildcard = CertClaim.Wildcard
		claimRequest.San = CertClaim.SAN
		claimRequest.Hints = CertClaim.Hints
		jBody, _ = json.MarshalIndent(claimRequest, "\t", "\t")
	} else {
		var claimRequest claimRequestType
		claimRequest.Name = CertClaim.FQDN
		claimRequest.Wildcard = CertClaim.Wildcard
		claimRequest.San = CertClaim.SAN
		claimRequest.Autodns.Ipv4 = CertClaim.AutoDNS
		claimRequest.Hints = CertClaim.Hints
		jBody, _ = json.MarshalIndent(claimRequest, "\t", "\t")
	}
	var postCertClaimUrl string
	if CertClaim.APIEndPoint[len(CertClaim.APIEndPoint)-1] == byte('/') {
		postCertClaimUrl = CertClaim.APIEndPoint + "ca/" + CertClaim.CA + "/crt"
	} else {
		postCertClaimUrl = CertClaim.APIEndPoint + "/ca/" + CertClaim.CA + "/crt"
	}
	if CertClaim.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command CERT CLAIM: API-END_POINT'%v' \n", postCertClaimUrl)
	}
	req, err := http.NewRequest(http.MethodPost, postCertClaimUrl, bytes.NewReader(jBody))
	if err != nil {
		return NewValueError(12401, fmt.Errorf("cert claim chain: url='%v' Error'%v'", postCertClaimUrl, err.Error()))
	}
	req.Header.Set("Accept", "application/json")
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + FinalCertToken(CertClaim.CertToken)
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	if CertClaim.Verbose {
		PrintFullRequestOut("INFO: Command CERT CLAIM Request", req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NewValueError(11402, fmt.Errorf("cert claim: Request failed Error:= '%v'", err.Error()))
	}
	defer resp.Body.Close()

	if CertClaim.Verbose {
		PrintFullRespond("INFO: Command CERT GET full chain: Request dump", resp)
	}
	if resp.StatusCode != 200 {
		return NewValueError(11403, fmt.Errorf("cert claim: Request failed Error:= '%v'", resp.StatusCode))
	}
	return nil
}
