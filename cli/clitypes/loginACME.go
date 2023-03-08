package clitypes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// AccountData holds a the data for accessing DNS3l via DEX
type ClientAppData struct {
	OidcUrl      string `json:"oidc_url"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_scret"`
}

// OpenIdInfo is the reply of the .well-known/openid-configuration endpoint
type OpenIdInfo struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksUri                           string   `json:"jwks_uri"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

type TokenInfo struct {
	AccesssToken string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Expire       int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

type LoginACMEType struct {
	Verbose          bool
	FromTerminal     bool
	ACMEProviderID   string
	ACMEProviderPASS string
	ACMEForceOStream bool
	ClientInfo       ClientAppData
}

func (loginData *LoginACMEType) GetOpenIdConfiguration() (*OpenIdInfo, error) {
	resp, err := http.Get(loginData.ClientInfo.OidcUrl)
	if err != nil {
		return nil, NewValueError(610, fmt.Errorf("request for OpenIdConfiguration of the ACME failed reason %v",err.Error()))
	}
	defer resp.Body.Close()
	if loginData.Verbose {
		PrintFullRespond("GetOpenIdConfiguration() dump respond", resp)
	}
	var msg OpenIdInfo
	if resp.StatusCode != http.StatusOK {
		return nil, NewValueError(620, fmt.Errorf("call for OpenIdConfiguration() failed HTTP StatusCode:='%v' ", resp.StatusCode))
	}
	err = json.NewDecoder(resp.Body).Decode(&msg)
	if err != nil {
		return nil,  NewValueError(630, fmt.Errorf("received OpenIdConfiguration data: json decoding Error, '%v' ", err.Error()))
	}
	return &msg, nil
}

// the call for retriving the tokens from the server
func (loginData *LoginACMEType) GetDEXToken(msg *OpenIdInfo) (*TokenInfo, error) {
	client := &http.Client{}
	var aToken TokenInfo
	dataStr := "grant_type=password&scope=openid profile email groups offline_access&username=" +
		url.QueryEscape(loginData.ACMEProviderID) + "&password=" + url.QueryEscape(loginData.ACMEProviderPASS)
	var data = strings.NewReader(dataStr)
	req, err := http.NewRequest("POST", msg.TokenEndpoint, data)
	if err != nil {
		return nil, NewValueError(640, fmt.Errorf("could not create Request for Token Error, '%s' ", err.Error()))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// OAuth2, both arguments must be URL encoded first with url.QueryEscape.
	req.SetBasicAuth(url.QueryEscape(loginData.ClientInfo.ClientId), url.QueryEscape(loginData.ClientInfo.ClientSecret))
	if loginData.Verbose {
		PrintFullRequestOut("INFO: Dump of token http.request", req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, NewValueError(650, fmt.Errorf("request for the token failed Error, '%s' ", err.Error()))
	}
	defer resp.Body.Close()
	if loginData.Verbose {
		PrintFullRespond("INFO: Dump of the reply of token request", resp)
	}

	if err = json.NewDecoder(resp.Body).Decode(&aToken); err != nil {
		return nil, NewValueError(660, fmt.Errorf("token data: json decoding Error '%s' ", err.Error()))
	}
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: AccesssToken ===========\n%s\n", string(aToken.AccesssToken))
		fmt.Fprintf(os.Stderr, "INFO: TokenType ==============\n%s\n", string(aToken.TokenType))
		fmt.Fprintf(os.Stderr, "INFO: Expire =================\n%v\n", aToken.Expire)
		fmt.Fprintf(os.Stderr, "INFO: RefreshToken ===========\n%s\n", string(aToken.RefreshToken))
		fmt.Fprintf(os.Stderr, "INFO: IdToken ================\n%s\n", string(aToken.IdToken))
	}
	return &aToken, nil
}

func (loginData *LoginACMEType) Init(verbose bool, id string, pass string, forceOStream bool, fromTerminal bool) {
	vip := viper.GetViper()
	var clientInfoViper ClientAppData
	clientInfoViper.OidcUrl = vip.GetString("acme.oidcUrl")
	clientInfoViper.ClientId = vip.GetString("acme.clientId") // Anwendung
	clientInfoViper.ClientSecret = vip.GetString("acme.clientSecret")
	// this are the values out of VIPER  Config and ENVIROMENT of SHELL
	loginData.Verbose = verbose
	loginData.ACMEForceOStream = forceOStream
	loginData.FromTerminal = fromTerminal
	// this are the values from the COMMANDLINE / Enviroment / Config
	loginData.ACMEProviderID = id
	loginData.ACMEProviderPASS = pass
	// commandline allways overrides config or env variables
	loginData.ClientInfo = clientInfoViper

}

func (loginData *LoginACMEType) PrintParams() {
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Command Add Cert Token to linux keyring or file add called \n")
		fmt.Fprintf(os.Stderr, "INFO: Verbose='%v'\n", loginData.Verbose)
		fmt.Fprintf(os.Stderr, "INFO: ForceOStream='%v'\n", loginData.ACMEForceOStream)
		fmt.Fprintf(os.Stderr, "INFO: ForceTerminalInput='%v'\n", loginData.FromTerminal)
		fmt.Fprintf(os.Stderr, "INFO: ACMEProviderID '%v'\n", loginData.ACMEProviderID)
		if loginData.ACMEProviderPASS == "" {
			fmt.Fprintf(os.Stderr, "INFO: ACMEProviderSecret 'is empty \n")
		} else {
			fmt.Fprintf(os.Stderr, "INFO: ACMEProviderSecret '%v'\n", loginData.ACMEProviderPASS[0:2])
		}
		fmt.Fprintf(os.Stderr, "INFO: DATA READ FROM KONFIG FILE / ENVIROMENT \n")
		fmt.Fprintf(os.Stderr, "INFO: acme.OicdUrl='%v'\n", loginData.ClientInfo.OidcUrl)
		fmt.Fprintf(os.Stderr, "INFO: acme.ClientId='%v'\n", loginData.ClientInfo.ClientId) // Anwendung
		fmt.Fprintf(os.Stderr, "INFO: acme.ClientSecret='%v'\n", loginData.ClientInfo.ClientSecret)
	}
}

func (loginData *LoginACMEType) CheckParams() error {
	// || accountInfo.ClientSecret == ""
	if loginData.ClientInfo.OidcUrl == "" ||
		loginData.ClientInfo.ClientId == "" ||
		loginData.ACMEProviderID == "" ||
		(loginData.ACMEProviderPASS == "" && !loginData.FromTerminal) {
		return NewValueError(610, fmt.Errorf("AccountInfo not complete valid, found epmpty entries"))
	}
	return nil
}

func (loginData *LoginACMEType) DoCommand() error {
	if loginData.FromTerminal {
		bIn, inErr := GetPasswordFromConsole("Password for acme account " + loginData.ACMEProviderID + " =")
		if inErr == nil {
			loginData.ACMEProviderPASS = string(bIn)
		} else {
			return NewValueError(620, inErr)
		}
	}
	// here we retrive the API-ENDPOINT from which we can query for tokens
	msg, err := loginData.GetOpenIdConfiguration()
	if err != nil {
		return NewValueError(630, err)
	}
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: API Endpoint for Token request: %v\n", msg.TokenEndpoint)
	}
	// here we make the call for the tokens
	tok, err := loginData.GetDEXToken(msg)
	if err != nil {
		return NewValueError(640, err)
	}
	// put into the ring
	if !loginData.ACMEForceOStream {
		err := CachePassword("CertAccountToken", tok.AccesssToken, uint(tok.Expire+60), loginData.Verbose)
		if nil != err {
			return NewValueError(650, err)
		}
		err = CachePassword("CertIdToken", tok.IdToken, uint(tok.Expire+60), loginData.Verbose)
		if nil != err {
			return NewValueError(660, err)
		}
		err = CachePassword("CertRefreshToken", tok.RefreshToken, uint(tok.Expire+60), loginData.Verbose)
		if nil != err {
			return NewValueError(670, err)
		}
	} else {
		fmt.Fprintf(os.Stdout, "%v\n", tok.AccesssToken)
	}
	return nil
}
