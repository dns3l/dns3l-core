package clitypes

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"

	"github.com/dns3l/dns3l-core/dns/infblx"
	"github.com/dns3l/dns3l-core/dns/otc"
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/spf13/viper"
)

// NotImplemented print the message NOT IMPLENENTED
func NotImplemented() {
	fmt.Fprintf(os.Stderr, "THIS COMMAND IS NOT IMPLEMENTED YET\n")

}

func PrintFullRequestOut(headline string, req *http.Request) {
	b, err := httputil.DumpRequestOut(req, true) // req.GetBody()
	if err == nil {
		fmt.Fprintf(os.Stderr, "%v\n", headline)
		fmt.Fprintf(os.Stderr, "%v\n", string(b))
	} else {
		fmt.Fprintf(os.Stderr, "%v\n", headline)
		fmt.Fprintf(os.Stderr, "ERROR printing the request: '%v'", err.Error())
	}
}

func PrintFullRespond(headline string, resp *http.Response) {
	b, err := httputil.DumpResponse(resp, true)
	if err == nil {
		fmt.Fprintf(os.Stderr, "%v\n", headline)
		fmt.Fprintf(os.Stderr, "HTTP Respond StatusCode:='%v'\n", resp.StatusCode)
		fmt.Fprintf(os.Stderr, "%v\n", string(b))
	} else {
		fmt.Fprintf(os.Stderr, "%v\n", headline)
		fmt.Fprintf(os.Stderr, "Error printing the respond: '%v'", err.Error())
	}
}

func getProviderData(dnsbackend string, verbose bool) (string, string) {
	var user string = ""
	var secret string = ""
	vip := viper.GetViper()
	providerPath := "dns.providers." + dnsbackend + "."
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO Will use Provider.path := %s\n", providerPath)
	}
	providerT := vip.GetString(providerPath + "type")
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO Found Provider Type := %s\n", providerT)
	}
	if providerT == "infblx" {
		user = vip.GetString(providerPath + "auth.user")
		secret = vip.GetString(providerPath + "auth.pass")
	} else if providerT == "otc" {
		user = vip.GetString(providerPath + "auth.accesskey ")
		secret = vip.GetString(providerPath + "auth.secretkey")

	}
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO provider user '%s'\n", user)
		fmt.Fprintf(os.Stderr, "INFO provider pass '%s'\n", secret)
	}
	return user, secret
}

func setProvider(dnsbackend string, id string, secret string, usePWSafe bool, verbose bool) types.DNSProvider {
	var dns types.DNSProvider
	vip := viper.GetViper()
	providerPath := "dns.providers." + dnsbackend + "."
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO setProvider() use Provider.path := %s\n", providerPath)
	}
	providerT := vip.GetString(providerPath + "type")
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO setProvider() Found Provider Type := %s\n", providerT)
	}
	if providerT == "infblx" {
		if verbose {
			fmt.Fprintf(os.Stderr, "INFO setProvider() processing case infblk\n")
		}
		infblxProvider := infblx.DNSProvider{}
		infblxConfig := infblx.Config{}
		infblxConfig.Name = vip.GetString(providerPath + "name")
		infblxConfig.Host = vip.GetString(providerPath + "host")
		infblxConfig.Port = vip.GetString(providerPath + "port")
		infblxConfig.Version = vip.GetString(providerPath + "version")
		if infblxConfig.Name == "" || infblxConfig.Host == "" || infblxConfig.Port == "" || infblxConfig.Version == "" {
			return nil
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "INFO setProvider()  User ID := %s\n", id)
		}
		// with "" or "NOT_SET" we switch to the values in the providersection"
		if id != "" && id != "NOT_SET" {
			infblxConfig.Auth.User = id
		} else {
			infblxConfig.Auth.User = vip.GetString(providerPath + "auth.user")
			if verbose {
				fmt.Fprintf(os.Stderr, "INFO  setProvider() User of the providers section %s is used infblk\n", dnsbackend)
				fmt.Fprintf(os.Stderr, "INFO  setProvider() User:= %s ", infblxConfig.Auth.User)
			}
			if infblxConfig.Auth.User == "" {
				fmt.Fprintf(os.Stderr, "ERROR:  setProvider() User/ID is empty command failed -- > exit")
				return nil
			}
		}
		// resolve the secret
		if usePWSafe {
			var err error
			var sec []byte
			if verbose {
				fmt.Fprintf(os.Stderr, "INFO setProvider(): User %s and password from safe \n", infblxConfig.Auth.User)
			}
			if sec, err = GetPasswordfromRing(infblxConfig.Auth.User, verbose); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR setProvider(), no secret provided in the Keyring for DNSBackend '%v' and ID:= '%v'\n", dnsbackend, infblxConfig.Auth.User)
				infblxConfig.Auth.Pass = ""
			} else {
				infblxConfig.Auth.Pass = string(sec)
				if verbose {
					fmt.Fprintf(os.Stderr, "INFO setProvider() Secret provided by Keyring for DNSBackend '%v' and ID:= '%v''\n", dnsbackend, infblxConfig.Auth.User)
				}
			}
		} else {
			// with "" or "NOT_SET" we switch to the values in the providersection"
			if secret != "" && secret != "NOT_SET" {
				if verbose {
					fmt.Fprintf(os.Stderr, "INFO setProvider() secret != '' or 'NOT_SET'\n")
				}
				infblxConfig.Auth.Pass = secret
			} else {
				if verbose {
					fmt.Fprintf(os.Stderr, "INFO setProvider()  using Provider section  \n")
				}
				infblxConfig.Auth.Pass = vip.GetString(providerPath + "auth.pass")
			}
		}
		infblxConfig.DNSView = vip.GetString(providerPath + "dnsview")
		infblxConfig.SSLVerify = vip.GetString(providerPath + "sslverify")
		if infblxConfig.DNSView == "" || infblxConfig.SSLVerify == "" {
			return nil
		}
		infblxProvider.C = &infblxConfig
		// infblx-Provider eine Interface zuweisen
		dns = &infblxProvider
		return dns
	} else if providerT == "otc" {
		fmt.Fprintf(os.Stderr, "case otc\n")
		otcProvider := otc.DNSProvider{}
		otcConfig := otc.Config{}
		otcConfig.Name = vip.GetString(providerPath + "name")
		otcConfig.Auth.AuthURL = vip.GetString(providerPath + "auth.authurl")
		otcConfig.Auth.ProjectName = vip.GetString(providerPath + "auth.projectname")
		otcConfig.Auth.AccessKey = vip.GetString(providerPath + "auth.accesskey ")
		otcConfig.Auth.SecretKey = vip.GetString(providerPath + "auth.secretkey")
		otcConfig.OSRegion = vip.GetString(providerPath + "osregion")
		if otcConfig.Name == "" || otcConfig.Auth.AuthURL == "" || otcConfig.Auth.ProjectName == "" || otcConfig.Auth.AccessKey == "" || otcConfig.Auth.SecretKey == "" || otcConfig.OSRegion == "" {
			return nil
		}
		otcProvider.C = &otcConfig
		// otc-Provider eine Interface zuweisen
		dns = &otcProvider
		return dns
	}
	fmt.Fprintf(os.Stderr, "not match for %s %s \n", dnsbackend, providerT)
	return nil
}

func SetCertClaimHints(hintsSection string) hintsType {
	vip := viper.GetViper()
	var hints hintsType
	hints.Kty = vip.GetString("hints." + hintsSection + ".kty")
	hints.Crv = vip.GetString("hints." + hintsSection + ".crv")
	hints.Size = vip.GetUint32("hints." + hintsSection + ".size")
	hints.TTL = vip.GetString("hints." + hintsSection + ".ttl")
	hints.Subject = vip.GetString("hints." + hintsSection + ".subject")
	// split the words
	hints.KeyUsage = vip.GetStringSlice("hints." + hintsSection + ".keyUsage")
	// split the words
	hints.ExtKeyUsage = vip.GetStringSlice("hints." + hintsSection + ".extKeyUsage")
	return hints
}

func printCertClaimHints(hints hintsType) {
	fmt.Fprintf(os.Stderr, "Cert hints	   kty: '%s' \n", hints.Kty)
	fmt.Fprintf(os.Stderr, "Cert hints 	   crv: '%s' \n", hints.Crv)
	fmt.Fprintf(os.Stderr, "Cert hints 	  size: '%v' \n", hints.Size)
	fmt.Fprintf(os.Stderr, "Cert hints 	   ttl: '%s' \n", hints.TTL)
	fmt.Fprintf(os.Stderr, "Cert hints     subject: '%s' \n", hints.Subject)
	if len(hints.KeyUsage) > 0 {
		for _, v := range hints.KeyUsage {
			fmt.Fprintf(os.Stderr, "Cert keyUsage 	    '%s' \n", v)
		}
	}
	if len(hints.ExtKeyUsage) > 0 {
		for _, v := range hints.ExtKeyUsage {
			fmt.Fprintf(os.Stderr, "Cert ExtkeyUsage    '%s' \n", v)
		}
	}
}

func FinalCertToken(inToken string) string {
	var aToken string
	switch inToken {
	case "USE_RING_TOKEN":
		token, inErr := GetPasswordfromRing("CertAccountToken", false)
		if inErr == nil {
			aToken = string(token)
		} else {
			fmt.Fprintf(os.Stderr, "Token for AMCE API Endpoint not found in KeyRing as exspected \n")
			aToken = ""
		}
	case "USE_ENV_TOKEN":
		vip := viper.GetViper()
		envToken := vip.GetString("cert.accessToken")
		if envToken != "" {
			aToken = envToken
		} else {
			fmt.Fprintf(os.Stderr, "Token for AMCE API Endpoint not found in enviroment as exspected \n")
			aToken = ""
		}
	default:
		aToken = inToken
	}
	return aToken
}

// PrintDNSProvider prints the parameters of the dns provider
func PrintDNSProvider(provider types.DNSProvider) {
	switch value := provider.(type) {
	case *(infblx.DNSProvider):
		fmt.Fprintf(os.Stderr, "Infblk Provider Config Name 	    '%s' \n", value.C.Name)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config Host     	'%s' \n", value.C.Host)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config Port     	'%s' \n", value.C.Port)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config Version    	'%s' \n", value.C.Version)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config Auth User 	'%s' \n", value.C.Auth.User)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config Auth Pass 	'%s' \n", value.C.Auth.Pass)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config DNSView   	'%s' \n", value.C.DNSView)
		fmt.Fprintf(os.Stderr, "Infblk Provider Config SSLVerify 	'%s' \n", value.C.SSLVerify)
	case *(otc.DNSProvider):
		fmt.Fprintf(os.Stderr, "OTC Provider Config Name            '%s' \n", value.C.Name)
		fmt.Fprintf(os.Stderr, "OTC Provider Config Auth.AuthURL    '%s' \n", value.C.Auth.AuthURL)
		fmt.Fprintf(os.Stderr, "OTC Provider Config Auth.ProjectName '%s' \n", value.C.Auth.ProjectName)
		fmt.Fprintf(os.Stderr, "OTC Provider Config Auth.AccessKey  '%s' \n", value.C.Auth.AccessKey)
		fmt.Fprintf(os.Stderr, "OTC Provider Config Auth.SecretKey  '%s' \n", value.C.Auth.SecretKey)
		fmt.Fprintf(os.Stderr, "OTC Provider Config OSRegion        '%s' \n", value.C.OSRegion)
		fmt.Fprintf(os.Stderr, "infblx.DNSProvider")
	default:
		fmt.Fprintf(os.Stderr, "No known Provider type %T\n", value)
	}

}

// PrintViperConfigDNS prints the common parameters of the dns cmd
func PrintViperConfigDNS() {
	// Provider = viper.GetString("provider")
	//BackendAPIEndPoint = viper.GetString("api")
	vip := viper.GetViper()
	fmt.Fprintf(os.Stderr, "resulting value Provider Name 	'%s' \n", vip.GetString("dns.backend"))
	fmt.Fprintf(os.Stderr, "resulting value  dns force flag	'%s' \n", vip.GetString("force"))
	fmt.Fprintf(os.Stderr, "resulting value  debug flag 	    '%s' \n", vip.GetString("debug"))
	fmt.Fprintf(os.Stderr, "resulting value  json output 	    '%s' \n", vip.GetString("json"))
	fmt.Fprintf(os.Stderr, "resulting value  User/ Id 	        '%s' \n", vip.GetString("dns.id"))
	fmt.Fprintf(os.Stderr, "resulting value  secret / Password '%s' \n", vip.GetString("dns.secret"))

}

// PrintViperConfigCert prints the common parameters of the cert cmd
func PrintViperConfigCert() {
	// Provider = viper.GetString("provider")
	//BackendAPIEndPoint = viper.GetString("api")
	vip := viper.GetViper()
	fmt.Fprintf(os.Stderr, "resulting value  cert.ca 	    '%s' \n", vip.GetString("cert.ca"))
	fmt.Fprintf(os.Stderr, "resulting value  cert.wildcard	'%v' \n", vip.GetString("cert.wildcard"))
	fmt.Fprintf(os.Stderr, "resulting value  cert.autodns 	'%s' \n", vip.GetString("cert.autodns"))
	fmt.Fprintf(os.Stderr, "resulting value  cert.mode 	'%s' \n", vip.GetString("cert.mode"))
	fmt.Fprintf(os.Stderr, "resulting value  cert.api  	'%s' \n", vip.GetString("cert.api"))
	fmt.Fprintf(os.Stderr, "resulting value  force flag	'%s' \n", vip.GetString("force"))
	fmt.Fprintf(os.Stderr, "resulting value  debug flag 	'%s' \n", vip.GetString("debug"))
	fmt.Fprintf(os.Stderr, "resulting value  json output 	'%s' \n", vip.GetString("json"))
}

var dnsTypeList [3]string = [...]string{"a", "txt", "cname"}

// CheckTypeOfDNSRecord checks the type of a DNS record
func CheckTypeOfDNSRecord(valStr string) bool {
	valLower := strings.ToLower(valStr)
	for _, v := range dnsTypeList {
		if strings.EqualFold(valLower, v) {
			return true
		}
	}
	return false
}

// CheckTypeOfData check if it is a correct type of a txt or cname
func CheckTypeOfData(valStr string, typeString string) bool {
	//
	switch {
	case strings.EqualFold(typeString, dnsTypeList[0]): // "a",
		return regExIPv4.MatchString(valStr)
	case strings.EqualFold(typeString, dnsTypeList[1]): // "txt",
		return regExTXT.MatchString(valStr)
	case strings.EqualFold(typeString, dnsTypeList[2]): // "cname"
		return regExCName.MatchString(valStr)
	}
	return false
}

// CheckTypeOfFQDN
// no checks for wildcard, CNAME e.g in certificates
func CheckTypeOfFQDN(valStr string) bool {
	if valStr == "" {
		return true
	}
	return regExFQDN.MatchString(valStr)
}

var regExFQDN *regexp.Regexp
var regExTXT *regexp.Regexp
var regExCName *regexp.Regexp
var regExIPv4 *regexp.Regexp

func init() {
	//regExFQDN = regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`)
	regExFQDN = regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)
	// TXT:= "ddd=ddd" the -"- are removed by cobra, so we check for  dddd=dddd
	regExTXT = regexp.MustCompile(`\w+=\w+`) // dddd=dddd
	regExCName = regexp.MustCompile(`^(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_\-]*[a-zA-Z0-9_])\.)*([A-Za-z0-9_]|[A-Za-z0-9_][A-Za-z0-9_\-]*[A-Za-z0-9_](\.?))$`)
	regExIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
}

/*
========================================
set of expressions for FQDN
========================================
Any FQDN:
	^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$
Specific sub-domain(example):
	^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.int.mydomain.com)$
Used here for FQDN
	^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$
	^(  ([a-zA-Z]{1})            |
		([a-zA-Z]{1}[a-zA-Z]{1}) |
		([a-zA-Z]{1}[0-9]{1})   |
		([0-9]{1}[a-zA-Z]{1})    |
		([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9])
	)\. ([a-zA-Z]{2, } | [a-zA-Z0-9-] {2,30}\.[a-zA-Z]{2,3})$
some use this end of the regex above {2, } --> {2,6}
	)\. ([a-zA-Z]{2,6} | [a-zA-Z0-9-] {2,30}\.[a-zA-Z]{2,3})$
Used for cname
	^(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_\-]*[a-zA-Z0-9_])\.)*([A-Za-z0-9_]|[A-Za-z0-9_][A-Za-z0-9_\-]*[A-Za-z0-9_](\.?))$
*/
