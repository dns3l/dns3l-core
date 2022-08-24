package clitypes

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dns3l/dns3l-core/dns/infblx"
	"github.com/dns3l/dns3l-core/dns/otc"
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/spf13/viper"
)

// NotImplemented print the message NOT IMPLENENTED
func NotImplemented() {
	fmt.Printf("\n\n===================================\nTHIS COMMAND IS NOT IMPLEMENTED YET\n===================================\n\n")

}

func setProvider(dnsbackend string, id string, secret string) types.DNSProvider {
	var dns types.DNSProvider
	vip := viper.GetViper()
	providerPath := "dns.providers." + dnsbackend + "."
	fmt.Printf("use Provider.path := %s\n", providerPath)
	providerT := vip.GetString(providerPath + "type")
	fmt.Printf("Found Provider Type := %s\n", providerT)
	if providerT == "infblx" {
		fmt.Printf("case infblk\n")
		influxProvider := infblx.DNSProvider{}
		infblxConfig := infblx.Config{}
		infblxConfig.Name = vip.GetString(providerPath + "name")
		infblxConfig.Host = vip.GetString(providerPath + "host")
		infblxConfig.Port = vip.GetString(providerPath + "port")
		infblxConfig.Version = vip.GetString(providerPath + "version")
		infblxConfig.Auth.User = vip.GetString(providerPath + "auth.user")
		infblxConfig.Auth.Pass = vip.GetString(providerPath + "auth.pass")
		infblxConfig.DNSView = vip.GetString(providerPath + "dnsview")
		infblxConfig.SSLVerify = vip.GetString(providerPath + "sslverify")
		influxProvider.C = &infblxConfig
		// Passwort überschreiebn aus cobra
		// USER + PASS
		if id != "" && id != "user" {
			infblxConfig.Auth.User = id
		}
		if secret != "" && secret != "pass" {
			infblxConfig.Auth.Pass = secret
		}
		// infblx-Provider eine Interface zuweisen
		dns = &influxProvider
		return dns
	} else if providerT == "otc" {
		fmt.Printf("case otc\n")
		otcProvider := otc.DNSProvider{}
		otcConfig := otc.Config{}
		otcConfig.Name = vip.GetString(providerPath + "name")
		otcConfig.Auth.AuthURL = vip.GetString(providerPath + "auth.authurl")
		otcConfig.Auth.ProjectName = vip.GetString(providerPath + "auth.projectname")
		otcConfig.Auth.AccessKey = vip.GetString(providerPath + "auth.accesskey ")
		otcConfig.Auth.SecretKey = vip.GetString(providerPath + "auth.secretkey")
		otcConfig.OSRegion = vip.GetString(providerPath + "osregion")
		otcProvider.C = &otcConfig
		// otc-Provider eine Interface zuweisen
		dns = &otcProvider
		return dns
	}
	fmt.Printf("not match for %s %s \n", dnsbackend, providerT)
	return nil
}

// PrintDNSProvider prints the parameters of the dns provider
func PrintDNSProvider(provider types.DNSProvider) {
	// type assertion
	switch value := provider.(type) {
	case *(infblx.DNSProvider):
		fmt.Printf("Infblk Provider Config Name 	'%s' \n", value.C.Name)
		fmt.Printf("Infblk Provider Config Host 	'%s' \n", value.C.Host)
		fmt.Printf("Infblk Provider Config Port 	'%s' \n", value.C.Port)
		fmt.Printf("Infblk Provider Config Version 	'%s' \n", value.C.Version)
		fmt.Printf("Infblk Provider Config Auth User 	'%s' \n", value.C.Auth.User)
		fmt.Printf("Infblk Provider Config Auth Pass 	'%s' \n", value.C.Auth.Pass)
		fmt.Printf("Infblk Provider Config DNSView 	'%s' \n", value.C.DNSView)
		fmt.Printf("Infblk Provider Config SSLVerify 	'%s' \n", value.C.SSLVerify)
	case *(otc.DNSProvider):
		fmt.Printf("OTC Provider Config Name  '%s' \n", value.C.Name)
		fmt.Printf("OTC Provider Config Auth.AuthURL  '%s' \n", value.C.Auth.AuthURL)
		fmt.Printf("OTC Provider Config Auth.ProjectName  '%s' \n", value.C.Auth.ProjectName)
		fmt.Printf("OTC Provider Config Auth.AccessKey  '%s' \n", value.C.Auth.AccessKey)
		fmt.Printf("OTC Provider Config Auth.SecretKey  '%s' \n", value.C.Auth.SecretKey)
		fmt.Printf("OTC Provider Config OSRegion  '%s' \n", value.C.OSRegion)
		fmt.Printf("infblx.DNSProvider")
	default:
		fmt.Printf("No known Provider type %T\n", value)
	}

}

// PrintViperConfigDNS prints the common parameters of the dns cmd
func PrintViperConfigDNS() {
	// Provider = viper.GetString("provider")
	//BackendAPIEndPoint = viper.GetString("api")
	vip := viper.GetViper()
	fmt.Printf("VIPER Provider Name 	'%s' \n", vip.GetString("dns.backend"))
	fmt.Printf("VIPER dns force flag	'%s' \n", vip.GetString("force"))
	fmt.Printf("VIPER debug flag 	'%s' \n", vip.GetString("debug"))
	fmt.Printf("VIPER json output 	'%s' \n", vip.GetString("json"))
	fmt.Printf("VIPER User/ Id 	'%s' \n", vip.GetString("dns.id"))
	fmt.Printf("VIPER secret / Password 	'%s' \n", vip.GetString("dns.secret"))

}

// PrintViperConfigCert prints the common parameters of the cert cmd
func PrintViperConfigCert() {
	// Provider = viper.GetString("provider")
	//BackendAPIEndPoint = viper.GetString("api")
	vip := viper.GetViper()
	fmt.Printf("VIPER cert.ca 	'%s' \n", vip.GetString("cert.ca"))
	fmt.Printf("VIPER cert.wildcard	'%s' \n", vip.GetString("cert.wildcard"))
	fmt.Printf("VIPER cert.autodns 	'%s' \n", vip.GetString("cert.autodns"))
	fmt.Printf("VIPER cert.mode 	'%s' \n", vip.GetString("cert.mode"))
	fmt.Printf("VIPER cert.api  	'%s' \n", vip.GetString("cert.api"))
	fmt.Printf("VIPER force flag	'%s' \n", vip.GetString("force"))
	fmt.Printf("VIPER debug flag 	'%s' \n", vip.GetString("debug"))
	fmt.Printf("VIPER json output 	'%s' \n", vip.GetString("json"))
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

// CheckTypeOfFQDN TOBE Done Wildcard CNAME e.g in Zertifikate
func CheckTypeOfFQDN(valStr string) bool {
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
