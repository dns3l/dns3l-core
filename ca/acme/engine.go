package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dta4/dns3l-go/ca/common.go"
	dns "github.com/dta4/dns3l-go/dns"
	dnscommon "github.com/dta4/dns3l-go/dns/common"
	dnstypes "github.com/dta4/dns3l-go/dns/types"
	"github.com/go-acme/lego/v4/certificate"
	legodns01 "github.com/go-acme/lego/v4/challenge/dns01"
)

var keyNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

const keyBitLength = 2048

//The Engine is created to have a consistent, object-based handle for Autokey operations
type Engine struct {
	Conf    *Config
	DNSConf *dns.Config
	State   ACMEStateManager
}

//TriggerUpdate ensures that a key/certificate pair of the given line is available. It expects that the user
//is authenticated and authorized for the requested domain.
//It will look up the current state of the user and the key/certificate and ensures that the user and
//the requested key/cert is present.
func (e *Engine) TriggerUpdate(uid string, keyname string, domains []string, dnsProviderID, email string) error {

	for _, domain := range domains {
		err := dnscommon.ValidateDomainNameWildcard(domain)
		if err != nil {
			return err
		}
	}

	err := validateKeyName(keyname)
	if err != nil {
		return err
	}

	log.Infof("Trigger request by user '%s' for key '%s', domains '%s'", uid, keyname, strings.Join(domains, ","))

	domainsSanitized, err := sanitizeDomains(domains)
	if err != nil {
		return err
	}

	log.Debugf("Domains '%s' validated and sanitized. Checking for existing keys/certificates...", strings.Join(domains, ","))

	state, err := e.State.NewSession()
	if err != nil {
		return err
	}
	defer state.Close()

	privKeyStr, expiryTime, err := state.GetACMECertPrivkeyByID(keyname, uid)
	if err != nil {
		return err
	}

	noKey := privKeyStr == ""

	if !noKey {
		now := time.Now()
		renewalDate := expiryTime.AddDate(0, 0, -e.Conf.DaysRenewBeforeExpiry)
		if now.Before(renewalDate) {
			//Not yet due for renewal
			return &NoRenewalDueError{RenewalDate: renewalDate}
		}
		log.Infof("Key '%s' for user '%s' exists, cert is due for renewal", keyname, uid)
	}

	var privKey *rsa.PrivateKey
	if noKey {
		log.Infof("Generating new RSA private key '%s' for user '%s'", keyname, uid)
		privKey, err = generateRSAPrivateKey()
		if err != nil {
			return err
		}
		privKeyStr = common.RSAPrivKeyToStr(privKey)
	} else {
		privKey, err = common.RSAPrivKeyFromStr(privKeyStr)
		if err != nil {
			return err
		}
	}

	var u User = &DefaultUser{
		Config: e.Conf,
		State:  state,
		UID:    uid,
		Email:  email,
	}

	err = u.InitUser()
	if err != nil {
		return err
	}

	dnsprovider, exists := e.DNSConf.Providers[dnsProviderID]
	if !exists {
		return fmt.Errorf("DNS provider 's' for setting ACME challenge has not been configured")
	}

	err = u.GetClient().Challenge.SetDNS01Provider(e.NewDNSProviderDNS3L(dnsprovider.Prov))
	if err != nil {
		return err
	}

	request := certificate.ObtainRequest{
		Domains:    domainsSanitized,
		PrivateKey: privKey,
		Bundle:     true,
	}
	log.Debugf("Requesting new certificate for key '%s', user '%s' via ACME",
		keyname, uid)
	certificates, err := u.GetClient().Certificate.Obtain(request)
	if err != nil {
		return err
	}

	cert, err := parseCertificatePEM(certificates.Certificate)
	if err != nil {
		return err
	}
	if len(cert) <= 0 {
		return errors.New("no certs have been returned")
	}
	certStr := string(certificates.Certificate)
	issuerCertStr := string(certificates.IssuerCertificate)

	return state.PutACMECertData(!noKey, uid, keyname, privKeyStr,
		certStr, issuerCertStr, cert[0].NotAfter)

}

func sanitizeDomains(domains []string) ([]string, error) {
	for i, d := range domains {
		if strings.HasSuffix(d, ".") {
			d = d[:len(d)-1]
			domains[i] = d
		}
	}
	return domains, nil
}

//NewDNSProviderOTC is a factory function for creating a new DNSProviderDNS3L
func (e *Engine) NewDNSProviderDNS3L(prov dnstypes.DNSProvider) *DNSProviderWrapper {
	return &DNSProviderWrapper{Provider: prov}
}

//The DNSProviderWrapper implements lego's DNS01 validation hook with acmeotc
type DNSProviderWrapper struct {
	Provider dnstypes.DNSProvider
}

// Present is called when the DNS01 challenge record shall be set up in the DNS.
// It wraps the acmeotc's DNS01 challenge setter into lego's DNS01 Present function.
func (p *DNSProviderWrapper) Present(domain, token, keyAuth string) error {
	fqdn, challenge := legodns01.GetRecord(domain, keyAuth)
	log.Debugf("Presenting challenge '%s', for domain '%s', fqdn '%s'...", challenge, domain, fqdn)
	err := p.Provider.SetRecordAcmeChallenge(domain, challenge)
	if err != nil {
		return err
	}
	log.Debugf("Presented challenge for domain '%s'", domain)
	return nil
}

// CleanUp is called when the DNS01 challenge record shall be set up in the DNS.
// It wraps the acmeotc's DNS01 challenge deleter into lego's DNS01 CleanUp function.
func (p *DNSProviderWrapper) CleanUp(domain, token, keyAuth string) error {
	log.Debugf("Cleaning up challenge for domain '%s'...", domain)
	err := p.Provider.DeleteRecordAcmeChallenge(domain)
	if err != nil {
		return err
	}
	log.Debugf("Cleaned up challenge for domain '%s'", domain)
	return nil
}

func generateRSAPrivateKey() (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, keyBitLength)
	if err != nil {
		return nil, err
	}

	err = k.Validate()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func parseCertificatePEM(certificate []byte) ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0)
	decodeTodo := certificate
	for {
		var block *pem.Block
		block, decodeTodo = pem.Decode(decodeTodo)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			result = append(result, cert)
		}
	}

	return result, nil

}

// GetResource returns an autokey-obtained resource (key, cert, issuer etc..) to the user
// of the autokey service. The GetUpdate function must be called first, otherwise
// GetObject will return NotFoundError because the resources are not yet present.
func (e *Engine) GetResource(keyName, userID, objectType string) (string, string, error) {

	err := validateKeyName(keyName)
	if err != nil {
		return "", "", err
	}

	log.Debugf("Request for resource '%s' belonging to key name '%s' by user '%s'",
		objectType, keyName, userID)

	sess, err := e.State.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()

	switch objectType {
	case "key":
		//"resourceName" of sess.GetResource must never be user input > not validated!
		res, err := sess.GetResource(keyName, userID, "priv_key")
		return res, "application/x-pem-file", err
	case "crt":
		res, err := sess.GetResource(keyName, userID, "cert")
		return res, "application/x-pem-file", err
	case "issuer-cert":
		res, err := sess.GetResource(keyName, userID, "issuer_cert")
		return res, "application/x-pem-file", err
	case "fullchain":
		res, err := sess.GetResources(keyName, userID, "cert", "issuer_cert")
		return res[0] + "\n" + res[1], "application/x-pem-file", err
	}
	return "", "", &NotFoundError{}

}

func validateKeyName(key string) error {
	if keyNameRe.MatchString(key) {
		return nil
	}
	return errors.New("key_name provided has invalid format or is too long")
}
