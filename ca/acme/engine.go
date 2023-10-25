package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dns3l/dns3l-core/ca/common"
	"github.com/dns3l/dns3l-core/ca/types"
	cmn "github.com/dns3l/dns3l-core/common"
	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/service/auth"
	"github.com/dns3l/dns3l-core/util"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	legodns01 "github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/sirupsen/logrus"
)

const keyBitLength = 2048

// The Engine is created to have a consistent, object-based handle for Autokey operations
type Engine struct {
	CAID    string
	Conf    *Config
	Context types.ProviderConfigurationContext
	State   ACMEStateManager

	//if the engine should not trust the previously set planned renewal date in the database
	RecalcRenewalDate bool
}

// TriggerUpdate ensures that a key/certificate pair of the given line is available. It expects that the user
// is authenticated and authorized for the requested domain.
// It will look up the current state of the user and the key/certificate and ensures that the user and
// the requested key/cert is present.
func (e *Engine) TriggerUpdate(acmeuser string, keyname string, domains []string,
	issuedBy *auth.UserInfo, ttl time.Duration) error {

	keyMustExist := acmeuser == "" || issuedBy == nil || len(domains) <= 0

	for _, domain := range domains {
		err := dnscommon.ValidateDomainNameWildcard(domain)
		if err != nil {
			return err
		}
	}

	err := common.ValidateKeyName(keyname)
	if err != nil {
		return err
	}

	log.Infof("Trigger request by user '%s' for key '%s', domains '%s'", acmeuser, keyname, strings.Join(domains, ","))

	var domainsSanitized []string //Domains that came in new..
	if domains != nil {
		domainsSanitized, err = sanitizeDomains(domains)
		if err != nil {
			return err
		}
		log.Debugf("Domains '%s' validated and sanitized. Checking for existing keys/certificates...", strings.Join(domains, ","))
	}

	state, err := e.State.NewSession()
	if err != nil {
		return err
	}
	defer state.Close()

	castate, err := e.Context.GetStateMgr().NewSession()
	if err != nil {
		return err
	}
	defer castate.Close()

	info, err := castate.GetCACertByID(keyname, e.CAID)
	if err != nil {
		return err
	}
	if info != nil {
		info.Domains, err = sanitizeDomains(info.Domains)
		if err != nil {
			return err
		}
	}

	noKey := info == nil

	if !noKey {

		forceUpdate := false
		if len(domainsSanitized) > 0 && !util.StringSlicesEqual(info.Domains, domainsSanitized) {
			log.Warnf("Domains for key %s have changed from %v to %v, must force update.",
				keyname, info.Domains, domainsSanitized)
			info.Domains = domainsSanitized
			forceUpdate = true
		}
		if acmeuser != "" && acmeuser != info.ACMEUser {
			log.Warnf("ACME user for key %s has changed from %s to %s, must force update.",
				keyname, info.ACMEUser, acmeuser)
			info.ACMEUser = acmeuser
			forceUpdate = true
		}
		if issuedBy != nil && !info.IssuedBy.Equal(issuedBy) {
			log.Infof("Issued-by user info for key %s has changed from %s to %s",
				keyname, info.IssuedBy, issuedBy)
			info.IssuedBy = issuedBy
		}

		now := time.Now()
		if !forceUpdate {
			var renewalDate time.Time
			if e.RecalcRenewalDate {
				renewalDate = info.ValidEndTime.AddDate(0, 0, -e.Conf.DaysRenewBeforeExpiry)
			} else {
				renewalDate = info.NextRenewalTime
			}
			if now.Before(renewalDate) {
				//Not yet due for renewal
				return &NoRenewalDueError{RenewalDate: renewalDate}
			}
			log.Infof("Key '%s' exists, cert is due for renewal", keyname)
		}
	}

	var privKey *rsa.PrivateKey
	if noKey {
		if keyMustExist {
			return &cmn.NotFoundError{RequestedResource: keyname}
		}
		info = &types.CACertInfo{
			ACMEUser: acmeuser,
			Domains:  domainsSanitized,
			IssuedBy: issuedBy,
		}
		log.Infof("Generating new RSA private key '%s' issued by user '%s'", keyname, acmeuser)
		privKey, err = generateRSAPrivateKey()
		if err != nil {
			return err
		}
		info.PrivKey = util.RSAPrivKeyToStr(privKey)
	} else {
		privKey, err = util.RSAPrivKeyFromStr(info.PrivKey)
		if err != nil {
			return err
		}
	}

	var u User = &DefaultUser{
		Config: e.Conf,
		State:  state,
		UID:    info.ACMEUser,
		Email:  e.getACMEEmail(info),
	}

	err = u.InitUser(false)
	if err != nil {
		return err
	}

	dnsprov := e.NewDNSProviderDNS3L(e.Context)

	err = u.GetClient().Challenge.SetDNS01Provider(dnsprov,
		dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			log.Debug("Skipping lego's DNS01 propagation check (ignore the previous 2 log lines).")
			return true, nil
		}))

	if err != nil {
		return err
	}

	var notafter time.Time
	if ttl <= 0 {
		notafter = time.Time{}
	} else {
		log.Debugf("Using custom TTL %s for certificate with key '%s'", ttl.String(), keyname)
		notafter = time.Now().Add(ttl)
	}

	request := certificate.ObtainRequest{
		Domains:    info.Domains,
		PrivateKey: privKey,
		Bundle:     false,
		NotAfter:   notafter,
	}
	log.Debugf("Requesting new certificate for key '%s', user '%s' via ACME",
		keyname, acmeuser)
	certificates, err := u.GetClient().Certificate.Obtain(request)
	if err != nil {
		return err
	}

	cert, err := util.ParseCertificatePEM(certificates.Certificate)
	if err != nil {
		return err
	}
	if len(cert) <= 0 {
		return errors.New("no certs have been returned")
	}

	info.ValidStartTime = cert[0].NotBefore
	info.ValidEndTime = cert[0].NotAfter
	info.NextRenewalTime = info.ValidEndTime.Add(
		time.Duration(-e.Conf.DaysRenewBeforeExpiry*24) * time.Hour)
	info.RenewedTime = time.Now()
	info.TTLSelected = ttl
	info.ClaimTime = info.RenewedTime
	certStr, err := util.ConvertCertBundleToPEMStr([]*x509.Certificate{cert[0]})
	if err != nil {
		return err
	}
	issuerCertStr := string(certificates.IssuerCertificate)

	if noKey {
		return castate.PutCACertData(keyname, e.CAID, info, certStr, issuerCertStr)
	}

	return castate.UpdateCACertData(keyname, e.CAID, info.RenewedTime, info.NextRenewalTime,
		info.ValidStartTime, info.ValidEndTime, certStr, issuerCertStr)

}

func (e *Engine) getACMEEmail(info *types.CACertInfo) string {
	if e.Conf.ACMERegisterWithoutEMail {
		return ""
	}
	return info.IssuedBy.Email
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

// NewDNSProviderOTC is a factory function for creating a new DNSProviderDNS3L
func (e *Engine) NewDNSProviderDNS3L(ctx types.ProviderConfigurationContext) *DNSProviderWrapper {
	return &DNSProviderWrapper{Context: ctx}
}

// The DNSProviderWrapper implements lego's DNS01 validation hook with acmeotc
type DNSProviderWrapper struct {
	Context types.ProviderConfigurationContext
}

// Present is called when the DNS01 challenge record shall be set up in the DNS.
// It wraps the acmeotc's DNS01 challenge setter into lego's DNS01 Present function.
func (p *DNSProviderWrapper) Present(domain, token, keyAuth string) error {

	dnsprovider, err := p.Context.GetDNSProviderForDomain(domain, true)
	if err != nil {
		return err
	}

	fqdn, challenge := legodns01.GetRecord(domain, keyAuth)
	log.Debugf("Presenting challenge '%s', for domain '%s', fqdn '%s'...", challenge, domain, fqdn)
	err = dnsprovider.SetRecordAcmeChallenge(domain, challenge)
	if err != nil {
		return err
	}
	log.Debugf("Presented challenge for domain '%s'", domain)

	chkconf := dnsprovider.GetPrecheckConfig()
	if chkconf.Enabled {
		log.WithFields(logrus.Fields{"fqdn": fqdn, "challenge": challenge}).Debug("Starting DNS propagation check...")
		rt := dnscommon.ResolveTester{}
		rt.ConfigureFromPrecheckConf(chkconf)
		err := rt.WaitForChallengeActive(fqdn, challenge)
		if err != nil {
			return fmt.Errorf("DNS propagation pre-check did not succeed: %w", err)
		}
		log.WithFields(logrus.Fields{"fqdn": fqdn, "challenge": challenge}).Debug("Successful DNS propagation check.")
	} else {
		log.WithFields(logrus.Fields{"fqdn": fqdn, "challenge": challenge}).Debug("DNS propagation check disabled.")
	}

	return nil
}

// CleanUp is called when the DNS01 challenge record shall be set up in the DNS.
// It wraps the acmeotc's DNS01 challenge deleter into lego's DNS01 CleanUp function.
func (p *DNSProviderWrapper) CleanUp(domain, token, keyAuth string) error {

	dnsprovider, err := p.Context.GetDNSProviderForDomain(domain, true)
	if err != nil {
		return err
	}

	log.Debugf("Cleaning up challenge for domain '%s'...", domain)
	err = dnsprovider.DeleteRecordAcmeChallenge(domain)
	if err != nil {
		return err
	}
	log.Debugf("Cleaned up challenge for domain '%s'", domain)
	return nil
}

func (p *DNSProviderWrapper) Timeout() (timeout, interval time.Duration) {
	return time.Second, 0
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

func (e *Engine) DeleteACMEUser(acmeuser string) error {

	state, err := e.State.NewSession()
	if err != nil {
		return err
	}
	defer state.Close()

	var u User = &DefaultUser{
		Config: e.Conf,
		State:  state,
		UID:    acmeuser,
		Email:  "",
	}

	return u.DeleteUser()

}

func (e *Engine) Revoke(acmeuser string, certPEM string) error {

	state, err := e.State.NewSession()
	if err != nil {
		return err
	}
	defer state.Close()

	var u User = &DefaultUser{
		Config: e.Conf,
		State:  state,
		UID:    acmeuser,
		Email:  "",
	}

	err = u.InitUser(true)
	if err != nil {
		return err
	}

	return u.GetClient().Certificate.Revoke([]byte(certPEM))

}
