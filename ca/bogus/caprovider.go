package bogus

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/dns3l/dns3l-core/ca/common"
	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/util"
)

type CAProvider struct {
	C       *Config `validate:"required"`
	ID      string
	Context types.ProviderConfigurationContext
}

func (p *CAProvider) GetInfo() *types.CAProviderInfo {

	return &types.CAProviderInfo{
		Name:        p.C.Name,
		Type:        p.C.CAType,
		Description: p.C.Description,
		LogoPath:    p.C.LogoPath,
		URL:         p.C.URL,
		Roots:       p.C.Roots,
		IsAcme:      false,
	}

}

func (p *CAProvider) Init(c types.ProviderConfigurationContext) error {

	p.ID = c.GetCAID()

	p.Context = c

	log.Debugf("Bogus CA provider initialized.")

	return nil

}

func (p *CAProvider) IsEnabled() bool {

	return !p.C.Disabled

}

func (p *CAProvider) PrecheckClaimCertificate(cinfo *types.CertificateClaimInfo) error {
	return nil
}

func (p *CAProvider) ClaimCertificate(cinfo *types.CertificateClaimInfo) error {

	castate, err := p.Context.GetStateMgr().NewSession()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, castate.Close)

	oldinfo, err := castate.GetCACertByID(cinfo.Name, p.ID)
	if err != nil {
		return err
	}

	if oldinfo != nil {
		return fmt.Errorf("key %s already existing, cannot create it again", cinfo.Name)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	ttl, err := common.GetTTL(cinfo, p.C.TTL)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		//default if unset in config and hint
		ttl = 90 * 24 * time.Hour
		log.Debugf("Using TTL %d for renewal (default).", ttl/24/time.Hour)
	} else {
		log.Debugf("Using TTL %d for renewal (custom).", ttl/24/time.Hour)
	}

	certStruct := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(ttl),
		SerialNumber: big.NewInt(123456),
		Subject: pkix.Name{
			CommonName:   cinfo.Name,
			Organization: []string{"DNS3L Bogus Org"},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &certStruct, &certStruct, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Generate a pem block with the certificate
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	issuerChain := bytes.Buffer{}

	err = pem.Encode(&issuerChain, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}

	err = pem.Encode(&issuerChain, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}

	info := &types.CACertInfo{
		Name:            cinfo.Name,
		PrivKey:         string(keyPem),
		IssuedBy:        cinfo.IssuedBy,
		ClaimTime:       time.Now(),
		RenewedTime:     time.Now(),
		NextRenewalTime: time.Now().Add(ttl),
		ValidStartTime:  time.Now(),
		ValidEndTime:    time.Now().Add(ttl),
		Domains:         cinfo.Domains,
		CertPEM:         string(certPem),
		TTLSelected:     cinfo.TTLSelected,
	} //TODO maybe there is the need to configure specific lifetimes for our tests

	return castate.PutCACertData(cinfo.Name, p.ID, info,
		info.CertPEM, issuerChain.String())

}

func (p *CAProvider) RenewCertificate(cinfo *types.CertificateRenewInfo) error {

	castate, err := p.Context.GetStateMgr().NewSession()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, castate.Close)

	info, err := castate.GetCACertByID(cinfo.CertKey, p.ID)
	if err != nil {
		return err
	}

	if info == nil {
		return fmt.Errorf("key %s does not exist, cannot renew", cinfo.CertKey)
	}

	var ttl = 90 * 24 * time.Hour
	if cinfo.TTLSelected > 0 {
		ttl = cinfo.TTLSelected
	}

	info.RenewedTime = time.Now()
	info.NextRenewalTime = time.Now().Add(ttl)
	info.ValidStartTime = time.Now()
	info.ValidEndTime = time.Now()
	info.ACMEUser = "bogus"

	info.CertPEM = "BOGUS - Cert (renewed)"

	return castate.UpdateCACertData(cinfo.CertKey, p.ID, info.RenewedTime,
		info.NextRenewalTime, info.ValidStartTime, info.ValidEndTime,
		info.CertPEM, "BOGUS - IssuerCert (renewed)")

}

func (p *CAProvider) CleanupAfterDeletion(keyID string, crt *types.CACertInfo) error {

	//Nothing to do with the bogus provider
	return nil

}

func (p *CAProvider) RevokeCertificate(keyID string, crt *types.CACertInfo) error {

	//Nothing to do with the bogus provider
	return nil

}
