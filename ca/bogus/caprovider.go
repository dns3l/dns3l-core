package bogus

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/dns3l/dns3l-core/ca/types"
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

	return true

}

func (p *CAProvider) ClaimCertificate(cinfo *types.CertificateClaimInfo) error {

	castate, err := p.Context.GetStateMgr().NewSession()
	if err != nil {
		return err
	}
	defer castate.Close()

	oldinfo, err := castate.GetCACertByID(cinfo.Name, p.ID)
	if err != nil {
		return err
	}

	if oldinfo != nil {
		return fmt.Errorf("Key %s already existing, cannot create it again.", cinfo.Name)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	certStruct := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
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

	info := &types.CACertInfo{
		Name:            cinfo.Name,
		PrivKey:         string(keyPem),
		IssuedByUser:    cinfo.IssuedBy,
		IssuedByEmail:   cinfo.IssuedByEmail,
		ClaimTime:       time.Now(),
		RenewedTime:     time.Now(),
		NextRenewalTime: time.Now().Add(90 * 24 * time.Hour),
		ValidStartTime:  time.Now(),
		ValidEndTime:    time.Now().Add(90 * 24 * time.Hour),
		Domains:         cinfo.Domains,
		CertPEM:         string(certPem),
	} //TODO maybe there is the need to configure specific lifetimes for our tests

	return castate.PutCACertData(cinfo.Name, p.ID, info,
		info.CertPEM, string(certPem))

}

func (p *CAProvider) RenewCertificate(cinfo *types.CertificateRenewInfo) error {

	castate, err := p.Context.GetStateMgr().NewSession()
	if err != nil {
		return err
	}
	defer castate.Close()

	info, err := castate.GetCACertByID(cinfo.CertKey, p.ID)
	if err != nil {
		return err
	}

	if info == nil {
		return fmt.Errorf("Key %s does not exist, cannot renew.", cinfo.CertKey)
	}

	info.RenewedTime = time.Now()
	info.NextRenewalTime = time.Now().Add(90 * 24 * time.Hour)
	info.ValidStartTime = time.Now()
	info.ValidEndTime = time.Now()
	info.ACMEUser = "bogus"

	info.CertPEM = "BOGUS - Cert (renewed)"

	return castate.UpdateCACertData(cinfo.CertKey, p.ID, info.RenewedTime,
		info.NextRenewalTime, info.ValidStartTime, info.ValidEndTime,
		info.CertPEM, "BOGUS - IssuerCert (renewed)")

}

func (p *CAProvider) CleanupAfterDeletion(keyID string) error {

	//Nothing to do with the bogus provider
	return nil

}
