package acme

/*

Acmeotc autokey user management.
Example usage of a DB-backed user:

	u := DBUser{
		DB:      //sql.DB object maintaining connection to the database.
		UID:     //the user's acmeotc ID (a string with no special chars..)
		Email:   //the user's LE e-mail address
		Staging: //whether this user is a staging (true) or production (false) user.
	}

	err = u.InitUser()
	if err != nil {
		return err
	}

	err = u.Client.Challenge.SetDNS01Provider(e.NewDNSProviderOTC())
	if err != nil {
		return err
	}

	request := certificate.ObtainRequest{
		Domains:    domainsSanitized,
		PrivateKey: privKey,
		Bundle:     true,
	}
	log.Printf("%sRequesting new certificate for key '%s', user '%s' via ACME...",
		logPrefixFunctions, keyname, uid)
	certificates, err := u.Client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("Problem while obtaining certificate: %v", err)
	}
*/

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/dns3l/dns3l-core/common"
	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// User resembles an ACME Autokey user. Cares about initialization
// and provides a simpler interface than just the ACME interface.
// Inherits functions from lego's AcmeUser
type User interface {
	InitUser() error
	GetEmail() string
	GetRegistration() *registration.Resource
	GetPrivateKey() crypto.PrivateKey
	GetClient() *lego.Client
	DeleteUser() error
}

// DBUser is a User implementation that is SQL-database-backed (tested with postgres and sqlite)
type DefaultUser struct {
	UID          string
	Config       *Config
	State        ACMEStateManagerSession
	Email        string
	registration *registration.Resource
	key          *ecdsa.PrivateKey
	client       *lego.Client
}

// GetEmail Returns the user's e-mail address to be used for internal Let's Encrypt purposes.
func (u *DefaultUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the user's lego registration object
func (u *DefaultUser) GetRegistration() *registration.Resource {
	return u.registration
}

// GetPrivateKey returns the user's ECDSA private key
func (u *DefaultUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// GetPrivateKey returns the user's ECDSA private key
func (u *DefaultUser) GetClient() *lego.Client {
	return u.client
}

// InitUser ensures that the user is intialized. Afther the user object has been created,
// it automatically cares about that any non-existing user is created at Let's Encrypt and
// keep authentication and identification state. If the user already exists, it does nothing
// at LE but loads its authentication / identification state.
func (u *DefaultUser) InitUser() error {

	log.Debugf("Initializing ACME user '%s'", u.UID)

	keyStr, registrationStr, err := u.State.GetACMEUserPrivkeyByID(u.UID)
	if err != nil {
		return err
	}
	notRegistered := keyStr == ""

	if notRegistered {
		log.Debugf("User '%s' is not yet initialized with ACME provider, creating new key "+
			"material and registering...", u.UID)
		u.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
	} else {
		log.Debugf("User '%s' is already initialized with ACME provider, using existing "+
			"auth material", u.UID)
		u.key, err = ecKeyFromStr(keyStr)
		if err != nil {
			return err
		}
		u.registration, err = registrationFromStr(registrationStr)
		if err != nil {
			return fmt.Errorf("problem while parsing existing registration data: %v", err)
		}
	}

	lconfig := lego.NewConfig(u)
	lconfig.Certificate.KeyType = certcrypto.RSA2048
	lconfig.CADirURL = u.Config.API
	if u.Config.HTTPInsecureSkipVerify {
		lconfig.HTTPClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}

	u.client, err = lego.NewClient(lconfig)
	if err != nil {
		return err
	}

	if notRegistered {

		if u.Config.EAB.KID == "" {

			u.registration, err = u.client.Registration.Register(registration.RegisterOptions{
				TermsOfServiceAgreed: true})
			if err != nil {
				return fmt.Errorf("problem when registering: %v", err)
			}
		} else {

			eabopts := registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  u.Config.EAB.KID,
				HmacEncoded:          u.Config.EAB.HMAC,
			}

			u.registration, err = u.client.Registration.RegisterWithExternalAccountBinding(eabopts)
			if err != nil {
				return fmt.Errorf("problem when registering with EAB: %v", err)
			}
		}

		log.Debugf("User '%s' was successfully registered with ACME provider, storing info",
			u.UID)

		keyStr, err = ecKeyToStr(u.key)
		if err != nil {
			return fmt.Errorf("problem while serializing private key: %v", err)
		}

		registrationStr, err = registrationToStr(u.registration)
		if err != nil {
			return fmt.Errorf("problem while serializing registration data: %v", err)
		}

		err = u.State.PutACMEUser(u.UID, keyStr, registrationStr, time.Now())
		if err != nil {
			return fmt.Errorf("problem while storing user in database: %v", err)
		}
	}

	log.Debugf("User '%s' successfully initialized", u.UID)

	return nil
}

func (u *DefaultUser) DeleteUser() error {
	log.Debugf("Deleting ACME user '%s'", u.UID)

	keyStr, registrationStr, err := u.State.GetACMEUserPrivkeyByID(u.UID)
	if err != nil {
		return err
	}

	if keyStr == "" {
		return &common.NotFoundError{RequestedResource: u.UID}
	}

	u.key, err = ecKeyFromStr(keyStr)
	if err != nil {
		return err
	}
	u.registration, err = registrationFromStr(registrationStr)
	if err != nil {
		return fmt.Errorf("problem while parsing existing registration data: %v", err)
	}

	lconfig := lego.NewConfig(u)
	lconfig.Certificate.KeyType = certcrypto.RSA2048
	lconfig.CADirURL = u.Config.API
	if u.Config.HTTPInsecureSkipVerify {
		lconfig.HTTPClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}

	u.client, err = lego.NewClient(lconfig)
	if err != nil {
		return err
	}

	err = u.client.Registration.DeleteRegistration()
	if err != nil {
		return fmt.Errorf("error while deleting remote registration of ACME user: %v", err)
	}

	u.client = nil

	//TODO maybe a force option if user cannot be found remotely but still exists locally...

	return u.State.DeleteACMEUser(u.UID)

}

func registrationToStr(r *registration.Resource) (string, error) {
	regBytes, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(regBytes), nil

}

func registrationFromStr(registrationStr string) (*registration.Resource, error) {

	res := &registration.Resource{}
	err := json.Unmarshal([]byte(registrationStr), res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func ecKeyToStr(k *ecdsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", err
	}
	keyStr := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return string(keyStr), nil
}

func ecKeyFromStr(keyStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyStr))
	return x509.ParseECPrivateKey(block.Bytes)
}
