package acme

import (
	"fmt"
	"time"
)

type ACMEStateManager interface {
	NewSession() (ACMEStateManagerSession, error)
}

type ACMEStateManagerSession interface {
	Close() error

	//returns privKey, expiryTime, error
	GetACMECertPrivkeyByID(keyname string, userid string) (string, time.Time, error)

	//returns privKey, registrationStr, error
	GetACMEUserPrivkeyByID(userid string) (string, string, error)

	PutACMEUser(userid, privatekey, registrationStr string, registrationDate time.Time) error

	PutACMECertData(update bool, uid, keyname, privKeyStr, certStr, issuerCertStr string, expiryTime time.Time) error

	GetResource(keyName, userid, resourceName string) (string, error)

	GetResources(keyName, userid string, resourceNames ...string) ([]string, error)
}

//A NoRenewalDueError is thrown if the certificate is not yet outdated enough to be renewed
//The service refuses to renew it in order not to hit rate limits on the ACME provider
type NoRenewalDueError struct {
	RenewalDate time.Time
}

func (e *NoRenewalDueError) Error() string {
	return fmt.Sprintf("No renewal is due yet, earliest on %s", e.RenewalDate)
}

//A NotFoundError is thrown if the requested resource was not found or is not supposed
//to exist at all
type NotFoundError struct{}

func (e *NotFoundError) Error() string {
	return "Requested resource not found"
}
