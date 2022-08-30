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

	//returns privKey, registrationStr, error
	GetACMEUserPrivkeyByID(userid string) (string, string, error)

	PutACMEUser(userid, privatekey, registrationStr string, registrationDate time.Time) error

	DeleteACMEUser(userid string) error
}

//A NoRenewalDueError is thrown if the certificate is not yet outdated enough to be renewed
//The service refuses to renew it in order not to hit rate limits on the ACME provider
type NoRenewalDueError struct {
	RenewalDate time.Time
}

func (e *NoRenewalDueError) Error() string {
	return fmt.Sprintf("No renewal is due yet, earliest on %s", e.RenewalDate)
}
