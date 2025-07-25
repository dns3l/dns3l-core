package acme

import (
	"fmt"

	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/service/auth"
	"github.com/dns3l/dns3l-core/util"
)

var schemes = map[string]ACMEUserScheme{
	"key":  ACMEUserPerKey{},
	"user": ACMEUserPerUser{},
	"one":  ACMEUserOne{},
}

func GetACMEUserScheme(schemename string) (ACMEUserScheme, error) {

	if schemename == "" {
		return ACMEUserPerKey{}, nil
	}

	us, exists := schemes[schemename]
	if !exists {
		return nil, fmt.Errorf("user scheme '%s' does not exist, only 'key', 'user', or 'one' allowed", schemename)
	}
	return us, nil
}

type ACMEUserScheme interface {

	// Returns the expected ACME user
	GetUserFor(keyname string, userinfo *auth.UserInfo) string

	// For cleaning up after key removal, returns empty string
	// if no ACME user shall be removed
	GetUserToDelete(keyname string, userinfo *auth.UserInfo,
		c types.ProviderConfigurationContext) (string, error)
}

type ACMEUserPerKey struct{}

func (s ACMEUserPerKey) GetUserFor(keyname string, userinfo *auth.UserInfo) string {
	return "acme-" + keyname
}

func (s ACMEUserPerKey) GetUserToDelete(keyname string, userinfo *auth.UserInfo,
	c types.ProviderConfigurationContext) (string, error) {
	return "acme-" + keyname, nil
}

type ACMEUserPerUser struct{}

func (s ACMEUserPerUser) GetUserFor(keyname string, userinfo *auth.UserInfo) string {
	return "user-" + userinfo.GetPreferredName()
}

func (s ACMEUserPerUser) GetUserToDelete(keyname string, userinfo *auth.UserInfo,
	c types.ProviderConfigurationContext) (string, error) {

	//Unfortunately, we need to make a DB operation here to determine if the user still has certs
	st, err := c.GetStateMgr().NewSession()
	if err != nil {
		return "", err
	}
	defer util.LogDefer(log, st.Close)

	acmeuser := "user-" + userinfo.GetPreferredName()

	hasCerts, err := st.UserHasCerts(userinfo, c.GetCAID())
	if err != nil {
		return "", err
	}
	if hasCerts {
		log.Infof("Not deleting ACME user '%s' because it still has certs", acmeuser)
		//If there are still certs assigned to user, do not delete acme user
		return "", nil
	}

	log.Infof("Deleting ACME user '%s' because it doesn't have any certs left", acmeuser)

	return acmeuser, nil
}

type ACMEUserOne struct{}

func (s ACMEUserOne) GetUserFor(keyname string, userinfo *auth.UserInfo) string {
	return "dns3l-one"
}

func (s ACMEUserOne) GetUserToDelete(keyname string, userinfo *auth.UserInfo,
	c types.ProviderConfigurationContext) (string, error) {
	//never delete the "singleton" user
	return "", nil
}
