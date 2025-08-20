package auth

import (
	"net/http"

	"github.com/dns3l/dns3l-core/service/auth/token"
	"github.com/dns3l/dns3l-core/service/auth/types"
)

type RESTAPIAuthProvider interface {
	Init() error
	AuthnGetAuthzInfo(r *http.Request) (types.AuthorizationInfo, error)
	GetServerInfoAuth() ServerInfoAuth
}

type AuthConfig struct {
	Provider RESTAPIAuthProvider
	Token    token.TokenAuthProvider
}

func (c *AuthConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {

	// We need to do the following workaround because unfortunately the OIDC auth
	// has been put at the top level of the "auth" element in the past - to
	// maintain config backwards compatibility
	var t struct {
		tokens token.TokenAuthConfig `yaml:"tokens"`
	}
	err := unmarshal(&t)
	if err != nil {
		return err
	}
	c.Token = token.TokenAuthProvider{
		Config: t.tokens,
	}

	// Since interfaces cannot be unpacked, we need to instantiate the one
	// and only OIDCHandler here. Need splitting like in dns and ca if this becomes
	// extended.
	c.Provider = &OIDCHandler{}
	return unmarshal(c.Provider)
}

type ServerInfoAuth interface{}

func (c *AuthConfig) Init() error {
	return c.Provider.Init()
}

func (c *AuthConfig) AuthnGetAuthzInfo(r *http.Request) (types.AuthorizationInfo, error) {
	tkninfo, err := c.Token.AuthnGetAuthzInfo(r)
	if err != nil {
		// error while doing token auth, falling back to provider's auth
		log.WithError(err).Error("Error while getting token authorization info.")
	} else {
		if tkninfo != nil {
			// a token has been found so use token's authz
			return tkninfo, nil
		}
	}
	// no token has been found or error from token auth provider
	return c.Provider.AuthnGetAuthzInfo(r)
}

func (c *AuthConfig) GetServerInfoAuth() ServerInfoAuth {
	return c.Provider.GetServerInfoAuth()
}
