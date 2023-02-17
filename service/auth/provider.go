package auth

import (
	"net/http"
)

type RESTAPIAuthProvider interface {
	Init() error
	AuthnGetAuthzInfo(r *http.Request) (AuthorizationInfo, error)
}

type AuthConfig struct {
	Provider RESTAPIAuthProvider
}

func (c *AuthConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Since interfaces cannot be unpacked, we need to instantiate the one
	// and only OIDCHandler here. Need splitting like in dns and ca if this becomes
	// extended.
	c.Provider = &OIDCHandler{}
	return unmarshal(c.Provider)
}
