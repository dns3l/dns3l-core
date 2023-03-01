package test

import (
	"errors"
	"net/http"

	"github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/service/auth"
)

type AuthStub struct {
	inited bool

	TestUsers map[string]AuthStubUser
}

type AuthStubUser struct {
	Name                 string
	Email                string
	DomainsAllowed       []string
	WriteAllowed         bool
	ReadAllowed          bool
	ReadAnyPublicAllowed bool
}

func (a *AuthStub) Init() error {
	a.inited = true
	return nil
}

func (a *AuthStub) AuthnGetAuthzInfo(r *http.Request) (auth.AuthorizationInfo, error) {

	if !a.inited {
		return nil, errors.New("auth stub reports auth has not been properly inited")
	}

	testusername := r.Header.Get("X-TestUser")
	v, exists := a.TestUsers[testusername]

	if !exists {
		return nil, &common.UnauthzedError{Msg: "test user not set or not existing"}
	}

	authzinfo := &auth.DefaultAuthorizationInfo{
		Name:                 v.Name,
		Username:             testusername,
		Email:                v.Email,
		DomainsAllowed:       v.DomainsAllowed,
		WriteAllowed:         v.WriteAllowed,
		ReadAllowed:          v.ReadAllowed,
		ReadAnyPublicAllowed: v.ReadAnyPublicAllowed,
	}

	return authzinfo, nil

}
