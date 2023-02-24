package auth

import (
	"fmt"
	"strings"

	"github.com/dns3l/dns3l-core/common"
)

type AuthorizationInfo interface {
	CheckAllowedToAccessDomains(domains []string, read bool, write bool) error
	CheckAllowedToAccessDomain(domain string, read bool, write bool) error
	GetUserID() string
	GetName() string
	GetEmail() string
	IsAuthzDisabled() bool
	GetDomainsAllowed() []string
}

// Authorization info for a specific user, along with some personal data
type DefaultAuthorizationInfo struct {

	//May be a full name (containing whitespaces and Unicode) or a M2M username
	Name                  string
	Username              string
	Email                 string
	DomainsAllowed        []string
	WriteAllowed          bool
	ReadAllowed           bool
	AuthorizationDisabled bool
}

func (i *DefaultAuthorizationInfo) GetUserID() string {
	return i.Username
}

func (i *DefaultAuthorizationInfo) GetName() string {
	return i.Name
}

func (i *DefaultAuthorizationInfo) GetEmail() string {
	return i.Email
}

func (i *DefaultAuthorizationInfo) IsAuthzDisabled() bool {
	return i.AuthorizationDisabled
}

func (i *DefaultAuthorizationInfo) CheckAllowedToAccessDomains(domains []string, read bool, write bool) error {

	if i.AuthorizationDisabled {
		return nil
	}

	for _, domain := range domains {
		if err := i.CheckAllowedToAccessDomain(domain, read, write); err != nil {
			return err
		}
	}

	return nil

}

func (i *DefaultAuthorizationInfo) CheckAllowedToAccessDomain(domain string, read bool, write bool) error {

	if i.AuthorizationDisabled {
		return nil
	}

	if !i.WriteAllowed && write {
		return &common.UnauthzedError{Msg: "write requested but not allowed to write"}
	}
	if !i.ReadAllowed && read {
		return &common.UnauthzedError{Msg: "read requested but not allowed to read"}
	}

	for _, domainAllowed := range i.DomainsAllowed {
		if strings.HasSuffix(domain, domainAllowed) {
			return nil
		}
	}

	return &common.UnauthzedError{Msg: fmt.Sprintf("user has no permission for domain '%s'", domain)}
}

func (i *DefaultAuthorizationInfo) GetDomainsAllowed() []string {

	if i.AuthorizationDisabled {
		return nil
	}
	return i.DomainsAllowed
}
