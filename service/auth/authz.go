package auth

import (
	"fmt"
	"strings"

	"github.com/dns3l/dns3l-core/common"
)

type AuthorizationInfo interface {

	//If the client is allowed to read public PKI material
	ChkAuthReadDomainPublic(domain string) error
	ChkAuthReadDomainsPublic(domains []string) error

	//If the client is allowed to read private PKI material
	ChkAuthReadDomain(domain string) error
	ChkAuthReadDomains(domains []string) error

	//If the client is allowed to write-access the given domain
	ChkAuthWriteDomain(domain string) error
	ChkAuthWriteDomains(domains []string) error

	GetDomainsAllowed() []string
	CanListPublicData() bool

	GetUserInfo() *UserInfo
	IsAuthzDisabled() bool

	String() string
}

type UserInfo struct {
	Name  string //May be a full name (containing whitespaces and Unicode) or a M2M username
	Email string
}

func (ui *UserInfo) Validate() error {
	if strings.TrimSpace(ui.Email) == "" && strings.TrimSpace(ui.Name) == "" {
		return &common.NotAuthnedError{Msg: "neither 'user' nor 'email' has been provided in OIDC token claims"}
	}
	return nil
}

func (ui *UserInfo) GetPreferredName() string {
	if ui.Email != "" {
		return ui.Email
	}
	return ui.Name
}

func (ui *UserInfo) String() string {
	return fmt.Sprintf("%s,%s", ui.Name, ui.Email)
}

func (ui *UserInfo) Equal(other *UserInfo) bool {
	if ui.Name != other.Name {
		return false
	}
	if ui.Email != other.Email {
		return false
	}
	return true
}

// Authorization info for a specific user, along with some personal data
type DefaultAuthorizationInfo struct {
	UserInfo              *UserInfo
	DomainsAllowed        []string
	WriteAllowed          bool
	ReadAllowed           bool
	ReadAnyPublicAllowed  bool //If this is set to true, no domain ACL check is done for public data!
	AuthorizationDisabled bool //everything will be allowed, danger zone!
}

func (i *DefaultAuthorizationInfo) String() string {
	return fmt.Sprintf("userinfo=%s, domains=%s, write=%t, read=%t, readpub=%t, authzdis=%t",
		i.UserInfo, i.DomainsAllowed, i.WriteAllowed, i.ReadAllowed,
		i.ReadAnyPublicAllowed, i.AuthorizationDisabled)
}

func (i *DefaultAuthorizationInfo) GetUserInfo() *UserInfo {
	return i.UserInfo
}

func (i *DefaultAuthorizationInfo) IsAuthzDisabled() bool {
	return i.AuthorizationDisabled
}

func (i *DefaultAuthorizationInfo) ChkAuthReadDomainPublic(domain string) error {

	if i.AuthorizationDisabled {
		return nil
	}

	if i.ReadAnyPublicAllowed {
		return nil //we override ACL check for public data
	}
	//otherwise treat it like private data
	return i.ChkAuthReadDomain(domain)
}

func (i *DefaultAuthorizationInfo) ChkAuthReadDomainsPublic(domains []string) error {
	if i.AuthorizationDisabled {
		return nil
	}

	if i.ReadAnyPublicAllowed {
		return nil //we override ACL check for public data
	}

	return i.ChkAuthReadDomains(domains)
}

func (i *DefaultAuthorizationInfo) ChkAuthReadDomain(domain string) error {
	if i.AuthorizationDisabled {
		return nil
	}

	if !i.ReadAllowed {
		return ReadNotAllowed
	}

	return i.checkAllowedToAccessDomain(domain)

}

func (i *DefaultAuthorizationInfo) ChkAuthReadDomains(domains []string) error {

	if i.AuthorizationDisabled {
		return nil
	}

	if !i.ReadAllowed {
		return ReadNotAllowed
	}

	return i.checkAllowedToAccessDomains(domains)

}

func (i *DefaultAuthorizationInfo) ChkAuthWriteDomain(domain string) error {

	if i.AuthorizationDisabled {
		return nil
	}

	if !i.WriteAllowed {
		return WriteNotAllowed
	}

	return i.checkAllowedToAccessDomain(domain)

}

func (i *DefaultAuthorizationInfo) ChkAuthWriteDomains(domains []string) error {

	if i.AuthorizationDisabled {
		return nil
	}

	if !i.WriteAllowed {
		return WriteNotAllowed
	}

	return i.checkAllowedToAccessDomains(domains)

}

var ReadNotAllowed error = &common.UnauthzedError{Msg: "read requested but not allowed to read"}
var WriteNotAllowed error = &common.UnauthzedError{Msg: "write requested but not allowed to write"}

func (i *DefaultAuthorizationInfo) checkAllowedToAccessDomains(domains []string) error {

	for _, domain := range domains {
		if err := i.checkAllowedToAccessDomain(domain); err != nil {
			return err
		}
	}

	return nil

}

func (i *DefaultAuthorizationInfo) checkAllowedToAccessDomain(domain string) error {

	for _, domainAllowed := range i.DomainsAllowed {
		if strings.HasSuffix(domain, "."+domainAllowed) {
			return nil //prefix allowed
		} else if domain == domainAllowed {
			return nil //exact match also allowed
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

func (i *DefaultAuthorizationInfo) CanListPublicData() bool {

	return i.AuthorizationDisabled || i.ReadAnyPublicAllowed

}
