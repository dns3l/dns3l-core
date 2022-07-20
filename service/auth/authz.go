package auth

import (
	"fmt"

	"github.com/dta4/dns3l-go/common"
)

// Authorization info for a specific user, along with some personal data
type AuthorizationInfo struct {
	Username              string
	Email                 string
	RootzonesAllowed      map[string]bool
	WriteAllowed          bool
	ReadAllowed           bool
	AuthorizationDisabled bool
}

func (i *AuthorizationInfo) CheckAllowedToAccessZones(zones []string, read bool, write bool) error {

	if i.AuthorizationDisabled {
		return nil
	}

	for _, zone := range zones {
		if err := i.CheckAllowedToAccessZone(zone, read, write); err != nil {
			return err
		}
	}

	return nil

}

func (i *AuthorizationInfo) CheckAllowedToAccessZone(zone string, read bool, write bool) error {

	if i.AuthorizationDisabled {
		return nil
	}

	if !i.WriteAllowed && write {
		return &common.UnauthzedError{Msg: "write requested but not allowed to write"}
	}
	if !i.ReadAllowed && read {
		return &common.UnauthzedError{Msg: "read requested but not allowed to read"}
	}
	if !i.RootzonesAllowed[zone] {
		return &common.UnauthzedError{Msg: fmt.Sprintf("user has no permission for zone '%s'", zone)}
	}

	return nil
}

func (i *AuthorizationInfo) GetRootzones() []string {

	if i.AuthorizationDisabled {
		return nil
	}

	result := make([]string, 0, len(i.RootzonesAllowed))
	for k := range i.RootzonesAllowed {
		result = append(result, k)
	}
	return result
}
