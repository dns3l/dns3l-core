package types

import (
	"fmt"
	"strings"

	"github.com/dns3l/dns3l-core/common"
)

type UserInfo struct {
	Name  string //May be a full name (containing whitespaces and Unicode) or a M2M username
	Email string
}

func (ui *UserInfo) Validate() error {
	if strings.TrimSpace(ui.Email) == "" && strings.TrimSpace(ui.Name) == "" {
		return &common.NotAuthnedError{Msg: "neither 'user' nor 'email' has been provided in auth claims"}
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
