package apiv1

import (
	myvalidation "github.com/dta4/dns3l-go/util/validation"
	"github.com/go-playground/validator/v10"
)

type Validator struct {
	a *validator.Validate
}

func (v *Validator) Init() error {
	v.a = validator.New()
	myvalidation.RegisterDNS3LValidations(v.a)
	return nil
}

func (v *Validator) ValidateAPIStruct(rbody interface{}) error {
	return v.a.Struct(rbody)

}
