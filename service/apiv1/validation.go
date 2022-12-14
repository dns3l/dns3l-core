package apiv1

import (
	myvalidation "github.com/dns3l/dns3l-core/util/validation"
	"github.com/go-playground/validator/v10"
)

type Validator struct {
	a *validator.Validate
}

func (v *Validator) Init() error {
	v.a = validator.New()
	return myvalidation.RegisterDNS3LValidations(v.a)
}

func (v *Validator) ValidateAPIStruct(rbody interface{}) error {
	return v.a.Struct(rbody)

}
