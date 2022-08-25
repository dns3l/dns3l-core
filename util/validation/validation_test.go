package validation

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

type DomainNameWildcard struct {
	Domain string `validate:"fqdn|fqdnWildcard"`
}

type DomainName struct {
	Domain string `validate:"fqdn"`
}

func TestDomainNames(t *testing.T) {

	v := validator.New()

	err := RegisterDNS3LValidations(v)
	if err != nil {
		panic(err)
	}

	e := DomainName{Domain: "foo.bar"}
	validate(v, e)

	e = DomainName{Domain: "foo.bar."}
	validate(v, e)

	d := DomainNameWildcard{Domain: "*.foo.bar"}
	validate(v, d)

	d = DomainNameWildcard{Domain: "*.foo.bar."}
	validate(v, d)

	d = DomainNameWildcard{Domain: "*.foo.bar%.a.."}
	validateFail(v, d)

}

func validate(v *validator.Validate, i interface{}) {

	err := v.Struct(i)
	if err != nil {
		log.Println(">>> Failed:", i)
		panic(err)
	} else {
		log.Println("||| Success:", i)
	}

}

func validateFail(v *validator.Validate, i interface{}) {

	err := v.Struct(i)
	if err != nil {
		log.Println(">>> Failed:", i)
	} else {
		log.Println("||| Success:", i)
		panic("Did not fail.")
	}

}
