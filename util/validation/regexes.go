package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

const (
	strAlphanumUnderscoreDash    = `^[a-zA-Z0-9_-]*$`
	strAlphanumUnderscoreDashDot = `^[a-zA-Z0-9\._-]*$`
	strWildcard                  = `^\*$`
	strFQDNDotAtEnd              = `^([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?(\.[a-zA-Z]{1}[a-zA-Z0-9]{0,62})\.$` //RFC 1123
	strFQDNWildcard              = `^\*\.([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?(\.[a-zA-Z]{1}[a-zA-Z0-9]{0,62})$`
)

var (
	reVals = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"alphanumUnderscoreDashDot", regexp.MustCompile(strAlphanumUnderscoreDashDot)},
		{"alphanumUnderscoreDash", regexp.MustCompile(strAlphanumUnderscoreDash)},
		{"wildcard", regexp.MustCompile(strWildcard)},
		{"fqdnDotAtEnd", regexp.MustCompile(strFQDNDotAtEnd)},
		{"fqdnWildcard", regexp.MustCompile(strFQDNWildcard)},
	}
)

func RegisterDNS3LValidations(val *validator.Validate) {
	for i := range reVals {
		reVal := &reVals[i] //otherwise we don't get pointers and run in segfault...
		val.RegisterValidation(reVal.name, func(fl validator.FieldLevel) bool {
			res := reVal.re.MatchString(fl.Field().String())
			log.WithFields(logrus.Fields{
				"validationType": reVal.name,
				"fieldval":       fl.Field().String(),
				"fieldname":      fl.FieldName(),
			}).Debugf("Input field validation success: %t", res)
			return res
		})
	}

}
