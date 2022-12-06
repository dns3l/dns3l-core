package auth

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
)

func TestGroupReplacement(t *testing.T) {

	hut := OIDCHandler{
		GroupsPrefix:     "dns3l_",
		GroupsReplaceDot: true,
	}

	dom, valid := hut.groupsToDomain("dns3l_foo_bar")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "foo.bar")

	dom, valid = hut.groupsToDomain("dns3l_dns3l_domain_com")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "dns3l.domain.com")

	dom, valid = hut.groupsToDomain("dns3l_underscore__in__name_com")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "underscore_in_name.com")

	_, valid = hut.groupsToDomain("dns3l_")
	assert.Equal(t, valid, false)

	hut.GroupsPrefix = ""
	dom, valid = hut.groupsToDomain("dns3l_com")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "dns3l.com")

}

const corrctTestToken = `Rm9vCg.eyJpc3MiOiJodHRwczovL2FjbWUuZGV2LmV4YW1wbGUuY29tL2F1dGgiLCJzdWIiOiJmbG9vYmxlY3JhbmsxMjM0NTY3OCIsImF1ZCI6ImRuczNsLWFwcCIsImV4cCI6MTY2OTk4MzE3NiwiaWF0IjoxNjY5OTgxMzc2LCJhdF9oYXNoIjoiMTIzNDU2Nzh4eXoiLCJlbWFpbCI6ImpvaG4uZG9lQGpvaG4uZG9lIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJKb2huIERvZSJ9Cg.U2lnbmF0dXJlCg`
const corrctTestToken2 = `Rm9vCg.eyJpc3MiOiJodHRwczovL2FjbWUuZGV2LmV4YW1wbGUyLmNvbS9hdXRoIiwic3ViIjoiZmxvb2JsZWNyYW5rMTIzNDU2NzgiLCJhdWQiOiJkbnMzbC1hcHAiLCJleHAiOjE2Njk5ODMxNzYsImlhdCI6MTY2OTk4MTM3NiwiYXRfaGFzaCI6IjEyMzQ1Njc4eHl6IiwiZW1haWwiOiJqb2huLmRvZUBqb2huLmRvZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiSm9obiBEb2UifQo.U2lnbmF0dXJlCg`
const wrongTestToken1 = `eyJpc3MiOiJodHRwczovL2FjbWUuZGV2LmV4YW1wbGUuY29tL2F1dGgiLCJzdWIiOiJmbG9vYmxlY3JhbmsxMjM0NTY3OCIsImF1ZCI6ImRuczNsLWFwcCIsImV4cCI6MTY2OTk4MzE3NiwiaWF0IjoxNjY5OTgxMzc2LCJhdF9oYXNoIjoiMTIzNDU2Nzh4eXoiLCJlbWFpbCI6ImpvaG4uZG9lQGpvaG4uZG9lIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJKb2huIERvZSJ9Cg.U2lnbmF0dXJlCg`
const wrongTestToken2 = `Rm9vCg`

const tokenUnknownIssuer = `Rm9vCg.eyJpc3MiOiJodHRwczovL2FjbWUuZGV2LnVua25vd24uY29tL2F1dGgiLCJzdWIiOiJmbG9vYmxlY3JhbmsxMjM0NTY3OCIsImF1ZCI6ImRuczNsLWFwcCIsImV4cCI6MTY2OTk4MzE3NiwiaWF0IjoxNjY5OTgxMzc2LCJhdF9oYXNoIjoiMTIzNDU2Nzh4eXoiLCJlbWFpbCI6ImpvaG4uZG9lQGpvaG4uZG9lIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJKb2huIERvZSJ9Cg.U2lnbmF0dXJlCg`

func TestIssuerExtraction(t *testing.T) {

	token, err := getIssuerURL(corrctTestToken)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, token, "https://acme.dev.example.com/auth")

	token, err = getIssuerURL(corrctTestToken2)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, token, "https://acme.dev.example2.com/auth")

	_, err = getIssuerURL(wrongTestToken1)
	assertErrorContains(err, "invalid character 'S'")

	_, err = getIssuerURL(wrongTestToken2)
	assertErrorContains(err, "need 3-part OIDC token, but got 1 parts")

}

func TestSelectIssuer(t *testing.T) {

	h := OIDCHandler{
		OIDCBindings: map[string]OIDCBinding{
			"https://acme.dev.example.com/auth": {
				ClientID: "example-client",
			},
			"https://acme.dev.example2.com/auth": {
				ClientID: "example2-client",
			},
		},
	}

	binding, err := h.selectIssuer(corrctTestToken)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, binding.ClientID, "example-client")

	binding, err = h.selectIssuer(corrctTestToken2)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, binding.ClientID, "example2-client")

	_, err = h.selectIssuer(wrongTestToken1)
	assertErrorContains(err, "invalid character 'S'")

	_, err = h.selectIssuer(tokenUnknownIssuer)
	assertErrorContains(err, "no OIDC binding exists with the given issuer URL")

}

func assertErrorContains(err error, containedStr string) {
	if err == nil {
		panic(fmt.Errorf("no error was thrown while checking for string '%s' contained in error", containedStr))
	}

	if !strings.Contains(err.Error(), containedStr) {
		panic(fmt.Errorf("Error does not contain %s: %w", containedStr, err))
	}
}
