package token

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenAuthProvider(t *testing.T) {

	abtoken, err := GenerateRandomToken()
	assert.NoError(t, err)

	ricktoken, err := GenerateRandomToken()
	assert.NoError(t, err)

	jerrytoken, err := GenerateRandomToken()
	assert.NoError(t, err)
	jerrytokenHash := ConvertPlainToken(jerrytoken)

	wrongtoken, err := GenerateRandomToken()
	assert.NoError(t, err)

	prov := TokenAuthProvider{
		Config: TokenAuthConfig{
			Static: []Token{
				{
					Name:           "AB", // name too small
					Plain:          abtoken,
					Write:          false,
					DomainsAllowed: []string{"foo.bar.rick.com", "bar.rick.de"},
				},
				{
					Name:           "Rick",
					Plain:          ricktoken,
					Write:          true,
					DomainsAllowed: []string{"foo.bar.rick.com", "bar.rick.de"},
				},
				{
					Name:           "Jerry",
					Sha256:         jerrytokenHash,
					Write:          false,
					DomainsAllowed: []string{"bar.rick.de"},
				},
			},
		},
	}

	authz, err := prov.AuthnGetAuthzInfo(makeemptyreq())
	assert.NoError(t, err)
	assert.Nil(t, authz)

	authz, err = prov.AuthnGetAuthzInfo(makereq("toosmall"))
	assert.NoError(t, err)
	assert.Nil(t, authz)

	authz, err = prov.AuthnGetAuthzInfo(makereq(abtoken))
	assert.NoError(t, err)
	assert.Nil(t, authz)

	authz, err = prov.AuthnGetAuthzInfo(makereq(ricktoken))
	assert.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "Rick", authz.GetUserInfo().Name)
	assert.NoError(t, authz.ChkAuthWriteDomains([]string{"bar.rick.de."}))

	authz, err = prov.AuthnGetAuthzInfo(makereq(jerrytoken))
	assert.NoError(t, err)
	assert.NotNil(t, authz)
	assert.Equal(t, "Jerry", authz.GetUserInfo().Name)
	assert.NoError(t, authz.ChkAuthReadDomains([]string{"bar.rick.de."}))
	assert.Error(t, authz.ChkAuthWriteDomains([]string{"bar.rick.de."}))

	authz, err = prov.AuthnGetAuthzInfo(makereq(wrongtoken))
	assert.NoError(t, err)
	assert.Nil(t, authz)

}

func makereq(token string) *http.Request {
	req := &http.Request{
		Header: make(map[string][]string),
	}
	req.Header.Add("X-DNS3L-Access-Token", token)
	return req
}

func makeemptyreq() *http.Request {
	req := &http.Request{
		Header: make(map[string][]string),
	}
	return req
}
