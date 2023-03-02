package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthRW(t *testing.T) {

	authzinfo1 := &DefaultAuthorizationInfo{
		Name:     "John Doe",
		Username: "Doe",
		Email:    "john@doe.email",
		DomainsAllowed: []string{
			"test.doe.email.",
			"test.doe.com.",
		},
		WriteAllowed:          true,
		ReadAllowed:           true,
		ReadAnyPublicAllowed:  false,
		AuthorizationDisabled: false,
	}

	assert.Error(t, authzinfo1.ChkAuthReadDomain("foo.com."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.com."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomain("test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthReadDomain("somethingtest.doe.email.")) //prefix only of same domain part
	assert.NoError(t, authzinfo1.ChkAuthReadDomain("foo.bar.test.doe.email."))
	assert.NoError(t, authzinfo1.ChkAuthWriteDomain("foo.baz.test.doe.com."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomains([]string{"foo.baz.test.doe.com.", "foo.com."}))
	assert.NoError(t, authzinfo1.ChkAuthWriteDomains([]string{"foo.baz.test.doe.com.", "baz.test.doe.email."}))
	assert.NoError(t, authzinfo1.ChkAuthReadDomainPublic("foo.baz.test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthReadDomainPublic("foo.baz.test.doe.de."))
	assert.Error(t, authzinfo1.ChkAuthReadDomainsPublic([]string{"foo.baz.test.doe.com.", "baz.test.doe.de.", "baz.test.doe.email."}))
	assert.False(t, authzinfo1.CanListPublicData())

}

func TestAuthR(t *testing.T) {

	authzinfo1 := &DefaultAuthorizationInfo{
		Name:     "Kilgore Trout",
		Username: "ktrout",
		Email:    "kilgore@trout.email",
		DomainsAllowed: []string{
			"test.doe.email.",
			"test.doe.com.",
		},
		WriteAllowed:          false,
		ReadAllowed:           true,
		ReadAnyPublicAllowed:  false,
		AuthorizationDisabled: false,
	}

	assert.Error(t, authzinfo1.ChkAuthReadDomain("foo.com."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.com."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomain("test.doe.email."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomain("foo.bar.test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.baz.test.doe.com."))
	assert.Error(t, authzinfo1.ChkAuthReadDomains([]string{"foo.baz.test.doe.com.", "foo.com."}))
	assert.Error(t, authzinfo1.ChkAuthWriteDomains([]string{"foo.baz.test.doe.com.", "baz.test.doe.email."}))
	assert.NoError(t, authzinfo1.ChkAuthReadDomains([]string{"foo.baz.test.doe.com.", "baz.test.doe.email."}))
	assert.NoError(t, authzinfo1.ChkAuthReadDomainPublic("foo.baz.test.doe.email."))

}

func TestAuthNothing(t *testing.T) {

	authzinfo1 := &DefaultAuthorizationInfo{
		Name:     "Kilgore Trout",
		Username: "ktrout",
		Email:    "kilgore@trout.email",
		DomainsAllowed: []string{
			"test.doe.email.",
			"test.doe.com.",
		},
		WriteAllowed:          false,
		ReadAllowed:           false,
		ReadAnyPublicAllowed:  false,
		AuthorizationDisabled: false,
	}

	assert.Error(t, authzinfo1.ChkAuthReadDomain("foo.com."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.com."))
	assert.Error(t, authzinfo1.ChkAuthReadDomain("test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthReadDomain("foo.bar.test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.baz.test.doe.com."))
	assert.Error(t, authzinfo1.ChkAuthReadDomainPublic("foo.baz.test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthReadDomainsPublic([]string{"foo.baz.test.doe.com.", "baz.test.doe.de.", "baz.test.doe.email."}))

}

func TestAuthPub(t *testing.T) {

	authzinfo1 := &DefaultAuthorizationInfo{
		Name:     "Kilgore Trout",
		Username: "ktrout",
		Email:    "kilgore@trout.email",
		DomainsAllowed: []string{
			"test.doe.email.",
			"test.doe.com.",
		},
		WriteAllowed:          false,
		ReadAllowed:           false,
		ReadAnyPublicAllowed:  true,
		AuthorizationDisabled: false,
	}

	assert.Error(t, authzinfo1.ChkAuthReadDomain("foo.com."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.com."))
	assert.Error(t, authzinfo1.ChkAuthReadDomain("test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthReadDomain("foo.bar.test.doe.email."))
	assert.Error(t, authzinfo1.ChkAuthWriteDomain("foo.baz.test.doe.com."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomainPublic("foo.baz.test.doe.de."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomainsPublic([]string{"foo.baz.test.doe.com.", "baz.test.doe.de.", "baz.test.doe.email."}))

	assert.True(t, authzinfo1.CanListPublicData())

}

func TestAuthDisabled(t *testing.T) {

	authzinfo1 := &DefaultAuthorizationInfo{
		Name:     "Kilgore Trout",
		Username: "ktrout",
		Email:    "kilgore@trout.email",
		DomainsAllowed: []string{
			"test.doe.email.",
			"test.doe.com.",
		},
		WriteAllowed:          false,
		ReadAllowed:           false,
		ReadAnyPublicAllowed:  false,
		AuthorizationDisabled: true,
	}

	assert.NoError(t, authzinfo1.ChkAuthReadDomain("foo.com."))
	assert.NoError(t, authzinfo1.ChkAuthWriteDomain("foo.com."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomain("test.doe.email."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomain("foo.bar.test.doe.email."))
	assert.NoError(t, authzinfo1.ChkAuthWriteDomain("foo.baz.test.doe.com."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomainPublic("foo.baz.test.doe.email."))
	assert.NoError(t, authzinfo1.ChkAuthReadDomains([]string{"foo.baz.test.doe.com.", "baz.test.doe.email."}))
	assert.NoError(t, authzinfo1.ChkAuthReadDomainsPublic([]string{"foo.baz.test.doe.com.", "baz.test.doe.email."}))
	assert.NoError(t, authzinfo1.ChkAuthWriteDomains([]string{"foo.baz.test.doe.com.", "blargh.com", "baz.test.doe.email."}))

	assert.True(t, authzinfo1.CanListPublicData())

}
