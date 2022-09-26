package auth

import (
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
	assert.Equal(t, dom, "foo.bar.")

	dom, valid = hut.groupsToDomain("dns3l_dns3l_domain_com")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "dns3l.domain.com.")

	dom, valid = hut.groupsToDomain("dns3l_underscore__in__name_com")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "underscore_in_name.com.")

	_, valid = hut.groupsToDomain("dns3l_")
	assert.Equal(t, valid, false)

	hut.GroupsPrefix = ""
	dom, valid = hut.groupsToDomain("dns3l_com")
	assert.Equal(t, valid, true)
	assert.Equal(t, dom, "dns3l.com.")

}
