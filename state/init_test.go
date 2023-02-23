package state

import (
	"testing"

	"github.com/go-playground/assert/v2"
)

func TestMySQLDSNForCreate(t *testing.T) {

	out, _, err := getAnonDBDSN("johndoe@unix(testdata/db.sock)/dns3ld?parseTime=true")
	if err != nil {
		panic(err)
	}

	assert.Equal(t,
		out,
		"johndoe@unix(testdata/db.sock)/?parseTime=true",
	)

}
