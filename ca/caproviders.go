package ca

import (
	"github.com/dta4/dns3l-go/ca/acme"
	"github.com/dta4/dns3l-go/ca/legacy"
	"github.com/dta4/dns3l-go/ca/types"
)

var CAProviderBuilders = map[string]func() types.CAProviderBuilder{
	"acme":   func() types.CAProviderBuilder { return &acme.Config{} },
	"legacy": func() types.CAProviderBuilder { return &legacy.Config{} },
}
