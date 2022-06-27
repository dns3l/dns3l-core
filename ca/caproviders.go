package ca

import (
	"github.com/dta4/dns3l-go/ca/acme"
	"github.com/dta4/dns3l-go/ca/legacy"
)

var CAProviderBuilders = map[string]func() CAProviderBuilder{
	"acme":   func() CAProviderBuilder { return &acme.Config{} },
	"legacy": func() CAProviderBuilder { return &legacy.Config{} },
}
