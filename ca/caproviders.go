package ca

import (
	"github.com/dns3l/dns3l-core/ca/acme"
	"github.com/dns3l/dns3l-core/ca/bogus"
	"github.com/dns3l/dns3l-core/ca/legacy"
)

var CAProviderBuilders = map[string]func() CAProviderBuilder{
	"acme":   func() CAProviderBuilder { return &acme.Config{} },
	"legacy": func() CAProviderBuilder { return &legacy.Config{} },
	"bogus":  func() CAProviderBuilder { return &bogus.Config{} },
}
