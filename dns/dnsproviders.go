package dns

import (
	"github.com/dns3l/dns3l-core/dns/bogus"
	"github.com/dns3l/dns3l-core/dns/infblx"
	"github.com/dns3l/dns3l-core/dns/manual"
	"github.com/dns3l/dns3l-core/dns/otc"
	"github.com/dns3l/dns3l-core/dns/types"
)

var DNSProviderBuilders = map[string]func() types.DNSProviderBuilder{
	"infoblox": func() types.DNSProviderBuilder { return &infblx.Config{} },
	"otc":      func() types.DNSProviderBuilder { return &otc.Config{} },
	"bogus":    func() types.DNSProviderBuilder { return &bogus.Config{} },
	"manual":   func() types.DNSProviderBuilder { return &manual.Config{} },
}
