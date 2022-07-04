package dns

import (
	"github.com/dta4/dns3l-go/dns/infblx"
	"github.com/dta4/dns3l-go/dns/otc"
	"github.com/dta4/dns3l-go/dns/types"
)

var DNSProviderBuilders = map[string]func() types.DNSProviderBuilder{
	"infoblox": func() types.DNSProviderBuilder { return &infblx.Config{} },
	"otc":      func() types.DNSProviderBuilder { return &otc.Config{} },
}
