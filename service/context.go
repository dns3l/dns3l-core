package service

import (
	"github.com/dta4/dns3l-go/dns"
	dnstypes "github.com/dta4/dns3l-go/dns/types"
	"github.com/dta4/dns3l-go/state"
)

type CAConfigurationContextImpl struct {
	StateProvider state.StateProvider
	DNSConfig     *dns.Config
}

func (ctx *CAConfigurationContextImpl) GetStateProvider() state.StateProvider {
	return ctx.StateProvider
}

func (ctx *CAConfigurationContextImpl) GetDNSProvider(provID string) (dnstypes.DNSProvider, bool) {

	dnsprov, exists := ctx.DNSConfig.Providers[provID]
	if !exists {
		return nil, false
	}
	return dnsprov.Prov, true

}
