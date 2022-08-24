package service

import (
	"github.com/dns3l/dns3l-core/dns"
	dnstypes "github.com/dns3l/dns3l-core/dns/types"
	"github.com/dns3l/dns3l-core/state"
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
