package infblx

import (
	"github.com/dns3l/dns3l-core/dns/types"

	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:              p.C.Name,
		Feature:           []string{"A", "TXT"},
		ZoneNesting:       true, //TODO
		DefaultAutoDNSTTL: dnscommon.ValidateSetDefaultTTL(p.C.TTL.AutoDNS, 3600),
	}

}

func (p *DNSProvider) getIBConnector() (*ibclient.Connector, error) {

	hostConfig := ibclient.HostConfig{
		Host:     p.C.Host,
		Version:  p.C.Version,
		Port:     p.C.Port,
		Username: p.C.Auth.User,
		Password: p.C.Auth.Pass,
	}

	if p.C.SSLVerify == "" {
		p.C.SSLVerify = "true"
	}

	transportConfig := ibclient.NewTransportConfig(p.C.SSLVerify, 20, 10)
	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}
	return ibclient.NewConnector(hostConfig, transportConfig, requestBuilder, requestor)

}

// Will probably be used in the future
// nolint:unused
func (p *DNSProvider) getIBObjectManager(conn ibclient.IBConnector) ibclient.IBObjectManager {
	return ibclient.NewObjectManager(conn, "myclient", "")
}

func (p *DNSProvider) GetPrecheckConfig() *types.PrecheckConfig {
	conf := &p.C.PreCheck
	conf.SetDefaults()
	return conf
}
