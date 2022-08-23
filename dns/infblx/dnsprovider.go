package infblx

import (
	"github.com/dns3l/dns3l-core/dns/types"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:        p.C.Name,
		Feature:     []string{"A", "TXT"},
		ZoneNesting: true, //TODO
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

func (p *DNSProvider) getIBObjectManager(conn ibclient.IBConnector) ibclient.IBObjectManager {
	return ibclient.NewObjectManager(conn, "myclient", "")
}
