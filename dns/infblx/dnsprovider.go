package infblx

import (
	"github.com/dta4/dns3l-go/dns/types"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

type DNSProvider struct {
	c *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {

	return &types.DNSProviderInfo{
		Name:        p.c.Name,
		Feature:     []string{"A", "TXT"},
		ZoneNesting: true, //TODO
	}

}

func (p *DNSProvider) getIBConnector() (*ibclient.Connector, error) {

	hostConfig := ibclient.HostConfig{
		Host:     p.c.Host,
		Version:  p.c.Version,
		Port:     p.c.Port,
		Username: p.c.Auth.User,
		Password: p.c.Auth.Pass,
	}

	if p.c.SSLVerify == "" {
		p.c.SSLVerify = "true"
	}

	transportConfig := ibclient.NewTransportConfig(p.c.SSLVerify, 20, 10)
	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}
	return ibclient.NewConnector(hostConfig, transportConfig, requestBuilder, requestor)

}

func (p *DNSProvider) getIBObjectManager(conn ibclient.IBConnector) ibclient.IBObjectManager {
	return ibclient.NewObjectManager(conn, "myclient", "")
}
