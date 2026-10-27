package infblx

import (
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/dns3l/dns3l-core/util"

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
		Host:    p.C.Host,
		Version: p.C.Version,
		Port:    p.C.Port,
	}

	authConfig := ibclient.AuthConfig{
		Username: p.C.Auth.User,
		Password: p.C.Auth.Pass,
	}

	if p.C.SSLVerify == "" {
		p.C.SSLVerify = "true"
	}

	transportConfig := ibclient.NewTransportConfig(p.C.SSLVerify, 20, 10)
	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}
	return ibclient.NewConnector(hostConfig, authConfig, transportConfig, requestBuilder, requestor)

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

func (p *DNSProvider) GetHealth() util.Health {
	var message string
	hostPort := p.C.Host + ":" + p.C.Port
	healthy, err := util.CheckHealth(
		util.CheckDNSResolution(p.C.Host),
		util.CheckTCPConnection(hostPort),
		util.CheckTLSConnection(hostPort, p.C.SSLVerify != "true"),
		// Auth check
		func() (bool, error) {
			_, err := p.getIBConnector()
			if err != nil {
				return false, err
			}
			return true, nil
		},
	)
	if err != nil {
		message = err.Error()
	}
	return util.Health{
		Healthy:  healthy,
		Message:  message,
		Endpoint: p.C.Host,
	}
}
