package otc

import (
	"fmt"

	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/dns3l/dns3l-core/util"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {
	return &types.DNSProviderInfo{
		Name:              p.C.Name,
		Feature:           []string{"A", "TXT"},
		ZoneNesting:       true,
		DefaultAutoDNSTTL: dnscommon.ValidateSetDefaultTTL(p.C.TTL.AutoDNS, 3600),
	}
}

func (p *DNSProvider) GetPrecheckConfig() *types.PrecheckConfig {
	conf := &p.C.PreCheck
	conf.SetDefaults()
	return conf
}

func (p *DNSProvider) GetHealth() util.Health {
	var message string
	healthy, err := util.CheckHealth(
		util.CheckDNSResolution(p.C.Auth.AuthURL),
		util.CheckTCPConnection(p.C.Auth.AuthURL),
		util.CheckTLSConnection(p.C.Auth.AuthURL, true),
		// Auth check
		func() (bool, error) {
			_, err := p.Auth()
			if err != nil {
				return false, fmt.Errorf("failed to authenticate with OTC: %w", err)
			}
			return true, nil
		},
		// App check
		func() (bool, error) {
			providerClient, err := p.Auth()
			if err != nil {
				return false, fmt.Errorf("failed to authenticate with OTC: %w", err)
			}
			const (
				healthCheckSubDomain = "healthcheck."
				healthCheckChallenge = "healthcheck"
			)

			client, err := openstack.NewDNSV2(providerClient, golangsdk.EndpointOpts{Region: p.C.OSRegion})
			if err != nil {
				return false, fmt.Errorf("failed to create DNS client for OTC: %w", err)
			}
			zones, err := getZones(client)
			if err != nil {
				return false, fmt.Errorf("failed to get zones from OTC: %w", err)
			}
			if len(zones) == 0 {
				return false, fmt.Errorf("no zones found in OTC")
			}
			healthCheckDomain := healthCheckSubDomain + zones[0].Name
			err = p.SetRecordAcmeChallenge(healthCheckDomain, "healthcheck")
			if err != nil {
				return false, fmt.Errorf("failed to set test record in OTC: %w", err)
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
		Endpoint: p.C.Auth.AuthURL,
	}
}
