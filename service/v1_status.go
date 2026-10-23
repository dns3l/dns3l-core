package service

import (
	"sync"
	"time"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
	"github.com/dns3l/dns3l-core/dns"
	"github.com/dns3l/dns3l-core/util"
)

func (s *V1) GetServerStatus() (*apiv1.ServerStatus, error) {
	s.logAction(nil, "GetServerStatus")

	return s.ServerStatus.GetServerStatus()
}

type ServerStatusProvider interface {
	GetServerStatus() (*apiv1.ServerStatus, error)
}

type serverStatusProviderImpl struct {
	config *Config
}

func (p *serverStatusProviderImpl) GetServerStatus() (*apiv1.ServerStatus, error) {
	status := &apiv1.ServerStatus{
		DNS:      make([]apiv1.HealthInfo, 0),
		CA:       make([]apiv1.HealthInfo, 0),
		DB:       make([]apiv1.HealthInfo, 0),
		Auth:     make([]apiv1.HealthInfo, 0),
		Resolver: make([]apiv1.HealthInfo, 0),
		Cached:   false,
		Age:      0,
	}

	// Get DNS Status
	for id, dnsProv := range p.config.DNS.Providers {
		health := dnsProv.Prov.GetHealth()

		status.DNS = append(status.DNS, apiv1.HealthInfo{
			ID:       id,
			Healthy:  health.Healthy,
			Message:  health.Message,
			Endpoint: health.Endpoint,
		})
	}

	// Get CA Status
	for id, caProv := range p.config.CA.Providers {
		if !caProv.Prov.IsEnabled() {
			continue
		}
		health := caProv.Prov.GetHealth()

		status.CA = append(status.CA, apiv1.HealthInfo{
			ID:       id,
			Healthy:  health.Healthy,
			Message:  health.Message,
			Endpoint: health.Endpoint,
		})
	}

	// Get DB Status
	dbHealth := p.config.DB.GetHealth()
	status.DB = []apiv1.HealthInfo{
		{
			ID:       "db",
			Healthy:  dbHealth.Healthy,
			Message:  dbHealth.Message,
			Endpoint: dbHealth.Endpoint,
		},
	}

	// Get Auth Status
	authHealth := p.config.Auth.GetHealth()
	for id, health := range authHealth {
		status.Auth = append(status.Auth, apiv1.HealthInfo{
			ID:       id,
			Healthy:  health.Healthy,
			Message:  health.Message,
			Endpoint: health.Endpoint,
		})
	}

	// Get Resolver Status
	for id, dnsProv := range p.config.DNS.Providers {
		preChkConf := dnsProv.Prov.GetPrecheckConfig()
		if preChkConf == nil {
			continue
		}
		for _, ns := range preChkConf.CheckNameservers {
			var message string
			healthy, err := util.CheckDNSServer(ns, collectRtznsForNS(p.config.RootZones, ns)...)()
			if err != nil {
				message = err.Error()
			}
			status.Resolver = append(status.Resolver, apiv1.HealthInfo{
				ID:       id,
				Healthy:  healthy,
				Message:  message,
				Endpoint: ns,
			})
		}
	}
	return status, nil
}

func NewCachingStatusProvider(cfg *Config, lifetime time.Duration) *serverStatusProviderCached {
	return &serverStatusProviderCached{
		provider: &serverStatusProviderImpl{
			config: cfg,
		},
		lifetime: lifetime,
	}
}

type serverStatusProviderCached struct {
	lock      sync.Mutex
	provider  ServerStatusProvider
	cache     *apiv1.ServerStatus
	lifetime  time.Duration
	lastFetch time.Time
}

func (p *serverStatusProviderCached) GetServerStatus() (*apiv1.ServerStatus, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.cache != nil && time.Since(p.lastFetch) < p.lifetime {
		status := *p.cache
		status.Cached = true
		status.Age = int32(time.Since(p.lastFetch).Seconds())
		return &status, nil
	}
	status, err := p.provider.GetServerStatus()
	if err != nil {
		return nil, err
	}
	p.cache = status
	p.lastFetch = time.Now()
	return status, nil
}

func collectRtznsForNS(zones dns.RootZones, ns string) []string {
	rootZonesForNs := make([]string, 0)
	for _, zone := range zones {
		if zone.DNSProvAutoDNS == ns || zone.DNSProvAcme == ns {
			rootZonesForNs = append(rootZonesForNs, zone.Root)
		}
	}
	return rootZonesForNs
}
