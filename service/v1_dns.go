package service

import (
	"fmt"

	"github.com/dta4/dns3l-go/ca"
	"github.com/dta4/dns3l-go/service/apiv1"
)

func (s *V1) GetDNSHandlers() []apiv1.DNSHandlerInfo {

	s.logAction(nil, "GetDNSHandlers")

	res := make([]apiv1.DNSHandlerInfo, 0, 10)
	for id, pinfo := range s.Service.Config.DNS.Providers {
		info := pinfo.Prov.GetInfo()
		res = append(res, apiv1.DNSHandlerInfo{
			ID:          id,
			Name:        info.Name,
			Feature:     info.Feature,
			ZoneNesting: info.ZoneNesting,
		})

	}
	return res
}

func (s *V1) GetDNSRootzones() []apiv1.DNSRootzoneInfo {

	s.logAction(nil, "GetDNSRootzones")

	res := make([]apiv1.DNSRootzoneInfo, 0, 10)
	for _, rz := range s.Service.Config.RootZones {
		res = append(res, apiv1.DNSRootzoneInfo{
			Root:    rz.Root,
			AutoDNS: rz.DNSProvAutoDNS,
			AcmeDNS: rz.DNSProvAcme,
			CA:      rz.CAs,
		})

	}
	return res
}

func caInfoFromProvider(id string, prov *ca.ProviderInfo) *apiv1.CAInfo {

	pinfo := prov.Prov.GetInfo()
	return &apiv1.CAInfo{
		ID:          id,
		Name:        pinfo.Name,
		Description: pinfo.Description,
		LogoPath:    pinfo.LogoPath,
		URL:         pinfo.URL,
		Roots:       pinfo.Roots,
		TotalValid:  prov.Prov.GetTotalValid(),
		TotalIssued: prov.Prov.GetTotalIssued(),
		Type:        pinfo.Type,
		IsAcme:      pinfo.IsAcme,
		Rootzones:   prov.GetRootZonesAsString(),
		Enabled:     prov.Prov.IsEnabled(),
	}
}

func (s *V1) GetCAs() []*apiv1.CAInfo {

	s.logAction(nil, "GetCAs")

	res := make([]*apiv1.CAInfo, 0, 10)
	for id, prov := range s.Service.Config.CA.Providers {
		res = append(res, caInfoFromProvider(id, prov))

	}
	return res
}

func (s *V1) GetCA(id string) (*apiv1.CAInfo, error) {

	s.logAction(nil, fmt.Sprintf("GetCA %s", id))

	prov, exists := s.Service.Config.CA.Providers[id]
	if !exists {
		return nil, fmt.Errorf("not found")
	}

	return caInfoFromProvider(id, prov), nil
}
