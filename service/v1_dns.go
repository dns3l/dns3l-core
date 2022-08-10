package service

import (
	"fmt"

	"github.com/dta4/dns3l-go/ca"
	"github.com/dta4/dns3l-go/common"
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

func caInfoFromProvider(fu *ca.CAFunctionHandler, id string, prov *ca.ProviderInfo) (*apiv1.CAInfo, error) {

	pinfo := prov.Prov.GetInfo()

	totalvalid, err := fu.GetTotalValid(id)
	if err != nil {
		return nil, err
	}

	totalissued, err := fu.GetTotalIssued(id)
	if err != nil {
		return nil, err
	}

	return &apiv1.CAInfo{
		ID:          id,
		Name:        pinfo.Name,
		Description: pinfo.Description,
		LogoPath:    pinfo.LogoPath,
		URL:         pinfo.URL,
		Roots:       pinfo.Roots,
		TotalValid:  totalvalid,
		TotalIssued: totalissued,
		Type:        pinfo.Type,
		IsAcme:      pinfo.IsAcme,
		Rootzones:   prov.GetRootZonesAsString(),
		Enabled:     prov.Prov.IsEnabled(),
	}, nil
}

func (s *V1) GetCAs() ([]*apiv1.CAInfo, error) {

	s.logAction(nil, "GetCAs")

	fu := s.Service.Config.CA.Functions

	res := make([]*apiv1.CAInfo, 0, 10)
	for id, prov := range s.Service.Config.CA.Providers {
		cainfo, err := caInfoFromProvider(fu, id, prov)
		if err != nil {
			return nil, err
		}
		res = append(res, cainfo)

	}
	return res, nil
}

func (s *V1) GetCA(id string) (*apiv1.CAInfo, error) {

	s.logAction(nil, fmt.Sprintf("GetCA %s", id))

	fu := s.Service.Config.CA.Functions

	prov, exists := s.Service.Config.CA.Providers[id]
	if !exists {
		return nil, &common.NotFoundError{id}
	}

	res, err := caInfoFromProvider(fu, id, prov)
	if err != nil {
		return nil, err
	}

	return res, nil
}
