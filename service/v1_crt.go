package service

import (
	"errors"
	"fmt"
	"net"
	"time"

	cacommon "github.com/dta4/dns3l-go/ca/common"
	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/common"
	"github.com/dta4/dns3l-go/dns"
	dnstypes "github.com/dta4/dns3l-go/dns/types"
	"github.com/dta4/dns3l-go/service/apiv1"
	"github.com/dta4/dns3l-go/service/auth"
	"github.com/dta4/dns3l-go/util"
	"github.com/sirupsen/logrus"
)

func (s *V1) ClaimCertificate(caID string, cinfo *apiv1.CertClaimInfo, authz *auth.AuthorizationInfo) error {
	fu := s.Service.Config.CA.Functions

	s.logAction(authz, fmt.Sprintf("ClaimCertificate %s", caID))

	var firstDomain string
	if cinfo.Wildcard {
		firstDomain = "*." + cinfo.Name
	} else {
		firstDomain = cinfo.Name
	}

	domains := append([]string{firstDomain}, cinfo.SubjectAltNames...)

	err := checkAllowedToUseDomains(s.Service.Config.RootZones, authz, domains, false, true)
	if err != nil {
		return err
	}

	namerz, err := s.Service.Config.RootZones.GetLowestRZForDomain(firstDomain)
	if err != nil {
		return err
	}

	var autodnsV4 net.IP
	autodnsProvs := make(map[string]dnstypes.DNSProvider)
	if cinfo.AutoDNS != nil {
		autodnsV4 = net.ParseIP(cinfo.AutoDNS.IPv4)
		if autodnsV4 == nil {
			return &common.InvalidInputError{Msg: "Net address for AutoDNS not parseable"}
		}
		autodnsV4 = autodnsV4.To4()
		if autodnsV4 == nil {
			return &common.InvalidInputError{Msg: "Net address for AutoDNS not of v4 format"}
		}

		for _, domain := range domains {

			if util.IsWildcard(domain) {
				log.WithField("domain", domain).Debug("Ignoring wildcard domain for AutoDNS")
				continue
			}

			rz, err := s.Service.Config.RootZones.GetLowestRZForDomain(domain)
			if err != nil {
				return err
			}
			if rz.DNSProvAutoDNS == "" {
				return &common.InvalidInputError{Msg: fmt.Sprintf(
					"AutoDNS provider for root zone '%s' not configured", rz.Root)}
			}
			autodnsProv, exists := s.Service.Config.DNS.Providers[rz.DNSProvAutoDNS]
			if !exists {
				return &common.InvalidInputError{Msg: fmt.Sprintf(
					"AutoDNS provider '%s' configured for root zone '%s' not found", rz.DNSProvAutoDNS, rz.Root)}
			}
			autodnsProvs[domain] = autodnsProv.Prov
		}

	}

	err = fu.ClaimCertificate(caID, &types.CertificateClaimInfo{
		Name:    cinfo.Name,
		NameRZ:  namerz.Root,
		Domains: domains,
	})

	if err != nil {
		return err
	}

	if cinfo.AutoDNS != nil {
		for domain, prov := range autodnsProvs {
			log.WithFields(logrus.Fields{"domain": domain, "prov": prov, "addr": autodnsV4}).Info(
				"Setting AutoDNS entry")
			err := prov.SetRecordA(domain, 300, autodnsV4) //TODO TTL to config
			if err != nil {
				return err
			}
		}
	}

	return nil

}

func (s *V1) DeleteCertificate(caID, crtID string, authz *auth.AuthorizationInfo) error {

	s.logAction(authz, fmt.Sprintf("DeleteCertificate %s %s", caID, crtID))

	fu := s.Service.Config.CA.Functions

	// SANs are not checked for deletion permission at the moment...
	err := checkAllowedToUseDomain(s.Service.Config.RootZones, authz, crtID, false, true)
	if err != nil {
		return err
	}

	return fu.DeleteCertificate(caID, crtID)

}

func (s *V1) GetCertificateResource(caID, crtID, obj string, authz *auth.AuthorizationInfo) (string, string, error) {

	s.logAction(authz, fmt.Sprintf("GetCertificateResource %s %s %s", caID, crtID, obj))

	fu := s.Service.Config.CA.Functions
	res, err := fu.GetCertificateResource(crtID, caID, obj)
	if err != nil {
		return "", "", err
	}

	//GetCertificateResource does not modify anything, so check permissions after request...
	err = checkAllowedToUseDomains(s.Service.Config.RootZones, authz, res.Domains, true, false)
	if err != nil {
		return "", "", err
	}

	return res.PEMData, res.ContentType, err

}

func (s *V1) GetAllCertResources(caID, crtID string, authz *auth.AuthorizationInfo) (*apiv1.CertResources, error) {

	s.logAction(authz, fmt.Sprintf("GetAllCertResources %s %s", caID, crtID))

	fu := s.Service.Config.CA.Functions

	r, err := fu.GetCertificateResources(crtID, caID)
	if err != nil {
		return nil, err
	}

	//GetCertificateResources does not modify anything, so check permissions after request...
	err = checkAllowedToUseDomains(s.Service.Config.RootZones, authz, r.Domains, true, false)
	if err != nil {
		return nil, err
	}

	return &apiv1.CertResources{

		Certificate: r.Certificate,
		Key:         r.Key,
		Chain:       r.Chain,
		FullChain:   r.FullChain,
	}, nil
}

//if caID and/or crtID is "", infos will not be filtered on that value.
// Cannot filter for both
func (s *V1) GetCertificateInfos(caID string, crtID string, authz *auth.AuthorizationInfo, pginfo *util.PaginationInfo) ([]apiv1.CertInfo, error) {

	s.logAction(authz, fmt.Sprintf("GetCertificateInfos %s %s", caID, crtID))

	//TODO pagination

	fu := s.Service.Config.CA.Functions

	rz := authz.GetRootzones()

	if len(rz) <= 0 && !authz.AuthorizationDisabled {
		return nil, &common.UnauthzedError{Msg: "No authorization for any rootzones"}
	}

	r, err := fu.GetCertificateInfos(caID, crtID, rz, pginfo)
	if err != nil {
		return nil, err
	}
	res := make([]apiv1.CertInfo, len(r))
	for i, cinfo := range r {
		err := apiCertInfoFromCACertInfo(&cinfo, &res[i])
		if err != nil {
			return nil, err
		}

	}
	return res, nil

}

func (s *V1) GetCertificateInfo(caID string, crtID string, authz *auth.AuthorizationInfo) (*apiv1.CertInfo, error) {

	s.logAction(authz, fmt.Sprintf("GetCertificateInfo %s %s", caID, crtID))

	fu := s.Service.Config.CA.Functions

	//GetCertificateResources does not modify anything, so check permissions after request...
	err := checkAllowedToUseDomain(s.Service.Config.RootZones, authz, crtID, true, false)
	if err != nil {
		return nil, err
	}

	cinfo, err := fu.GetCertificateInfo(caID, crtID)
	if err != nil {
		return nil, err
	}
	res := &apiv1.CertInfo{}
	err = apiCertInfoFromCACertInfo(cinfo, res)
	if err != nil {
		return nil, err
	}

	return res, nil

}

func (s *V1) DeleteCertificatesAllCA(crtID string, authz *auth.AuthorizationInfo) error {

	s.logAction(authz, fmt.Sprintf("DeleteCertificatesAllCA %s", crtID))

	fu := s.Service.Config.CA.Functions

	//GetCertificateResources does not modify anything, so check permissions after request...
	err := checkAllowedToUseDomain(s.Service.Config.RootZones, authz, crtID, false, true)
	if err != nil {
		return err
	}

	return fu.DeleteCertificatesAllCA(crtID)

}

func apiCertInfoFromCACertInfo(source *types.CACertInfo, target *apiv1.CertInfo) error {
	cbatch, err := cacommon.ParseCertificatePEM([]byte(source.CertPEM))
	if err != nil {
		return err
	}

	if len(cbatch) <= 0 {
		return errors.New("returned cert data contains no PEM chunks")
	}

	cert := cbatch[0]

	target.Name = source.Name
	target.ClaimedOn = source.ClaimTime.Format(time.RFC3339)
	target.ValidTo = source.ValidEndTime.Format(time.RFC3339)
	target.Valid = isValid(source)
	target.RenewCount = source.RenewCount
	target.Wildcard = isWildcard(source.Domains)
	target.SubjectCN = cert.Subject.CommonName
	target.IssuerCN = cert.Issuer.CommonName
	target.Serial = cert.SerialNumber.String()
	target.ClaimedBy.Slug = source.IssuedByUser //TODO what about e-mail and name?

	return nil
}

func isValid(cinfo *types.CACertInfo) bool {
	now := time.Now()
	return now.Before(cinfo.ValidEndTime) && now.After(cinfo.ValidStartTime)
}

//This is defined as having
func isWildcard(domains []string) bool {
	if len(domains) <= 0 {
		return false
	}
	return util.IsWildcard(domains[0])
}

func checkAllowedToUseDomains(zones dns.RootZones, authz *auth.AuthorizationInfo, domains []string,
	read bool, write bool) error {

	rzs, err := getRootZonesForDomains(zones, domains)
	if err != nil {
		return err
	}

	return authz.CheckAllowedToAccessZones(rzs, read, write)

}

func checkAllowedToUseDomain(zones dns.RootZones, authz *auth.AuthorizationInfo, domain string,
	read bool, write bool) error {

	rz, err := zones.GetLowestRZForDomain(domain)
	if err != nil {
		return err
	}

	return authz.CheckAllowedToAccessZone(rz.Root, read, write)

}

func getRootZonesForDomains(zones dns.RootZones, domains []string) ([]string, error) {
	result := make([]string, len(domains))
	for i, domain := range domains {
		lowest_rz, err := zones.GetLowestRZForDomain(domain)
		if err != nil {
			return nil, err
		}
		result[i] = lowest_rz.Root
	}

	return result, nil

}
