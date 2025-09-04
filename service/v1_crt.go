package service

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/service/apiv1"
	"github.com/dns3l/dns3l-core/util"
	"github.com/sirupsen/logrus"

	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
)

func (s *V1) ClaimCertificate(caID string, cinfo *apiv1.CertClaimInfo, authz authtypes.AuthorizationInfo) error {
	fu := s.Service.Config.CA.Functions

	s.logAction(authz, fmt.Sprintf("ClaimCertificate %s", caID))

	//Ensure standard notation
	cinfo.Name = util.GetDomainFQDNDot(cinfo.Name)
	for i := range cinfo.SubjectAltNames {
		cinfo.SubjectAltNames[i] = util.GetDomainFQDNDot(cinfo.SubjectAltNames[i])
	}

	var firstDomain string
	if cinfo.Wildcard {
		firstDomain = "*." + cinfo.Name
	} else {
		firstDomain = cinfo.Name
	}

	domains := append([]string{firstDomain}, cinfo.SubjectAltNames...)

	err := authz.ChkAuthWriteDomains(domains)
	if err != nil {
		return err
	}

	namerz, err := s.Service.Config.RootZones.GetLowestRZForDomain(firstDomain)
	if err != nil {
		return err
	}

	var autodnsV4 net.IP

	trl := make(util.TransactionalJobList, 0, 10)

	var ClaimFunc func() error

	trl = append(trl, &util.TransactionalJobImpl{
		DoFunc: func() error {
			var err error
			ClaimFunc, err = fu.PrepareClaimCertificate(caID, &types.CertificateClaimInfo{
				Name:        cinfo.Name,
				NameRZ:      namerz.Root,
				Domains:     domains,
				IssuedBy:    authz.GetUserInfo(),
				TTLSelected: util.DaysToDuration(cinfo.Hints.TTL),
			})
			return err
		},
		UndoFunc: nil, //not needed because this is always the last thing that is executed
	})

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

			domain := domain //bump the scope

			trl = append(trl, &util.TransactionalJobImpl{
				DoFunc: func() error {
					log.WithFields(logrus.Fields{"domain": domain, "prov": autodnsProv.Prov, "addr": autodnsV4}).Info(
						"Setting AutoDNS entry")
					return autodnsProv.Prov.SetRecordA(domain, autodnsProv.Prov.GetInfo().DefaultAutoDNSTTL, autodnsV4)
				},
				UndoFunc: func() error {
					log.WithFields(logrus.Fields{"domain": domain, "prov": autodnsProv.Prov}).Info(
						"Rolling back AutoDNS entry")
					return autodnsProv.Prov.DeleteRecordA(domain)
				},
			})
		}

	}

	if strings.TrimSpace(authz.GetUserInfo().Email) == "" {
		return &common.UnauthzedError{Msg: "the user's email address has not been provided by the auth provider, required for claiming certificate"}
	}

	trl = append(trl, &util.TransactionalJobImpl{
		DoFunc: func() error {
			return ClaimFunc()
		},
		UndoFunc: nil, //not needed because this is always the last thing that is executed
	})

	return trl.Commit()

}

func (s *V1) DeleteCertificate(caID, crtID string, authz authtypes.AuthorizationInfo) error {

	s.logAction(authz, fmt.Sprintf("DeleteCertificate %s %s", caID, crtID))

	crtID = util.GetDomainFQDNDot(crtID)

	fu := s.Service.Config.CA.Functions

	// SANs are not checked for deletion permission at the moment...
	err := authz.ChkAuthWriteDomain(crtID)
	if err != nil {
		return err
	}

	return fu.DeleteCertificate(caID, crtID)

}

func (s *V1) GetCertificateResource(caID, crtID, obj string, authz authtypes.AuthorizationInfo) (string, string, error) {

	s.logAction(authz, fmt.Sprintf("GetCertificateResource %s %s %s", caID, crtID, obj))

	crtID = util.GetDomainFQDNDot(crtID)

	fu := s.Service.Config.CA.Functions
	res, err := fu.GetCertificateResource(crtID, caID, obj)
	if err != nil {
		return "", "", err
	}

	//GetCertificateResource does not modify anything, so check permissions after request...
	if res.CanBePublic {
		err = authz.ChkAuthReadDomainsPublic(res.Domains)
	} else {
		err = authz.ChkAuthReadDomains(res.Domains)
	}

	if err != nil {
		return "", "", err
	}

	return res.PEMData, res.ContentType, err

}

func (s *V1) GetAllCertResources(caID, crtID string, authz authtypes.AuthorizationInfo) (*apiv1.CertResources, error) {

	s.logAction(authz, fmt.Sprintf("GetAllCertResources %s %s", caID, crtID))

	crtID = util.GetDomainFQDNDot(crtID)

	fu := s.Service.Config.CA.Functions

	r, err := fu.GetCertificateResources(crtID, caID)
	if err != nil {
		return nil, err
	}

	//GetCertificateResources does not modify anything, so check permissions after request when we know the domains...
	err = authz.ChkAuthReadDomains(r.Domains)
	if err != nil {
		return nil, err
	}

	root, chain, err := util.SplitOffRootCertPEM(r.RootChain)
	if err != nil {
		return nil, err
	}

	return &apiv1.CertResources{

		Certificate: r.Certificate,
		Key:         r.Key,
		Root:        root,
		Chain:       chain,
		RootChain:   r.RootChain,
		FullChain:   r.FullChain,
	}, nil
}

// if caID and/or crtID is "", infos will not be filtered on that value.
// Cannot filter for both
func (s *V1) GetCertificateInfos(caID string, crtID string, authz authtypes.AuthorizationInfo, pginfo *util.PaginationInfo) ([]apiv1.CertInfo, error) {

	s.logAction(authz, fmt.Sprintf("GetCertificateInfos %s %s", caID, crtID))

	if crtID != "" {
		crtID = util.GetDomainFQDNDot(crtID)
	}

	//TODO pagination

	fu := s.Service.Config.CA.Functions

	doms := authz.GetDomainsAllowed()

	if len(doms) <= 0 && !authz.CanListPublicData() {
		return nil, &common.UnauthzedError{Msg: "No authorization for any domains"}
	}

	if authz.CanListPublicData() {
		doms = nil
	}

	// we can interpret a len(doms) <= 0 now as "permit all"
	// note that this request just lists public info, no secrets

	r, err := fu.GetCertificateInfos(caID, crtID, doms, pginfo)
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

func (s *V1) GetCertificateInfo(caID string, crtID string, authz authtypes.AuthorizationInfo) (*apiv1.CertInfo, error) {

	s.logAction(authz, fmt.Sprintf("GetCertificateInfo %s %s", caID, crtID))

	crtID = util.GetDomainFQDNDot(crtID)

	fu := s.Service.Config.CA.Functions

	// TODO: do we need to implement SAN permissions check?
	err := authz.ChkAuthReadDomainPublic(crtID)
	if err != nil {
		return nil, err
	}

	cinfo, err := fu.GetCertificateInfo(caID, crtID)
	if err != nil {
		return nil, err
	}

	if cinfo == nil {
		return nil, &common.NotFoundError{RequestedResource: crtID}
	}

	res := &apiv1.CertInfo{}
	err = apiCertInfoFromCACertInfo(cinfo, res)
	if err != nil {
		return nil, err
	}

	return res, nil

}

func (s *V1) DeleteCertificatesAllCA(crtID string, authz authtypes.AuthorizationInfo) error {

	s.logAction(authz, fmt.Sprintf("DeleteCertificatesAllCA %s", crtID))

	crtID = util.GetDomainFQDNDot(crtID)

	fu := s.Service.Config.CA.Functions

	err := authz.ChkAuthWriteDomain(crtID)
	if err != nil {
		return err
	}

	return fu.DeleteCertificatesAllCA(crtID)

}

func apiCertInfoFromCACertInfo(source *types.CACertInfo, target *apiv1.CertInfo) error {
	cbatch, err := util.ParseCertificatePEM([]byte(source.CertPEM))
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
	target.NextRenewal = source.NextRenewalTime.Format(time.RFC3339)
	if source.LastAccessTime.IsZero() {
		target.LastAccess = ""
	} else {
		target.LastAccess = source.LastAccessTime.Format(time.RFC3339)
	}
	target.Valid = isValid(source)
	target.RenewCount = source.RenewCount
	target.AccessCount = source.AccessCount
	target.Wildcard = isWildcard(source.Domains)
	target.SubjectCN = cert.Subject.CommonName
	target.IssuerCN = cert.Issuer.CommonName
	target.Serial = cert.SerialNumber.String()
	target.ClaimedBy.Name = source.IssuedBy.Name
	target.ClaimedBy.EMail = source.IssuedBy.Email

	return nil
}

func isValid(cinfo *types.CACertInfo) bool {
	now := time.Now()
	return now.Before(cinfo.ValidEndTime) && now.After(cinfo.ValidStartTime)
}

func isWildcard(domains []string) bool {
	if len(domains) <= 0 {
		return false
	}
	return util.IsWildcard(domains[0])
}
