package service

import (
	"errors"
	"time"

	cacommon "github.com/dta4/dns3l-go/ca/common"
	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/service/apiv1"
	"github.com/dta4/dns3l-go/util"
)

func (s *V1) ClaimCertificate(caID string, cinfo *apiv1.CertClaimInfo) error {
	fu := s.Service.Config.CA.Functions

	//TODO: Autodns here

	return fu.ClaimCertificate(caID, &types.CertificateClaimInfo{
		Name:    cinfo.Name,
		Domains: cinfo.SubjectAltNames,
	})

}

func (s *V1) DeleteCertificate(caID, crtID string) error {
	fu := s.Service.Config.CA.Functions

	return fu.DeleteCertificate(caID, crtID)

}

func (s *V1) GetCertificateResource(caID, crtID, obj string) (string, string, error) {
	fu := s.Service.Config.CA.Functions

	return fu.GetCertificateResource(crtID, caID, obj)
}

func (s *V1) GetAllCertResources(caID, crtID string) (*apiv1.CertResources, error) {
	fu := s.Service.Config.CA.Functions

	r, err := fu.GetCertificateResources(crtID, caID)
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
func (s *V1) GetCertificateInfos(caID string, crtID string) ([]apiv1.CertInfo, error) {

	//TODO pagination

	fu := s.Service.Config.CA.Functions

	r, err := fu.GetCertificateInfos(caID, crtID)
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

func (s *V1) GetCertificateInfo(caID string, crtID string) (*apiv1.CertInfo, error) {

	fu := s.Service.Config.CA.Functions

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
