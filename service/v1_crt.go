package service

import (
	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/service/apiv1"
)

func (s *V1) ClaimCertificate(caID string, cinfo *apiv1.CertClaimInfo) error {
	fu := s.Service.Config.CA.Functions

	//TODO: Autodns here

	return fu.ClaimCertificate(caID, &types.CertificateClaimInfo{
		Name:            cinfo.Name,
		SubjectAltNames: cinfo.SubjectAltNames,
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
