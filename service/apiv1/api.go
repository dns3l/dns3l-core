package apiv1

import (
	"github.com/dns3l/dns3l-core/service/auth"
	"github.com/dns3l/dns3l-core/util"
)

type ServiceV1 interface {
	GetServerInfo() *ServerInfo
	GetDNSHandlers() []DNSHandlerInfo
	GetDNSRootzones() []DNSRootzoneInfo
	GetCAs() ([]*CAInfo, error)
	GetCA(caID string) (*CAInfo, error)
	ClaimCertificate(caID string, cinfo *CertClaimInfo, authz auth.AuthorizationInfo) error
	DeleteCertificate(caID, crtID string, authz auth.AuthorizationInfo) error
	GetCertificateResource(caID, crtID, obj string, authz auth.AuthorizationInfo) (string, string, error)
	GetAllCertResources(caID, crtID string, authz auth.AuthorizationInfo) (*CertResources, error)
	GetCertificateInfos(caID string, crtID string, authz auth.AuthorizationInfo, pginfo *util.PaginationInfo) ([]CertInfo, error)
	GetCertificateInfo(caID string, crtID string, authz auth.AuthorizationInfo) (*CertInfo, error)
	DeleteCertificatesAllCA(crtID string, authz auth.AuthorizationInfo) error
}
