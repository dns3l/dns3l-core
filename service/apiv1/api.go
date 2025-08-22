package apiv1

import (
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/util"
)

type ServiceV1 interface {
	GetServerInfo() *ServerInfo
	GetDNSHandlers() []DNSHandlerInfo
	GetDNSRootzones() []DNSRootzoneInfo
	GetCAs() ([]*CAInfo, error)
	GetCA(caID string) (*CAInfo, error)
	ClaimCertificate(caID string, cinfo *CertClaimInfo, authz authtypes.AuthorizationInfo) error
	DeleteCertificate(caID, crtID string, authz authtypes.AuthorizationInfo) error
	GetCertificateResource(caID, crtID, obj string, authz authtypes.AuthorizationInfo) (string, string, error)
	GetAllCertResources(caID, crtID string, authz authtypes.AuthorizationInfo) (*CertResources, error)
	GetCertificateInfos(caID string, crtID string, authz authtypes.AuthorizationInfo, pginfo *util.PaginationInfo) ([]CertInfo, error)
	GetCertificateInfo(caID string, crtID string, authz authtypes.AuthorizationInfo) (*CertInfo, error)
	DeleteCertificatesAllCA(crtID string, authz authtypes.AuthorizationInfo) error
}
