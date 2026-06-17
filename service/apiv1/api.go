package apiv1

import (
	api "github.com/dns3l/dns3l-core/api/v1"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/util"
)

type ServiceV1 interface {
	GetServerInfo() *api.ServerInfo
	GetDNSHandlers() []api.DNSHandlerInfo
	GetDNSRootzones() []api.DNSRootzoneInfo
	GetCAs() ([]*api.CAInfo, error)
	GetCA(caID string) (*api.CAInfo, error)
	ClaimCertificate(caID string, cinfo *api.CertClaimInfo, authz authtypes.AuthorizationInfo) error
	DeleteCertificate(caID, crtID string, authz authtypes.AuthorizationInfo) error
	GetCertificateResource(caID, crtID, obj string, authz authtypes.AuthorizationInfo) (string, string, error)
	GetAllCertResources(caID, crtID string, authz authtypes.AuthorizationInfo) (*api.CertResources, error)
	GetCertificateInfos(caID string, crtID string, authz authtypes.AuthorizationInfo, pginfo *util.PaginationInfo) ([]api.CertInfo, error)
	GetCertificateInfo(caID string, crtID string, authz authtypes.AuthorizationInfo) (*api.CertInfo, error)
	DeleteCertificatesAllCA(crtID string, authz authtypes.AuthorizationInfo) error
}
