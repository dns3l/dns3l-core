package apiv1

type ServiceV1 interface {
	GetServerInfo() *ServerInfo
	GetDNSHandlers() []DNSHandlerInfo
	GetDNSRootzones() []DNSRootzoneInfo
	GetCAs() []*CAInfo
	GetCA(caID string) (*CAInfo, error)
	ClaimCertificate(caID string, cinfo *CertClaimInfo) error
	DeleteCertificate(caID, crtID string) error
	GetCertificateResource(caID, crtID, obj string) (string, string, error)
	GetAllCertResources(caID, crtID string) (*CertResources, error)
}
