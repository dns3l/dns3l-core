package apiv1

type ServiceV1 interface {
	GetServerInfo() *ServerInfo
	GetDNSHandlers() []DNSHandlerInfo
	GetDNSRootzones() []DNSRootzoneInfo
	GetCAs() []*CAInfo
	GetCA(caID string) (*CAInfo, error)
}
