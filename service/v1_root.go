package service

import (
	"github.com/dta4/dns3l-go/context"
	"github.com/dta4/dns3l-go/service/apiv1"
	"github.com/dta4/dns3l-go/service/auth"
)

type V1 struct {
	Service *Service
}

func (s *V1) GetServerInfo() *apiv1.ServerInfo {
	return &apiv1.ServerInfo{
		Version: &apiv1.ServerInfoVersion{
			Daemon: context.Version,
			API:    apiv1.Version,
		},
		Contact: &apiv1.ServerInfoContact{
			URL:   s.Service.Config.URL,
			EMail: s.Service.Config.AdminEMail,
		},
	}
}

/*
  /info:
  /dns:
  /dns/rtzn:
  /ca:
  /ca/{caId}:
  /ca/{caId}/crt:
  /ca/{caId}/csr:
  /ca/{caId}/crt/{crtName}:
  /ca/{caId}/crt/{crtName}/pem:
  /ca/{caId}/crt/{crtName}/pem/crt:
  /ca/{caId}/crt/{crtName}/pem/key:
  /ca/{caId}/crt/{crtName}/pem/fullchain:
  /crt:
  /crt/{crtName}:
*/

func (s *V1) logAction(authz *auth.AuthorizationInfo, action string) {

	u := "anonymous"
	if authz != nil && authz.Username != "" {
		u = authz.Username
	}
	log.WithField("username", u).Infof("API call for %s", action)
}
