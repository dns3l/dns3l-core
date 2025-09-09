package service

import (
	"github.com/dns3l/dns3l-core/context"
	"github.com/dns3l/dns3l-core/renew"
	"github.com/dns3l/dns3l-core/service/apiv1"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
)

type V1 struct {
	Service *Service
}

func (s *V1) GetServerInfo() *apiv1.ServerInfo {

	renewal, err := s.Service.Config.CA.Functions.GetLastRenewSummary()
	if err != nil {
		log.WithError(err).Error("Could not retrieve last renew summary from database.")
	}
	if renewal == nil {
		renewal = &renew.ServerInfoRenewal{}
	}

	return &apiv1.ServerInfo{
		Version: &apiv1.ServerInfoVersion{
			Daemon: context.ServiceVersion,
			API:    apiv1.Version,
		},
		Contact: &apiv1.ServerInfoContact{
			URL:   s.Service.Config.URL,
			EMail: s.Service.Config.AdminEMail,
		},
		Auth:    s.Service.Config.Auth.GetServerInfoAuth(),
		Renewal: renewal,
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

func (s *V1) logAction(authz authtypes.AuthorizationInfo, action string) {

	u := "anonymous"
	if authz != nil {
		userid := authz.GetUserInfo().GetPreferredName()
		if userid != "" {
			u = userid
		}
	}
	log.WithField("username", u).Infof("API call for %s", action)
}
