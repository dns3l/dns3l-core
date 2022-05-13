package service

import (
	"github.com/dta4/dns3l-go/context"
	"github.com/dta4/dns3l-go/service/apiv1"
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
			URL: "https://dns3l.example.com/ <TODO where does this come from?>",
			EMail: []string{
				"leonhard.nobach@telekom.de <TODO where does this come from?>",
				"andreas.schulze02@telekom.de <TODO where does this come from?>",
			},
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
