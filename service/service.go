package service

import (
	"net/http"

	"github.com/dta4/dns3l-go/service/apiv1"
	"github.com/gorilla/mux"
)

type Service struct {
	Config  *Config
	Socket  string
	NoRenew bool
}

func (s *Service) GetV1() *V1 {
	return &V1{s}
}

func (s *Service) Run() error {

	if s.NoRenew {
		log.Info("Disabling automatic cert renewal as per user request.")
	} else if s.Config.Renew != nil {
		err := s.startRenewer()
		if err != nil {
			return err
		}
		log.Info("Started automatic renewal job.")
	} else {
		log.Warn("Renewer is not active (renew section is missing in config). " +
			"Certificates might become expired without warning.")
	}

	r := mux.NewRouter().StrictSlash(true)

	err := s.Config.Auth.Init()
	if err != nil {
		return err
	}

	v1hdlr := &apiv1.RestV1Handler{
		Service: s.GetV1(),
		Auth:    s.Config.Auth,
	}
	v1hdlr.RegisterHandle(r.PathPrefix("/api/v1").Subrouter())
	v1hdlr.RegisterHandle(r.PathPrefix("/api").Subrouter())

	err = v1hdlr.Init()
	if err != nil {
		return err
	}

	log.Info("Service starting...")

	return http.ListenAndServe(s.Socket, r)

}

func (s *Service) startRenewer() error {
	r := &Renewer{
		Service: s,
		Config:  s.Config.Renew,
	}
	err := r.Init()
	if err != nil {
		return err
	}
	return r.StartAsync()
}
