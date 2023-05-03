package service

import (
	"context"
	"net/http"

	"github.com/dns3l/dns3l-core/service/apiv1"
	"github.com/gorilla/mux"
)

type Service struct {
	Config  *Config
	Socket  string
	NoRenew bool

	server  *http.Server
	router  *mux.Router
	running bool
	runerr  error
}

func (s *Service) GetV1() *V1 {
	return &V1{s}
}

func (s *Service) Run() error {

	err := s.prepare()
	if err != nil {
		return err
	}

	log.Info("Service starting...")

	return s.runRaw(s.router)
}

func (s *Service) RunAsync() error {

	err := s.prepare()
	if err != nil {
		return err
	}

	go func() {
		err := s.runRaw(s.router)
		if err != nil {
			if err != http.ErrServerClosed {
				log.WithError(err).Error("Error occurred while running dns3ld service")
			} else {
				log.Info("HTTP server closed")
			}
		}
	}()

	return nil

}

func (s *Service) Stop() error {
	return s.server.Shutdown(context.Background())
}

func (s *Service) runRaw(r *mux.Router) error {
	s.running = true
	s.server = &http.Server{Addr: s.Socket, Handler: r}
	err := s.server.ListenAndServe()
	s.runerr = err
	s.running = false
	return err
}

func (s *Service) prepare() error {

	db := s.Config.DB

	err := db.Init()
	if err != nil {
		return err
	}

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

	err = s.Config.Auth.Provider.Init()
	if err != nil {
		return err
	}

	v1hdlr := &apiv1.RestV1Handler{
		Service: s.GetV1(),
		Auth:    s.Config.Auth.Provider,
	}
	v1hdlr.RegisterHandle(r.PathPrefix("/api/v1").Subrouter())
	v1hdlr.RegisterHandle(r.PathPrefix("/api").Subrouter())

	err = v1hdlr.Init()
	if err != nil {
		return err
	}

	s.router = r

	return nil
}

func (s *Service) GetRouter() *mux.Router {
	return s.router
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
