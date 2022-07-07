package service

import (
	"net/http"

	"github.com/dta4/dns3l-go/service/apiv1"
	"github.com/gorilla/mux"
)

type Service struct {
	Config *Config
	Socket string
}

func (s *Service) GetV1() *V1 {
	return &V1{s}
}

func (s *Service) Run() error {

	log.Printf("Service is running...")

	r := mux.NewRouter().StrictSlash(true)

	v1hdlr := &apiv1.RestV1Handler{
		Service: s.GetV1(),
	}
	v1hdlr.Handle(r.PathPrefix("/api/v1").Subrouter())

	return http.ListenAndServe(s.Socket, r)

}
