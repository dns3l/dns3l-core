package apiv1

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

var Version = "1.0" //this is the API version, not the one of the daemon

type RestV1Handler struct {
	Service ServiceV1
}

type ErrorMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (hdlr *RestV1Handler) Handle(r *mux.Router) {

	r.NotFoundHandler = http.HandlerFunc(hdlr.NotFound)
	r.HandleFunc("/info", hdlr.GetServerInfo)
	r.HandleFunc("/dns", hdlr.GetDNSInfo)
	r.HandleFunc("/dns/rtzn", hdlr.GetDNSRootzones)
	r.HandleFunc("/ca", hdlr.GetCAs)
	r.HandleFunc("/ca/{id:[A-Za-z0-9_-]+}", hdlr.GetCA)
}

func (hdlr *RestV1Handler) NotFound(w http.ResponseWriter, r *http.Request) {
	httpError(w, 404, "Resource not found")
}

func (hdlr *RestV1Handler) GetServerInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(hdlr.Service.GetServerInfo())
}

func (hdlr *RestV1Handler) GetDNSInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(hdlr.Service.GetDNSHandlers())
}

func (hdlr *RestV1Handler) GetDNSRootzones(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(hdlr.Service.GetDNSRootzones())
}

func (hdlr *RestV1Handler) GetCAs(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(hdlr.Service.GetCAs())
}

func (hdlr *RestV1Handler) GetCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	vars := mux.Vars(r)
	id, idSet := vars["id"]
	if !idSet {
		httpError(w, 500, "'id' not set")
		return
	}

	ca, err := hdlr.Service.GetCA(id)
	if err != nil {
		httpError(w, 404, err.Error())
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(ca)
}

func httpError(w http.ResponseWriter, sc int, message string) {
	w.WriteHeader(sc)
	json.NewEncoder(w).Encode(&ErrorMsg{
		Code:    sc,
		Message: message,
	})
}

/*
  /info:
  * /dns:
  * /dns/rtzn:
  * /ca:
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
