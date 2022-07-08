package apiv1

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

var Version = "1.0" //this is the API version, not the one of the daemon

type RestV1Handler struct {
	Service   ServiceV1
	Validator Validator
}

type ErrorMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (hdlr *RestV1Handler) Init(r *mux.Router) error {

	r.NotFoundHandler = http.HandlerFunc(hdlr.NotFound)
	r.HandleFunc("/info", hdlr.GetServerInfo)
	r.HandleFunc("/dns", hdlr.GetDNSInfo)
	r.HandleFunc("/dns/rtzn", hdlr.GetDNSRootzones)
	r.HandleFunc("/ca", hdlr.GetCAs)
	r.HandleFunc("/ca/{id:[A-Za-z0-9_-]+}", hdlr.GetCA)
	r.HandleFunc("/ca/{id:[A-Za-z0-9_-]+}/crt", hdlr.HandleCAAnonCert)
	r.HandleFunc("/ca/{caID:[A-Za-z0-9_-]+}/crt/{crtID:\\*?[A-Za-z0-9\\._-]+}", hdlr.HandleCANamedCert)
	r.HandleFunc("/ca/{caID:[A-Za-z0-9_-]+}/crt/{crtID:\\*?[A-Za-z0-9\\._-]+}/pem", hdlr.HandleCertObjs)
	r.HandleFunc("/ca/{caID:[A-Za-z0-9_-]+}/crt/{crtID:\\*?[A-Za-z0-9\\._-]+}/pem/{obj:[a-z_-]+}",
		hdlr.HandleNamedCertObj)

	return hdlr.Validator.Init()

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

func (hdlr *RestV1Handler) HandleCAAnonCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	vars := mux.Vars(r)
	caID, idSet := vars["id"]
	if !idSet {
		httpError(w, 500, "'caID' not set")
		return
	}

	if r.Method == http.MethodPost {
		//Claim Cert
		cinfo := &CertClaimInfo{}
		err := json.NewDecoder(r.Body).Decode(&cinfo)
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}

		err = hdlr.Validator.ValidateAPIStruct(cinfo)
		if err != nil {
			httpError(w, 400, err.Error())
			return
		}

		err = hdlr.Service.ClaimCertificate(caID, cinfo)
		if err != nil {
			httpError(w, 500, err.Error())
			return
		}
	} else if r.Method == http.MethodGet {
		//Get info of all CA's certs
		httpError(w, 500, "Not yet implemented")
		return
	} else {
		httpError(w, 500, "Wrong method")
		return
	}

	w.WriteHeader(200)
}

func (hdlr *RestV1Handler) HandleCANamedCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	vars := mux.Vars(r)
	caID, idSet := vars["caID"]
	if !idSet {
		httpError(w, 500, "'caID' not set")
		return
	}
	crtID, idSet := vars["crtID"]
	if !idSet {
		httpError(w, 500, "'crtID' not set")
		return
	}

	if r.Method == http.MethodDelete {
		//Delete cert

		err := hdlr.Service.DeleteCertificate(caID, crtID)
		if err != nil {
			httpError(w, 500, err.Error())
			return
		}
	} else if r.Method == http.MethodGet {
		httpError(w, 500, "Not yet implemented")
		return
	} else {
		httpError(w, 500, "Wrong method")
		return
	}

	w.WriteHeader(200)
}

func (hdlr *RestV1Handler) HandleCertObjs(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	vars := mux.Vars(r)
	caID, idSet := vars["caID"]
	if !idSet {
		httpError(w, 500, "'caID' not set")
		return
	}
	crtID, idSet := vars["crtID"]
	if !idSet {
		httpError(w, 500, "'crtID' not set")
		return
	}

	if r.Method == http.MethodGet {
		//Get all cert PEM infos

		obj, err := hdlr.Service.GetAllCertResources(caID, crtID)
		if err != nil {
			httpError(w, 500, err.Error())
			return
		}

		w.WriteHeader(200)

		err = json.NewEncoder(w).Encode(obj)
		if err != nil {
			log.WithError(err).Error("Error while decoding")
			return
		}
		return

	}
	httpError(w, 500, "Wrong method")
}

func (hdlr *RestV1Handler) HandleNamedCertObj(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	caID, set := vars["caID"]
	if !set {
		w.Header().Add("Content-Type", "application/json")
		httpError(w, 500, "'caID' not set")
		return
	}
	crtID, set := vars["crtID"]
	if !set {
		w.Header().Add("Content-Type", "application/json")
		httpError(w, 500, "'crtID' not set")
		return
	}

	obj, set := vars["obj"]
	if !set {
		w.Header().Add("Content-Type", "application/json")
		httpError(w, 500, "'obj' not set")
		return
	}

	if r.Method == http.MethodGet {

		res, ctype, err := hdlr.Service.GetCertificateResource(caID, crtID, obj)
		if err != nil {
			w.Header().Add("Content-Type", "application/json")
			httpError(w, 500, err.Error())
			return
		}

		w.Header().Add("Content-Type", ctype)
		w.WriteHeader(200)
		w.Write([]byte(res))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	httpError(w, 500, "Wrong method")

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
