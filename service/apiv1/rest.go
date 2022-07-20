package apiv1

import (
	"encoding/json"
	"net/http"

	"github.com/dta4/dns3l-go/common"
	"github.com/dta4/dns3l-go/service/auth"
	"github.com/gorilla/mux"
)

var Version = "1.0" //this is the API version, not the one of the daemon

type RestV1Handler struct {
	Service   ServiceV1
	Validator Validator

	//Must be inited externally PRIOR to Rest API execution
	Auth auth.RESTAPIAuthProvider
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
	r.HandleFunc("/crt", hdlr.HandleAnonCert)
	r.HandleFunc("/crt/{crtID:\\*?[A-Za-z0-9\\._-]+}", hdlr.HandleNamedCert)

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

	authz, err := hdlr.Auth.AuthnGetAuthzInfo(r)
	if err != nil {
		httpErrorFromErr(w, err)
		return
	}

	if r.Method == http.MethodGet {
		//Get info of all CA's certs
		certInfos, err := hdlr.Service.GetCertificateInfos(caID, "", authz, nil)
		//TODO pagination
		if err != nil {
			httpError(w, 404, err.Error()) //TODO detect Not Found error
			return
		}

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(certInfos)
		return
	} else if r.Method == http.MethodPost {
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

		err = hdlr.Service.ClaimCertificate(caID, cinfo, authz)
		if err != nil {
			httpError(w, 500, err.Error())
			return
		}
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

	authz, err := hdlr.Auth.AuthnGetAuthzInfo(r)
	if err != nil {
		httpErrorFromErr(w, err)
		return
	}

	if r.Method == http.MethodDelete {
		//Delete cert

		err := hdlr.Service.DeleteCertificate(caID, crtID, authz)
		if err != nil {
			httpErrorFromErr(w, err)
			return
		}
	} else if r.Method == http.MethodGet {
		//Get info of specific cert
		certInfo, err := hdlr.Service.GetCertificateInfo(caID, crtID, authz)
		if err != nil {
			httpErrorFromErr(w, err)
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(certInfo)
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

	authz, err := hdlr.Auth.AuthnGetAuthzInfo(r)
	if err != nil {
		httpErrorFromErr(w, err)
		return
	}

	if r.Method == http.MethodGet {
		//Get all cert PEM infos

		obj, err := hdlr.Service.GetAllCertResources(caID, crtID, authz)
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

	authz, err := hdlr.Auth.AuthnGetAuthzInfo(r)
	if err != nil {
		httpErrorFromErr(w, err)
		return
	}

	if r.Method == http.MethodGet {

		res, ctype, err := hdlr.Service.GetCertificateResource(caID, crtID, obj, authz)
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

func (hdlr *RestV1Handler) HandleAnonCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	authz, err := hdlr.Auth.AuthnGetAuthzInfo(r)
	if err != nil {
		httpErrorFromErr(w, err)
		return
	}

	if r.Method == http.MethodGet {
		//Get all certs
		certInfos, err := hdlr.Service.GetCertificateInfos("", "", authz, nil)
		//TODO pagination
		if err != nil {
			httpErrorFromErr(w, err)
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(certInfos)
		return
	} else {
		httpError(w, 500, "Wrong method")
		return
	}

}

func (hdlr *RestV1Handler) HandleNamedCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	vars := mux.Vars(r)
	crtID, idSet := vars["crtID"]
	if !idSet {
		httpError(w, 500, "'crtID' not set")
		return
	}

	authz, err := hdlr.Auth.AuthnGetAuthzInfo(r)
	if err != nil {
		httpErrorFromErr(w, err)
		return
	}

	if r.Method == http.MethodGet {
		//Get info of specific cert
		certInfos, err := hdlr.Service.GetCertificateInfos("", crtID, authz, nil)
		//TODO pagination
		if err != nil {
			httpErrorFromErr(w, err)
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(certInfos)
		return
	} else if r.Method == http.MethodDelete {
		//Delete info of specific cert
		err := hdlr.Service.DeleteCertificatesAllCA(crtID, authz)
		if err != nil {
			httpErrorFromErr(w, err)
			return
		}
		w.WriteHeader(200)
		return
	} else {
		httpError(w, 500, "Wrong method")
		return
	}

}

func httpErrorFromErr(w http.ResponseWriter, e error) {

	switch e.(type) {
	case *common.NotFoundError:
		httpError(w, 404, e.Error())
	default:
		httpError(w, 500, e.Error())
	}

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
