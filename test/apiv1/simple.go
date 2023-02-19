package apiv1

import (
	"fmt"

	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/service/apiv1"
	httptest "github.com/dns3l/dns3l-core/test/http"
)

func CreateKey(srv *service.Service, caid string, user string, name string, sans []string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequestJSON(
			"POST",
			fmt.Sprintf("/api/ca/%s/crt", caid),
			user,
			&apiv1.CertClaimInfo{
				Name:            name,
				Wildcard:        false,
				SubjectAltNames: sans,

				AutoDNS: nil,
				Hints:   nil,
			},
		))
}

func ListKeys(srv *service.Service, caid string, user string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("GET", fmt.Sprintf("/api/ca/%s/crt", caid), user, nil),
	)
}

func ListAllKeys(srv *service.Service, user string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("GET", "/api/crt", user, nil),
	)
}

func ListKeyAllCA(srv *service.Service, user string, key_id string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("GET", fmt.Sprintf("/api/crt/%s", key_id), user, nil),
	)
}

func GetKeyById(srv *service.Service, caid string, user string, key_id string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("GET", fmt.Sprintf("/api/ca/%s/crt/%s", caid, key_id), user, nil),
	)
}

func GetCertResources(srv *service.Service, caid string, user string, key_id string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("GET", fmt.Sprintf("/api/ca/%s/crt/%s/pem", caid, key_id), user, nil),
	)
}

func GetCertResource(srv *service.Service, caid string, user string, key_id string, resource string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("GET", fmt.Sprintf("/api/ca/%s/crt/%s/pem/%s", caid, key_id, resource), user, nil),
	)
}

func DeleteKeyById(srv *service.Service, caid string, user string, key_id string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("DELETE", fmt.Sprintf("/api/ca/%s/crt/%s", caid, key_id), user, nil),
	)
}

func DeleteKeyAllCAById(srv *service.Service, user string, key_id string) *httptest.HttpResult {
	return httptest.TestSendRequest(
		srv.GetRouter(), httptest.CreateNewRequest("DELETE", fmt.Sprintf("/api/crt/%s", key_id), user, nil),
	)
}
