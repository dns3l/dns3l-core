package apiv1

import (
	"fmt"

	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/service/apiv1"
	httptest "github.com/dns3l/dns3l-core/test/http"
)

func CreateKey(srv *service.Service, user string, name string, sans []string) {
	httptest.AssertSuccess(
		httptest.TestSendRequest(
			srv.GetRouter(), httptest.CreateNewRequestJSON(
				"POST",
				"/api/ca/bogus/crt",
				user,
				&apiv1.CertClaimInfo{
					Name:            name,
					Wildcard:        false,
					SubjectAltNames: sans,

					AutoDNS: nil,
					Hints:   nil,
				},
			)))

}

func ListKeys(srv *service.Service, user string) string {
	return httptest.AssertSuccess(
		httptest.TestSendRequest(
			srv.GetRouter(), httptest.CreateNewRequest("GET", "/api/ca/bogus/crt", user, nil),
		))

}

func GetKeyById(srv *service.Service, user string, key_id string) string {
	return httptest.AssertSuccess(
		httptest.TestSendRequest(
			srv.GetRouter(), httptest.CreateNewRequest("GET", fmt.Sprintf("/api/ca/bogus/crt/%s", key_id), user, nil),
		))

}

func DeleteKeyById(srv *service.Service, user string, key_id string) string {
	return httptest.AssertSuccess(
		httptest.TestSendRequest(
			srv.GetRouter(), httptest.CreateNewRequest("DELETE", fmt.Sprintf("/api/ca/bogus/crt/%s", key_id), user, nil),
		))

}
