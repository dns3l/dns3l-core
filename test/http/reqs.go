package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
)

type HttpResult struct {
	ReturnCode int
	Body       *bytes.Buffer
}

func CreateNewRequest(method, url, stubuser string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	if stubuser != "" {
		req.Header.Add("X-Testuser", stubuser)
	}
	return req
}

func CreateNewRequestJSON(method, url, stubuser string, body interface{}) *http.Request {

	bodybytes, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	return CreateNewRequest(method, url, stubuser, bytes.NewReader(bodybytes))
}

func TestSendRequest(rt *mux.Router, req *http.Request) *HttpResult {
	rr := httptest.NewRecorder()
	rt.ServeHTTP(rr, req)
	return &HttpResult{ReturnCode: rr.Result().StatusCode, Body: rr.Body}
}

func AssertSuccess(desc string, result *HttpResult) string {

	if result.ReturnCode < 200 || result.ReturnCode > 299 {
		panic(fmt.Errorf("test run %s: HTTP return code was not as expected. Body: %s",
			desc, result.Body.String()))
	}

	return result.Body.String()

}

func AssertStatusCode(desc string, expected_rc int, result *HttpResult) string {

	if result.ReturnCode != expected_rc {
		panic(fmt.Errorf("test run %s: HTTP return code was not as expected. Expected: %d, Actual: %d, Body: %s",
			desc, expected_rc, result.ReturnCode, result.Body.String()))
	}

	return result.Body.String()

}
