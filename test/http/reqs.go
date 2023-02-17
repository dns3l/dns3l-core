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

func TestSendRequest(rt *mux.Router, req *http.Request) (int, *bytes.Buffer) {
	rr := httptest.NewRecorder()
	rt.ServeHTTP(rr, req)
	return rr.Result().StatusCode, rr.Body
}

func AssertSuccess(rc int, buf *bytes.Buffer) string {

	if rc < 200 || rc > 299 {
		panic(fmt.Errorf("HTTP return code was not as expected. Body: %s", buf.String()))
	}

	return buf.String()

}

func AssertStatusCode(expected_rc int, rc int, buf *bytes.Buffer) string {

	if rc != expected_rc {
		panic(fmt.Errorf("HTTP return code was not as expected. Expected: %d, Actual: %d, Body: %s", expected_rc, rc, buf.String()))
	}

	return buf.String()

}
