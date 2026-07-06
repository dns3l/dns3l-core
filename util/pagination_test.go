package util

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoPagination(t *testing.T) {

	r := newTestReq(t, "https://foo.bar/baz")
	pag := PaginationInfoFromRequest(r)
	assert.Nil(t, pag)

	pag = &PaginationInfo{Limit: 0, Offset: 0, TotalCount: 12}
	assert.Empty(t, pag.MakeSQL())

}

func TestPaginationLimit(t *testing.T) {

	r := newTestReq(t, "https://foo.bar/baz?limit=15")
	pag := PaginationInfoFromRequest(r)
	assert.NotNil(t, pag)
	assert.Equal(t, " LIMIT 15", pag.MakeSQL())
	pag.TotalCount = 42
	s := newTestResp()
	pag.SetHTTPHeaders(s)
	assert.Equal(t, "15", s.Header().Get("Page-Limit"))
	assert.Empty(t, s.Header().Get("Page-Offset"))
	assert.Equal(t, "42", s.Header().Get("Total-Count"))

}

func TestPaginationLimitOffset(t *testing.T) {

	r := newTestReq(t, "https://foo.bar/baz?limit=15&offset=30")
	pag := PaginationInfoFromRequest(r)
	assert.NotNil(t, pag)
	assert.Equal(t, " LIMIT 30, 15", pag.MakeSQL())
	pag.TotalCount = 43
	s := newTestResp()
	pag.SetHTTPHeaders(s)
	assert.Equal(t, "15", s.Header().Get("Page-Limit"))
	assert.Equal(t, "30", s.Header().Get("Page-Offset"))
	assert.Equal(t, "43", s.Header().Get("Total-Count"))

}

func newTestReq(t *testing.T, rawUrl string) *http.Request {
	r, err := url.Parse(rawUrl)
	assert.NoError(t, err)
	return &http.Request{URL: r}
}

type TestResponseWriter struct {
	TestHeader http.Header
}

// Header implements [http.ResponseWriter].
func (t *TestResponseWriter) Header() http.Header {
	return t.TestHeader
}

// Write implements [http.ResponseWriter].
func (t *TestResponseWriter) Write([]byte) (int, error) {
	panic("unimplemented")
}

// WriteHeader implements [http.ResponseWriter].
func (t *TestResponseWriter) WriteHeader(statusCode int) {
	panic("unimplemented")
}

func newTestResp() http.ResponseWriter {
	return &TestResponseWriter{
		TestHeader: make(http.Header),
	}
}
