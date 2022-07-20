package auth

import "net/http"

type RESTAPIAuthProvider interface {
	AuthnGetAuthzInfo(r *http.Request) (*AuthorizationInfo, error)
}
