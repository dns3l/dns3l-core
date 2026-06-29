package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestTokenFetcherFetch(t *testing.T) {
	var sawAuth bool
	var sawScope bool
	client := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/auth/token" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent() {
			t.Fatalf("unexpected user agent: %q", got)
		}
		user, pass, ok := r.BasicAuth()
		sawAuth = ok && user == "dns3l-api" && pass == "secret"
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		sawScope = r.Form.Get("scope") == "openid profile email groups offline_access audience:server:client_id:dns3ld"
		if r.Form.Get("grant_type") != "password" || r.Form.Get("username") != "alice" || r.Form.Get("password") != "pw" {
			t.Fatalf("unexpected form: %#v", r.Form)
		}
		body, _ := json.Marshal(map[string]string{"id_token": "token-123"})
		return testResponse(http.StatusOK, string(body)), nil
	})

	cfg := &RuntimeConfig{
		AuthURL:            "https://example.com/auth/token",
		ADUser:             "alice",
		ADPassword:         "pw",
		OIDCClientID:       "dns3l-api",
		OIDCClientSecret:   "secret",
		OIDCDaemonClientID: "dns3ld",
	}
	token, err := (&TokenFetcher{Client: client}).Fetch(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-123" {
		t.Fatalf("unexpected token %q", token)
	}
	if !sawAuth {
		t.Fatal("token request did not use expected basic auth")
	}
	if !sawScope {
		t.Fatal("token request did not use expected scope")
	}
}
