package cli

import (
	"context"
	"net/http"
	"testing"
)

func TestClientFetchesTokenAndCallsAPI(t *testing.T) {
	var tokenCalled bool
	var apiCalled bool
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/auth/token":
			tokenCalled = true
			return testResponse(http.StatusOK, `{"id_token":"oidc-token"}`), nil
		case "/api/v1/crt":
			apiCalled = true
			if got := r.Header.Get("User-Agent"); got != userAgent() {
				t.Fatalf("unexpected user agent: %q", got)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer oidc-token" {
				t.Fatalf("unexpected Authorization header: %q", got)
			}
			return testResponse(http.StatusOK, `[]`), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		return testResponse(http.StatusNotFound, ""), nil
	})

	cfg, err := ResolveConfig(FlagOptions{
		Server:           "https://example.com/api/v1",
		ADUser:           "alice",
		ADPassword:       "pw",
		OIDCClientID:     "dns3l-api",
		OIDCClientSecret: "secret",
	}, ChangedFlags{
		"server":             true,
		"ad-user":            true,
		"ad-password":        true,
		"oidc-client-id":     true,
		"oidc-client-secret": true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(cfg)
	client.HTTPClient = httpClient
	client.TokenFetcher.Client = httpClient
	if _, err := client.Do(context.Background(), http.MethodGet, "/crt", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !tokenCalled || !apiCalled {
		t.Fatalf("expected token and API calls, token=%v api=%v", tokenCalled, apiCalled)
	}
}

func TestClientNoAuth(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})

	cfg := &RuntimeConfig{APIBaseURL: "https://example.com", NoAuth: true}
	client := NewClient(cfg)
	client.HTTPClient = httpClient
	if _, err := client.Do(context.Background(), http.MethodGet, "/", nil, nil); err != nil {
		t.Fatal(err)
	}
}
