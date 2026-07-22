package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
	appctx "github.com/dns3l/dns3l-core/context"
	"github.com/spf13/cobra"
)

func TestRootCommandInfoJSON(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/info" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return testResponse(http.StatusOK, `{"version":{"daemon":"1.2.3","api":"1.2"}}`), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "--json", "info"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"version":{"daemon":"1.2.3","api":"1.2"}}` {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRootCommandHelpDocumentsConfigAndEnvironment(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, http.DefaultClient)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	help := out.String()
	expected := []string{
		"version " + appctx.ServiceVersion + " (implemented API version " + ImplementedAPIVersion + ")",
		"Example config.yaml:",
		"server: https://my-server.com/api/v1",
		"ad_user: alice@example.com",
		"oidc_client_id: dns3l-api",
		"Config keys and environment variables are shown inline",
		"YAML config path (env: DNS3L_CONFIG)",
		"config: server (aliases: instance, dns3l_instance)",
		"env: DNS3L_SERVER (alias: DNS3L_INSTANCE)",
		"DNS3L_AD_USER",
		"config: ad_password (alias: ad_pass)",
		"env: DNS3L_AD_PASSWORD (alias: DNS3L_AD_PASS)",
		"config: oidc_client_id (alias: client_id)",
		"env: DNS3L_OIDC_CLIENT_ID (aliases: OIDC_CLIENT_ID, CLIENT_ID)",
		"config: oidc_client_secret (alias: client_secret)",
		"DNS3L_OIDC_CLIENT_SECRET",
		"DNS3L_ID_TOKEN (alias: DNS3L_TOKEN)",
		"DNS3L_API_KEY",
		"DNS3L_TIMEOUT",
		"DNS3L_TIMEOUT_CLAIM",
	}
	for _, want := range expected {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q:\n%s", want, help)
		}
	}
	unexpected := []string{
		"Config aliases also accepted:",
		"Environment variables:",
	}
	for _, unwanted := range unexpected {
		if strings.Contains(help, unwanted) {
			t.Fatalf("help output still contains old section %q:\n%s", unwanted, help)
		}
	}
}

func TestRootCommandVersionPrintsCLIAndAPIVersion(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, http.DefaultClient)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	want := "dns3lcli version: " + appctx.ServiceVersion + "\nAPI version: " + ImplementedAPIVersion + "\n"
	if out.String() != want {
		t.Fatalf("unexpected output:\nwant %q\ngot  %q", want, out.String())
	}
}

func TestRootCommandClaimBody(t *testing.T) {
	var claim apiv1.CertClaimInfo
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/auth/token":
			return testResponse(http.StatusOK, `{"id_token":"oidc-token"}`), nil
		case "/api/v1/ca/les/crt":
			if got := r.Header.Get("Authorization"); got != "Bearer oidc-token" {
				t.Fatalf("unexpected auth header: %q", got)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &claim); err != nil {
				t.Fatal(err)
			}
			return testResponse(http.StatusOK, ``), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return testResponse(http.StatusNotFound, ""), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{
		"--server", "https://example.com/api/v1",
		"--ad-user", "alice",
		"--ad-password", "pw",
		"--oidc-client-id", "dns3l-api",
		"--oidc-client-secret", "secret",
		"crt", "claim", "les", "test.example.com",
		"--wildcard",
		"--san", "alt.example.com",
		"--autodns-ipv4", "192.0.2.10",
		"--ttl", "30",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if claim.Name != "test.example.com" || !claim.Wildcard || claim.AutoDNS == nil || claim.AutoDNS.IPv4 != "192.0.2.10" {
		t.Fatalf("unexpected claim body: %#v", claim)
	}
	if len(claim.SubjectAltNames) != 1 || claim.SubjectAltNames[0] != "alt.example.com" {
		t.Fatalf("unexpected SANs: %#v", claim.SubjectAltNames)
	}
	if claim.Hints.TTL != 30 {
		t.Fatalf("unexpected TTL: %d", claim.Hints.TTL)
	}
	if !strings.Contains(out.String(), "certificate claim completed") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRootCommandClaimUsesClaimTimeout(t *testing.T) {
	var capturedTimeout time.Duration
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/auth/token":
			return testResponse(http.StatusOK, `{"id_token":"oidc-token"}`), nil
		case "/api/v1/ca/les/crt":
			return testResponse(http.StatusOK, ``), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return testResponse(http.StatusNotFound, ""), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommandWithFactory(&out, &errOut, func(cfg *RuntimeConfig) *Client {
		capturedTimeout = cfg.Timeout
		client := NewClient(cfg)
		client.HTTPClient = httpClient
		client.TokenFetcher.Client = httpClient
		return client
	})
	cmd.SetArgs([]string{
		"--server", "https://example.com/api/v1",
		"--ad-user", "alice",
		"--ad-password", "pw",
		"--oidc-client-id", "dns3l-api",
		"--oidc-client-secret", "secret",
		"--timeout", "2s",
		"--timeout-claim", "7m",
		"crt", "claim", "les", "test.example.com",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if capturedTimeout != 7*time.Minute {
		t.Fatalf("claim did not use claim timeout, got %s", capturedTimeout)
	}
}

func TestRootCommandListUsesRegularTimeout(t *testing.T) {
	var capturedTimeout time.Duration
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/crt" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return testResponse(http.StatusOK, `[]`), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommandWithFactory(&out, &errOut, func(cfg *RuntimeConfig) *Client {
		capturedTimeout = cfg.Timeout
		client := NewClient(cfg)
		client.HTTPClient = httpClient
		client.TokenFetcher.Client = httpClient
		return client
	})
	cmd.SetArgs([]string{
		"--server", "https://example.com/api/v1",
		"--timeout", "2s",
		"--timeout-claim", "7m",
		"crt", "list",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if capturedTimeout != 2*time.Second {
		t.Fatalf("non-claim command did not use regular timeout, got %s", capturedTimeout)
	}
}

func TestRootCommandListPagination(t *testing.T) {
	var capturedTimeout time.Duration
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/crt" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "5" {
			t.Fatalf("no pagination limit sent %s", r.URL.Path)
		}
		if r.URL.Query().Get("offset") != "10" {
			t.Fatalf("no pagination offset sent %s", r.URL.Path)
		}
		hdrs := make(http.Header)
		hdrs.Add("Page-Limit", "5")
		hdrs.Add("Page-Offset", "10")
		hdrs.Add("Total-Count", "123")
		return testResponseHdrs(http.StatusOK, `[]`, hdrs), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommandWithFactory(&out, &errOut, func(cfg *RuntimeConfig) *Client {
		capturedTimeout = cfg.Timeout
		client := NewClient(cfg)
		client.HTTPClient = httpClient
		client.TokenFetcher.Client = httpClient
		return client
	})
	cmd.SetArgs([]string{
		"--server", "https://example.com/api/v1",
		"--timeout", "2s",
		"--timeout-claim", "7m",
		"crt", "list", "--limit", "5", "--offset", "10",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if capturedTimeout != 2*time.Second {
		t.Fatalf("non-claim command did not use regular timeout, got %s", capturedTimeout)
	}
}

func TestPaginationInfo(t *testing.T) {
	hdrs := make(http.Header)
	hdrs.Add("Page-Limit", "5")
	hdrs.Add("Page-Offset", "10")
	hdrs.Add("Total-Count", "123")
	pinfo := paginationInfo(hdrs)
	if pinfo != "Showing element 11 - 15 of 123 elements" {
		t.Fatalf("paginationInfo was %s", pinfo)
	}

	if strToUint64_0("foo", "bar") != 0 {
		t.Fatalf("strToUint64_0 returned non-0 on illegal uint value")
	}
}

func TestRootCommandCRTListAnonymousWithoutAuthData(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/auth/token" {
			t.Fatal("did not expect token fetch for anonymous certificate list")
		}
		if r.URL.Path != "/api/v1/crt" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected Authorization header: %q", got)
		}
		return testResponse(http.StatusOK, `[]`), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "--json", "crt", "list"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `[]` {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRootCommandCRTListUsesProvidedToken(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/auth/token" {
			t.Fatal("did not expect token fetch when manual token is provided")
		}
		if got := r.Header.Get("Authorization"); got != "Bearer manual-token" {
			t.Fatalf("unexpected Authorization header: %q", got)
		}
		return testResponse(http.StatusOK, `[]`), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "--token", "manual-token", "--json", "crt", "list"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestRootCommandCRTGetJSONUnwrapsSingleAllCAResult(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/auth/token" {
			t.Fatal("did not expect token fetch for anonymous certificate get")
		}
		if r.URL.Path != "/api/v1/crt/test.example.com" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return testResponse(http.StatusOK, `[{"name":"test.example.com","valid":true}]`), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "--json", "crt", "get", "test.example.com"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"name":"test.example.com","valid":true}` {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRootCommandCRTGetEmptyAllCAResultIsError(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/crt/missing.example.com" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return testResponse(http.StatusOK, `[]`), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "--json", "crt", "get", "missing.example.com"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !strings.Contains(err.Error(), `certificate "missing.example.com" not found`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.String() != "" {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRootCommandPEMFullchainAnonymousWithoutAuthData(t *testing.T) {
	pemData := "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/auth/token" {
			t.Fatal("did not expect token fetch for anonymous certificate PEM")
		}
		if r.URL.Path != "/api/v1/ca/les/crt/test.example.com/pem/fullchain" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected Authorization header: %q", got)
		}
		return testResponse(http.StatusOK, pemData), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "crt", "pem", "les", "test.example.com", "--resource", "fullchain"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.String() != pemData {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRootCommandPEMKeyRequiresAuthData(t *testing.T) {
	httpClient := testHTTPClient(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("request should not be sent without auth data: %s", r.URL.Path)
		return testResponse(http.StatusInternalServerError, ""), nil
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := testRootCommand(&out, &errOut, httpClient)
	cmd.SetArgs([]string{"--server", "https://example.com/api/v1", "crt", "pem", "les", "test.example.com", "--resource", "key"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing auth data error")
	}
	if !strings.Contains(err.Error(), "missing required authentication setting") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testRootCommand(out, errOut io.Writer, httpClient *http.Client) *cobra.Command {
	return testRootCommandWithFactory(out, errOut, func(cfg *RuntimeConfig) *Client {
		client := NewClient(cfg)
		client.HTTPClient = httpClient
		client.TokenFetcher.Client = httpClient
		return client
	})
}

func testRootCommandWithFactory(out, errOut io.Writer, clientFactory func(*RuntimeConfig) *Client) *cobra.Command {
	f := &CommandFactory{
		Out:    out,
		ErrOut: errOut,
		opts: FlagOptions{
			ConfigPath:         DefaultConfigPath,
			OIDCDaemonClientID: DefaultDaemonOIDCClient,
			Timeout:            DefaultTimeout,
			TimeoutClaim:       DefaultClaimTimeout,
		},
	}
	f.Client = clientFactory
	return f.newRootCommand()
}
