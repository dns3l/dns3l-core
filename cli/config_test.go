package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server: https://from-config.example/api/v1
ad_user: config-user
ad_password: config-pass
oidc_client_id: config-client
oidc_client_secret: config-secret
oidc_daemon_client_id: config-daemon
timeout: 3s
timeout_claim: 4m
`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNS3L_SERVER", "https://from-env.example/api/v1")
	t.Setenv("DNS3L_AD_USER", "env-user")
	t.Setenv("DNS3L_AD_PASS", "env-pass")
	t.Setenv("DNS3L_OIDC_CLIENT_ID", "env-client")
	t.Setenv("DNS3L_OIDC_CLIENT_SECRET", "env-secret")
	t.Setenv("DNS3L_TIMEOUT_CLAIM", "5m")

	cfg, err := ResolveConfig(FlagOptions{
		ConfigPath:       cfgPath,
		Server:           "https://from-cli.example/api/v1",
		ADPassword:       "cli-pass",
		OIDCClientSecret: "cli-secret",
		TimeoutClaim:     6 * time.Minute,
	}, ChangedFlags{
		"config":             true,
		"server":             true,
		"ad-password":        true,
		"oidc-client-secret": true,
		"timeout-claim":      true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://from-cli.example/api/v1" {
		t.Fatalf("server precedence failed: %q", cfg.Server)
	}
	if cfg.ADUser != "env-user" {
		t.Fatalf("env should override config for ad user, got %q", cfg.ADUser)
	}
	if cfg.ADPassword != "cli-pass" {
		t.Fatalf("cli should override env for password, got %q", cfg.ADPassword)
	}
	if cfg.OIDCClientID != "env-client" {
		t.Fatalf("env should override config for client id, got %q", cfg.OIDCClientID)
	}
	if cfg.OIDCClientSecret != "cli-secret" {
		t.Fatalf("cli should override env for client secret, got %q", cfg.OIDCClientSecret)
	}
	if cfg.OIDCDaemonClientID != "config-daemon" {
		t.Fatalf("config daemon client id not used, got %q", cfg.OIDCDaemonClientID)
	}
	if cfg.Timeout != 3*time.Second {
		t.Fatalf("timeout not parsed from config, got %s", cfg.Timeout)
	}
	if cfg.TimeoutClaim != 6*time.Minute {
		t.Fatalf("timeout claim precedence failed, got %s", cfg.TimeoutClaim)
	}
	if cfg.AuthURL != "https://from-cli.example/auth/token" {
		t.Fatalf("auth URL mismatch: %q", cfg.AuthURL)
	}
}

func TestResolveConfigDefaultTimeouts(t *testing.T) {
	cfg, err := ResolveConfig(FlagOptions{
		Server: "https://example.com/api/v1",
		NoAuth: true,
	}, ChangedFlags{"server": true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Fatalf("unexpected default timeout: %s", cfg.Timeout)
	}
	if cfg.TimeoutClaim != DefaultClaimTimeout {
		t.Fatalf("unexpected default claim timeout: %s", cfg.TimeoutClaim)
	}
}

func TestResolveConfigRequiresAuthFields(t *testing.T) {
	_, err := ResolveConfig(FlagOptions{
		Server: "https://example.com/api/v1",
	}, ChangedFlags{"server": true}, true)
	if err == nil {
		t.Fatal("expected missing auth fields error")
	}
}

func TestResolveConfigNoAuthSkipsAuthFields(t *testing.T) {
	cfg, err := ResolveConfig(FlagOptions{
		Server: "https://example.com/api/v1",
		NoAuth: true,
	}, ChangedFlags{"server": true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NoAuth {
		t.Fatal("expected no-auth to be set")
	}
}
