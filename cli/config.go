package cli

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	DefaultConfigPath       = "config.yaml"
	DefaultDaemonOIDCClient = "dns3ld"
	DefaultTimeout          = 60 * time.Second
	DefaultClaimTimeout     = 10 * time.Minute
)

type RuntimeConfig struct {
	Server             string
	ADUser             string
	ADPassword         string
	OIDCClientID       string
	OIDCClientSecret   string
	OIDCDaemonClientID string
	Token              string
	APIKey             string
	NoAuth             bool
	JSON               bool
	Debug              bool
	Trace              bool
	Timeout            time.Duration
	TimeoutClaim       time.Duration

	APIBaseURL string
	AuthURL    string
}

type FlagOptions struct {
	ConfigPath         string
	Server             string
	ADUser             string
	ADPassword         string
	OIDCClientID       string
	OIDCClientSecret   string
	OIDCDaemonClientID string
	Token              string
	APIKey             string
	NoAuth             bool
	JSON               bool
	Debug              bool
	Trace              bool
	Timeout            time.Duration
	TimeoutClaim       time.Duration
}

type ChangedFlags map[string]bool

type fileConfig struct {
	Server             string `yaml:"server"`
	Instance           string `yaml:"instance"`
	DNS3LInstance      string `yaml:"dns3l_instance"`
	ADUser             string `yaml:"ad_user"`
	ADPassword         string `yaml:"ad_password"`
	ADPass             string `yaml:"ad_pass"`
	OIDCClientID       string `yaml:"oidc_client_id"`
	OIDCClientSecret   string `yaml:"oidc_client_secret"`
	OIDCDaemonClientID string `yaml:"oidc_daemon_client_id"`
	ClientID           string `yaml:"client_id"`
	ClientSecret       string `yaml:"client_secret"`
	Token              string `yaml:"token"`
	APIKey             string `yaml:"api_key"`
	Timeout            string `yaml:"timeout"`
	TimeoutClaim       string `yaml:"timeout_claim"`
}

func ResolveConfig(opts FlagOptions, changed ChangedFlags, requireAuth bool) (*RuntimeConfig, error) {
	cfgPath := DefaultConfigPath
	explicitConfig := false
	if env := strings.TrimSpace(os.Getenv("DNS3L_CONFIG")); env != "" {
		cfgPath = env
		explicitConfig = true
	}
	if changed["config"] {
		cfgPath = opts.ConfigPath
		explicitConfig = true
	}

	cfg := &RuntimeConfig{
		OIDCDaemonClientID: DefaultDaemonOIDCClient,
		Timeout:            DefaultTimeout,
		TimeoutClaim:       DefaultClaimTimeout,
	}

	if err := applyConfigFile(cfg, cfgPath, explicitConfig); err != nil {
		return nil, err
	}
	applyEnv(cfg)
	applyFlags(cfg, opts, changed)

	if cfg.OIDCDaemonClientID == "" {
		cfg.OIDCDaemonClientID = DefaultDaemonOIDCClient
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.TimeoutClaim <= 0 {
		cfg.TimeoutClaim = DefaultClaimTimeout
	}

	apiBase, authURL, err := normalizeServer(cfg.Server)
	if err != nil {
		return nil, err
	}
	cfg.APIBaseURL = apiBase
	cfg.AuthURL = authURL

	if requireAuth && !cfg.NoAuth && cfg.Token == "" && cfg.APIKey == "" {
		missing := missingAuthFields(cfg)
		if len(missing) > 0 {
			return nil, fmt.Errorf("missing required authentication setting(s): %s", strings.Join(missing, ", "))
		}
	}

	return cfg, nil
}

func applyConfigFile(cfg *RuntimeConfig, path string, explicit bool) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("config path must not be empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return nil
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	setIfNotEmpty(&cfg.Server, firstNonEmpty(fc.Server, fc.Instance, fc.DNS3LInstance))
	setIfNotEmpty(&cfg.ADUser, fc.ADUser)
	setIfNotEmpty(&cfg.ADPassword, firstNonEmpty(fc.ADPassword, fc.ADPass))
	setIfNotEmpty(&cfg.OIDCClientID, firstNonEmpty(fc.OIDCClientID, fc.ClientID))
	setIfNotEmpty(&cfg.OIDCClientSecret, firstNonEmpty(fc.OIDCClientSecret, fc.ClientSecret))
	setIfNotEmpty(&cfg.OIDCDaemonClientID, fc.OIDCDaemonClientID)
	setIfNotEmpty(&cfg.Token, fc.Token)
	setIfNotEmpty(&cfg.APIKey, fc.APIKey)
	if strings.TrimSpace(fc.Timeout) != "" {
		timeout, err := time.ParseDuration(fc.Timeout)
		if err != nil {
			return fmt.Errorf("parse config timeout: %w", err)
		}
		cfg.Timeout = timeout
	}
	if strings.TrimSpace(fc.TimeoutClaim) != "" {
		timeout, err := time.ParseDuration(fc.TimeoutClaim)
		if err != nil {
			return fmt.Errorf("parse config timeout_claim: %w", err)
		}
		cfg.TimeoutClaim = timeout
	}
	return nil
}

func applyEnv(cfg *RuntimeConfig) {
	setIfNotEmpty(&cfg.Server, firstNonEmptyEnv("DNS3L_SERVER", "DNS3L_INSTANCE"))
	setIfNotEmpty(&cfg.ADUser, os.Getenv("DNS3L_AD_USER"))
	setIfNotEmpty(&cfg.ADPassword, firstNonEmptyEnv("DNS3L_AD_PASSWORD", "DNS3L_AD_PASS"))
	setIfNotEmpty(&cfg.OIDCClientID, firstNonEmptyEnv("DNS3L_OIDC_CLIENT_ID", "OIDC_CLIENT_ID", "CLIENT_ID"))
	setIfNotEmpty(&cfg.OIDCClientSecret, firstNonEmptyEnv("DNS3L_OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET", "CLIENT_SECRET"))
	setIfNotEmpty(&cfg.OIDCDaemonClientID, firstNonEmptyEnv("DNS3L_OIDC_DAEMON_CLIENT_ID", "DAEMON_CLIENT_ID"))
	setIfNotEmpty(&cfg.Token, firstNonEmptyEnv("DNS3L_ID_TOKEN", "DNS3L_TOKEN"))
	setIfNotEmpty(&cfg.APIKey, os.Getenv("DNS3L_API_KEY"))
	if raw := strings.TrimSpace(os.Getenv("DNS3L_TIMEOUT")); raw != "" {
		if timeout, err := time.ParseDuration(raw); err == nil {
			cfg.Timeout = timeout
		}
	}
	if raw := strings.TrimSpace(os.Getenv("DNS3L_TIMEOUT_CLAIM")); raw != "" {
		if timeout, err := time.ParseDuration(raw); err == nil {
			cfg.TimeoutClaim = timeout
		}
	}
}

func applyFlags(cfg *RuntimeConfig, opts FlagOptions, changed ChangedFlags) {
	if changed["server"] {
		cfg.Server = opts.Server
	}
	if changed["ad-user"] {
		cfg.ADUser = opts.ADUser
	}
	if changed["ad-password"] {
		cfg.ADPassword = opts.ADPassword
	}
	if changed["oidc-client-id"] {
		cfg.OIDCClientID = opts.OIDCClientID
	}
	if changed["oidc-client-secret"] {
		cfg.OIDCClientSecret = opts.OIDCClientSecret
	}
	if changed["oidc-daemon-client-id"] {
		cfg.OIDCDaemonClientID = opts.OIDCDaemonClientID
	}
	if changed["token"] {
		cfg.Token = opts.Token
	}
	if changed["api-key"] {
		cfg.APIKey = opts.APIKey
	}
	if changed["timeout"] {
		cfg.Timeout = opts.Timeout
	}
	if changed["timeout-claim"] {
		cfg.TimeoutClaim = opts.TimeoutClaim
	}
	cfg.NoAuth = opts.NoAuth
	cfg.JSON = opts.JSON
	cfg.Debug = opts.Debug
	cfg.Trace = opts.Trace
}

func missingAuthFields(cfg *RuntimeConfig) []string {
	var missing []string
	if strings.TrimSpace(cfg.ADUser) == "" {
		missing = append(missing, "ad_user")
	}
	if strings.TrimSpace(cfg.ADPassword) == "" {
		missing = append(missing, "ad_password")
	}
	if strings.TrimSpace(cfg.OIDCClientID) == "" {
		missing = append(missing, "oidc_client_id")
	}
	if strings.TrimSpace(cfg.OIDCClientSecret) == "" {
		missing = append(missing, "oidc_client_secret")
	}
	return missing
}

func (cfg *RuntimeConfig) hasDirectAuth() bool {
	return strings.TrimSpace(cfg.Token) != "" || strings.TrimSpace(cfg.APIKey) != ""
}

func (cfg *RuntimeConfig) hasCompleteOIDCAuth() bool {
	return strings.TrimSpace(cfg.ADUser) != "" &&
		strings.TrimSpace(cfg.ADPassword) != "" &&
		strings.TrimSpace(cfg.OIDCClientID) != "" &&
		strings.TrimSpace(cfg.OIDCClientSecret) != ""
}

func (cfg *RuntimeConfig) hasPartialOIDCAuth() bool {
	return strings.TrimSpace(cfg.ADUser) != "" ||
		strings.TrimSpace(cfg.ADPassword) != "" ||
		strings.TrimSpace(cfg.OIDCClientID) != "" ||
		strings.TrimSpace(cfg.OIDCClientSecret) != ""
}

func normalizeServer(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("server must be provided via config, environment, or --server")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse server URL: %w", err)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("server URL %q has no host", raw)
	}
	u.Path = strings.TrimRight(u.EscapedPath(), "/")
	if u.Path == "" {
		u.Path = "/api/v1"
	}
	u.RawQuery = ""
	u.Fragment = ""
	apiBase := strings.TrimRight(u.String(), "/")

	auth := *u
	auth.RawQuery = ""
	auth.Fragment = ""
	path := strings.TrimRight(auth.Path, "/")
	switch {
	case strings.HasSuffix(path, "/api/v1"):
		path = strings.TrimSuffix(path, "/api/v1")
	case strings.HasSuffix(path, "/api"):
		path = strings.TrimSuffix(path, "/api")
	default:
		path = ""
	}
	auth.Path = strings.TrimRight(path, "/") + "/auth/token"
	authURL := auth.String()

	return apiBase, authURL, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func setIfNotEmpty(target *string, value string) {
	if strings.TrimSpace(value) != "" {
		*target = value
	}
}
