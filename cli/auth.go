package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenFetcher struct {
	Client *http.Client
}

func (f *TokenFetcher) Fetch(ctx context.Context, cfg *RuntimeConfig) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("scope", fmt.Sprintf("openid profile email groups offline_access audience:server:client_id:%s", cfg.OIDCDaemonClientID))
	form.Set("username", cfg.ADUser)
	form.Set("password", cfg.ADPassword)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.AuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.OIDCClientID, cfg.OIDCClientSecret)

	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch OIDC token: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if strings.TrimSpace(tokenResp.IDToken) == "" {
		return "", fmt.Errorf("token response from %s did not contain id_token", cfg.AuthURL)
	}
	return tokenResp.IDToken, nil
}
