package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	Config       *RuntimeConfig
	HTTPClient   *http.Client
	TokenFetcher *TokenFetcher
}

type Response struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

type HTTPError struct {
	StatusCode int
	Message    string
	Body       string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("server returned HTTP %d: %s", e.StatusCode, e.Message)
	}
	if e.Body != "" {
		return fmt.Sprintf("server returned HTTP %d: %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("server returned HTTP %d", e.StatusCode)
}

func NewClient(cfg *RuntimeConfig) *Client {
	httpClient := &http.Client{Timeout: cfg.Timeout}
	return &Client{
		Config:       cfg,
		HTTPClient:   httpClient,
		TokenFetcher: &TokenFetcher{Client: httpClient},
	}
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) (*Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	reqURL, err := c.urlFor(path, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, text/plain")
	if err := c.applyAuth(ctx, req); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"method": method, "url": reqURL}).Debug("Sending API request")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send API request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read API response: %w", err)
	}
	log.WithFields(log.Fields{
		"method": method,
		"url":    reqURL,
		"status": resp.StatusCode,
	}).Debug("Received API response")
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithField("body", string(respBody)).Trace("API response body")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newHTTPError(resp.StatusCode, respBody)
	}

	return &Response{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        respBody,
	}, nil
}

func (c *Client) applyAuth(ctx context.Context, req *http.Request) error {
	cfg := c.Config
	if cfg.NoAuth {
		return nil
	}
	if cfg.APIKey != "" {
		req.Header.Set("X-DNS3L-API-Key", cfg.APIKey)
		return nil
	}
	token := cfg.Token
	if token == "" {
		var err error
		token, err = c.TokenFetcher.Fetch(ctx, cfg)
		if err != nil {
			return err
		}
		cfg.Token = token
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

func (c *Client) urlFor(path string, query url.Values) (string, error) {
	base, err := url.Parse(c.Config.APIBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse API base URL: %w", err)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	if len(query) > 0 {
		base.RawQuery = query.Encode()
	}
	return base.String(), nil
}

func newHTTPError(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	var errMsg apiv1.ErrorMsg
	if err := json.Unmarshal(body, &errMsg); err == nil && errMsg.Message != "" {
		msg = errMsg.Message
	}
	return &HTTPError{StatusCode: status, Message: msg, Body: strings.TrimSpace(string(body))}
}

func pathEscape(value string) string {
	return url.PathEscape(value)
}
