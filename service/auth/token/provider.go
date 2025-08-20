package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"

	"github.com/dns3l/dns3l-core/service/auth/types"
)

const (
	TokenHeaderKey    = "X-DNS3L-Access-Token"
	TokenLength       = 32
	TokenLengthBase64 = 44 // 4*ceil(32/3)
)

// When needed manually, generate tokens with: openssl rand -base64 32

type TokenAuthProvider struct {
	Config TokenAuthConfig
}

func (c *TokenAuthProvider) AuthnGetAuthzInfo(r *http.Request) (types.AuthorizationInfo, error) {

	token := strings.TrimSpace(r.Header.Get(TokenHeaderKey))

	if token == "" {
		// this is not token-based auth
		return nil, nil
	}

	if len(token) < TokenLengthBase64 || !isBase64(token) {
		log.Debug("Token must be 32 bytes in base64, ignoring token.")
		return nil, nil
	}

	tokenHashed := ConvertPlainToken(token)

	// only static implemented at the moment
	for i, tokencfg := range c.Config.Static {
		if !validName(tokencfg) {
			log.Errorf("Static token in config at position %d has invalid name, must be at least 3 characters long, ignoring.", i)
			continue
		}
		if tokencfg.Sha256 == tokenHashed ||
			tokencfg.Sha256 == "" && tokencfg.Plain == token {
			authzinfo := &types.DefaultAuthorizationInfo{
				UserInfo: &types.UserInfo{
					Name: tokencfg.Name,
				},
				WriteAllowed:   tokencfg.Write,
				ReadAllowed:    true,
				DomainsAllowed: tokencfg.DomainsAllowed,
			}
			log.WithField("authzinfo", authzinfo.String()).Debug("Token request authorization determined")
			return authzinfo, nil
		}
	}

	log.Debug("Token did not match an authorization.")

	return nil, nil

}

func validName(tokencfg Token) bool {
	return len(tokencfg.Name) >= 3
}

// Tokens are not user-provided passwords, but >= 32-character random strings
// generated from a trusted source, no need for salting or slow hashes
// Bash equivalent: echo -n "<token>" | openssl sha256 -binary | base64 -
func ConvertPlainToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

var regex32bytebase64 = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

func isBase64(token string) bool {
	return regex32bytebase64.MatchString(token)
}

func (c *TokenAuthProvider) GetServerInfoAuth() interface{} {
	return struct{}{}
}

func GenerateRandomToken() (string, error) {
	b := make([]byte, TokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}
