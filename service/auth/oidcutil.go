package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func getIssuerURL(token string) (string, error) {

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("need 3-part OIDC token, but got %d parts", len(parts))
	}
	decodedStr, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("base64 decoded of 2nd part of token failed: %w", err)
	}
	fmt.Println(string(decodedStr))
	var decoded struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(decodedStr, &decoded); err != nil {
		return "", fmt.Errorf("error while decoding JSON structure of OIDC token: %w", err)
	}

	return decoded.Issuer, nil
}
