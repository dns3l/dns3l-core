package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/dns3l/dns3l-core/common"
	myvalidation "github.com/dns3l/dns3l-core/util/validation"
	"github.com/go-playground/validator/v10"
)

type OIDCHandler struct {
	Issuer                 string              `yaml:"issuer" validate:"url,required"`
	ClientID               string              `yaml:"client_id" validate:"required"`
	AuthnDisabled          bool                `yaml:"authn_disabled"`
	AuthnDisabledEmail     string              `yaml:"authn_disabled_email" validate:"email"`
	AuthzDisabled          bool                `yaml:"authz_disabled"`
	HTTPInsecureSkipVerify bool                `yaml:"http_insecure_skip_verify"`
	DebugClaims            bool                `yaml:"debug_claims"`
	InjectGroups           map[string][]string `yaml:"inject_groups"`

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	validate *validator.Validate
}

type ClaimsInfo struct {
	Name          string `json:"name"`
	Email         string `json:"email" validate:"email"`
	EmailVerified bool   `json:"email_verified"`
	Groups        []string
}

func (h *OIDCHandler) Init() error {
	var err error

	if h.AuthnDisabled {
		return nil
	}

	myClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: h.HTTPInsecureSkipVerify},
		},
	}
	ctx := oidc.ClientContext(context.Background(), myClient)

	h.provider, err = oidc.NewProvider(ctx, h.Issuer)
	if err != nil {
		return err
	}
	oidcConfig := &oidc.Config{
		ClientID: h.ClientID,
	}
	h.verifier = h.provider.Verifier(oidcConfig)

	h.validate = validator.New()
	err = myvalidation.RegisterDNS3LValidations(h.validate)
	if err != nil {
		return err
	}

	return nil

}

func (h *OIDCHandler) AuthnGetAuthzInfo(r *http.Request) (*AuthorizationInfo, error) {

	if h.AuthnDisabled {
		return &AuthorizationInfo{
			AuthorizationDisabled: true,
			Email:                 h.AuthnDisabledEmail,
		}, nil
	}

	tkn, err := GetBearerToken(r)
	if err != nil {
		return nil, err
	}
	if tkn == "" {
		return nil, &common.NotAuthnedError{Msg: "no bearer token has been set"}
	}

	idToken, err := h.verifier.Verify(r.Context(), tkn)
	if err != nil {
		return nil, err
	}

	claimsDebug := make(map[string]interface{})
	err = idToken.Claims(&claimsDebug)
	if err != nil {
		return nil, err
	}
	if h.DebugClaims {
		log.WithField("claims", claimsDebug).Info("Claims Debug")
	}

	var cinfo ClaimsInfo

	err = idToken.Claims(&cinfo)
	if err != nil {
		return nil, err
	}

	err = h.validate.StructFiltered(cinfo, func(ns []byte) bool {
		//fmt.Printf("VALIDATION: %s\n", ns)
		return false
	})
	if err != nil {
		return nil, err
	}

	var username string
	if cinfo.Email != "" {
		username = cinfo.Email
	} else if cinfo.Name != "" {
		username = cinfo.Name
	} else {
		return nil, &common.NotAuthnedError{Msg: "neither 'user' nor 'email' has been provided in OIDC token claims"}
	}

	if len(h.InjectGroups) > 0 {
		//This is a quirks mode for OIDC environments not offering
		//groups, e.g. test beds. Normally not used.
		groups, exists := h.InjectGroups[username]
		if exists {
			cinfo.Groups = append(cinfo.Groups, groups...)
			log.WithField("groups", groups).WithField("username", username).Debug("Injected groups for authorization (quirks)")
		}
	}

	authzinfo := &AuthorizationInfo{
		RootzonesAllowed:      make(map[string]bool, 100),
		AuthorizationDisabled: h.AuthzDisabled,
		ReadAllowed:           false,
		WriteAllowed:          false,
		Name:                  cinfo.Name,
		Username:              username,
		Email:                 cinfo.Email,
	}

	for _, grp := range cinfo.Groups {
		if strings.EqualFold(grp, "write") {
			authzinfo.WriteAllowed = true
			authzinfo.ReadAllowed = true
			continue
		}
		if strings.EqualFold(grp, "read") {
			authzinfo.ReadAllowed = true
			continue
		}
		authzinfo.RootzonesAllowed[grp] = true
	}

	return authzinfo, nil

}

func GetBearerToken(r *http.Request) (string, error) {

	hdr := r.Header.Get("authorization")

	if hdr == "" {
		return "", nil
	}

	spl := strings.Split(hdr, " ")

	if len(spl) < 2 || !strings.EqualFold(spl[0], "Bearer") {
		return "", errors.New("invalid bearer token")
	}

	return spl[1], nil

}
