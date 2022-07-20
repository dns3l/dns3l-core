package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/dta4/dns3l-go/common"
	myvalidation "github.com/dta4/dns3l-go/util/validation"
	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
)

type OIDCHandler struct {
	Issuer        string `yaml:"issuer" validate:"url,required"`
	ClientID      string `yaml:"client_id" validate:"required"`
	AuthnDisabled bool   `yaml:"authn_disabled"`
	AuthzDisabled bool   `yaml:"authz_disabled"`

	ctx      context.Context
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	validate *validator.Validate
}

type ClaimsInfo struct {
	Username      string   `mapstructure:"username" validate:"required,alphanum"`
	Email         string   `json:"email" validate:"required,alphanum"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `mapstructure:"groups"`
}

func (h *OIDCHandler) Init() error {
	var err error

	if h.AuthnDisabled {
		return nil
	}

	h.ctx = context.Background()

	h.provider, err = oidc.NewProvider(h.ctx, h.Issuer)
	if err != nil {
		return err
	}
	oidcConfig := &oidc.Config{
		ClientID: h.ClientID,
	}
	h.verifier = h.provider.Verifier(oidcConfig)

	h.validate = validator.New()
	myvalidation.RegisterDNS3LValidations(h.validate)

	return nil

}

func (h *OIDCHandler) AuthnGetAuthzInfo(r *http.Request) (*AuthorizationInfo, error) {

	if h.AuthnDisabled {
		return &AuthorizationInfo{
			AuthorizationDisabled: true,
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
		return nil, &common.NotAuthnedError{Msg: "unable to verify OIDC token"}
	}

	var cinfo ClaimsInfo
	err = mapstructure.Decode(idToken.Claims, &cinfo)
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

	authzinfo := &AuthorizationInfo{
		RootzonesAllowed:      make(map[string]bool, 100),
		AuthorizationDisabled: h.AuthzDisabled,
		ReadAllowed:           false,
		WriteAllowed:          false,
		Username:              cinfo.Username,
		Email:                 cinfo.Email,
	}

	for _, grp := range cinfo.Groups {
		if strings.EqualFold(grp, "write") {
			authzinfo.WriteAllowed = true
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
