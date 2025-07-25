package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/util"
	myvalidation "github.com/dns3l/dns3l-core/util/validation"
	"github.com/go-playground/validator/v10"
)

type OIDCHandler struct {
	AuthnDisabled         bool                `yaml:"authn_disabled"`
	AuthnDisabledEmail    string              `yaml:"authn_disabled_email" validate:"email"`
	AuthzDisabled         bool                `yaml:"authz_disabled"`
	DebugClaims           bool                `yaml:"debug_claims"`
	InjectGroups          map[string][]string `yaml:"inject_groups"`
	GroupsPrefix          string              `yaml:"groups_prefix" validate:"alphanumUnderscoreDashDot"`
	AuthnedCanReadPublic  bool                `yaml:"authned_can_read_public"`
	AnonCanReadPublic     bool                `yaml:"anon_can_read_public"`
	GroupsDomainDelimiter string              `yaml:"groups_domain_delim"`

	OIDCBindings map[string]*OIDCBinding `yaml:"oidc_bindings"`

	validate *validator.Validate
}

type OIDCBinding struct {
	ClientID               string        `yaml:"client_id" validate:"required"`
	HTTPInsecureSkipVerify bool          `yaml:"http_insecure_skip_verify"`
	ForceOnStartup         bool          `yaml:"force_on_startup"`
	TCPTimeout             time.Duration `yaml:"tcp_timeout"`

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

type ClaimsInfo struct {
	Name          string `json:"name"`
	Email         string `json:"email" validate:"email"`
	EmailVerified bool   `json:"email_verified"`
	Groups        []string
}

type OIDCServerInfoAuth struct {
	GroupsPrefix          string `json:"groups-prefix"`
	GroupsDomainDelimiter string `json:"groups-domain-delim"`
}

func createNewOIDCBinding(binding *OIDCBinding, issuer string, onStartup bool) error {

	var dialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

	if binding.TCPTimeout != 0 {
		dialContext = (&net.Dialer{
			Timeout:   binding.TCPTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}

	myClient := &http.Client{
		Transport: &http.Transport{
			DialContext:     dialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: binding.HTTPInsecureSkipVerify},
		},
	}
	ctx := oidc.ClientContext(context.Background(), myClient)

	var err error
	binding.provider, err = oidc.NewProvider(ctx, issuer)
	if err != nil {
		if binding.ForceOnStartup || !onStartup {
			return fmt.Errorf("could not initialize new OIDC binding for %s: %w", issuer, err)
		}
		binding.provider = nil
		log.WithError(err).WithField("issuerURL", issuer).Errorf("Error while initializing new provider, will retry with next request.")
		return nil
	}
	oidcConfig := &oidc.Config{
		ClientID: binding.ClientID,
	}
	binding.verifier = binding.provider.Verifier(oidcConfig)

	log.WithField("issuerURL", issuer).Info("Successfully initialized new OIDC provider.")
	return nil
}

func (h *OIDCHandler) Init() error {
	var err error

	if h.AuthnDisabled {
		return nil
	}

	for issuer, binding := range h.OIDCBindings {
		err := createNewOIDCBinding(binding, issuer, true)
		if err != nil {
			return err
		}

	}

	h.validate = validator.New()
	err = myvalidation.RegisterDNS3LValidations(h.validate)
	if err != nil {
		return err
	}

	return nil

}

func (h *OIDCHandler) GetServerInfoAuth() ServerInfoAuth {

	delim := h.GroupsDomainDelimiter
	if delim == "" {
		delim = "." //. is default
	}

	return OIDCServerInfoAuth{
		GroupsPrefix:          h.GroupsPrefix,
		GroupsDomainDelimiter: delim,
	}
}

func (h *OIDCHandler) selectIssuer(token string) (*OIDCBinding, string, error) {

	issuerURL, err := getIssuerURL(token)
	if err != nil {
		return nil, "", err
	}

	binding, exists := h.OIDCBindings[issuerURL]
	if !exists {
		return nil, "", fmt.Errorf("no OIDC binding exists with the given issuer URL '%s'", issuerURL)
	}

	return binding, issuerURL, nil

}

func (h *OIDCHandler) GetAnonymousInfo() *DefaultAuthorizationInfo {

	return &DefaultAuthorizationInfo{
		DomainsAllowed:        []string{},
		AuthorizationDisabled: false,
		ReadAllowed:           false,
		WriteAllowed:          false,
		UserInfo:              &UserInfo{"anonymous", h.AuthnDisabledEmail},
		ReadAnyPublicAllowed:  false,
	}

}

func (h *OIDCHandler) AuthnGetAuthzInfo(r *http.Request) (AuthorizationInfo, error) {

	rinfo, err := h.authnGetAuthzInfoRaw(r)

	if err == nil {
		log.WithField("authzinfo", rinfo.String()).Debug("Request authorization determined")
	}

	return rinfo, err

}

func (h *OIDCHandler) authnGetAuthzInfoRaw(r *http.Request) (AuthorizationInfo, error) {

	if h.AuthnDisabled {
		disinfo := h.GetAnonymousInfo()
		disinfo.AuthorizationDisabled = true
		return disinfo, nil
	}

	tkn, err := GetBearerToken(r)
	if err != nil {
		return nil, err
	}
	if tkn == "" {
		if h.AnonCanReadPublic {
			rinfo := h.GetAnonymousInfo()
			rinfo.ReadAnyPublicAllowed = true
			return rinfo, nil
		}

		return nil, &common.NotAuthnedError{Msg: "no bearer token has been set"}
	}

	issuer, issuerURL, err := h.selectIssuer(tkn)
	if err != nil {
		return nil, fmt.Errorf("problem detecting OIDC token issuer: %w", err)
	}

	if issuer.provider == nil {
		//the OIDC client has not been set on startup, e.g. due to an error
		err = createNewOIDCBinding(issuer, issuerURL, false)
		if err != nil {
			return nil, fmt.Errorf("problem initializing OIDC client: %w", err)
		}
	}

	idToken, err := issuer.verifier.Verify(r.Context(), tkn)
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

	userinfo := &UserInfo{
		Name:  cinfo.Name,
		Email: cinfo.Email,
	}

	err = userinfo.Validate()
	if err != nil {
		return nil, err
	}

	uname := userinfo.GetPreferredName()

	if len(h.InjectGroups) > 0 {
		//This is a quirks mode for OIDC environments not offering
		//groups, e.g. test beds. Normally not used.
		groups, exists := h.InjectGroups[uname]
		if exists {
			cinfo.Groups = append(cinfo.Groups, groups...)
			log.WithField("groups", groups).WithField("username", uname).Debug("Injected groups for authorization (quirks)")
		}
	}

	authzinfo := &DefaultAuthorizationInfo{
		DomainsAllowed:        make([]string, 0, 100),
		AuthorizationDisabled: h.AuthzDisabled,
		ReadAllowed:           false,
		WriteAllowed:          false,
		UserInfo:              userinfo,
		ReadAnyPublicAllowed:  h.AuthnedCanReadPublic,
	}

	for _, grp := range cinfo.Groups {

		domain, valid := h.groupsToDomain(grp)

		if !valid {
			//e.g. does not have the prefix, silently ignore it
			continue
		}

		if strings.EqualFold(domain, "write") {
			authzinfo.WriteAllowed = true
			authzinfo.ReadAllowed = true
			continue
		}
		if strings.EqualFold(domain, "read") {
			authzinfo.ReadAllowed = true
			continue
		}

		if domain == "" || domain == "." {
			log.Warn("Permitting the root domain '.' to users is not allowed, dropping domain prefix for authz.")
			continue
		}

		authzinfo.DomainsAllowed = append(authzinfo.DomainsAllowed, util.GetDomainFQDNDot(domain))
	}

	return authzinfo, nil

}

func (h *OIDCHandler) groupsToDomain(group string) (string, bool) {

	if !strings.HasPrefix(group, h.GroupsPrefix) {
		return "", false
	}

	group = group[len(h.GroupsPrefix):]

	if group == "" {
		return "", false
	}

	if h.GroupsDomainDelimiter != "" && h.GroupsDomainDelimiter != "." {

		group = strings.ReplaceAll(group, h.GroupsDomainDelimiter, ".") //corner cases where we need an underscore are removed

	}
	return group, true
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
