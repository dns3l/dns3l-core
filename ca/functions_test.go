package ca

import (
	"time"

	"testing"

	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/renew"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/util"
)

// fakeCAProvider is a minimal types.CAProvider whose certificate operations all
// succeed, so DeleteCertificate completes without error.
type fakeCAProvider struct{}

func (p *fakeCAProvider) Init(types.ProviderConfigurationContext) error { return nil }
func (p *fakeCAProvider) GetInfo() *types.CAProviderInfo                { return &types.CAProviderInfo{} }
func (p *fakeCAProvider) IsEnabled() bool                               { return true }
func (p *fakeCAProvider) PrecheckClaimCertificate(*types.CertificateClaimInfo) error {
	return nil
}
func (p *fakeCAProvider) ClaimCertificate(*types.CertificateClaimInfo) error { return nil }
func (p *fakeCAProvider) RenewCertificate(*types.CertificateRenewInfo) error { return nil }
func (p *fakeCAProvider) RevokeCertificate(string, *types.CACertInfo) error  { return nil }
func (p *fakeCAProvider) CleanupAfterDeletion(string, *types.CACertInfo) error {
	return nil
}

// fakeStateManager / fakeSession provide a state backend in which the requested
// certificate exists and is deleted without error.
type fakeStateManager struct{}

func (m *fakeStateManager) NewSession() (types.CAStateManagerSession, error) {
	return &fakeSession{}, nil
}

type fakeSession struct{}

func (s *fakeSession) Close() error { return nil }

func (s *fakeSession) GetCACertByID(keyID string, caID string) (*types.CACertInfo, error) {
	return &types.CACertInfo{Name: keyID}, nil
}

func (s *fakeSession) DelCACertByID(keyID string, caID string) error { return nil }

func (s *fakeSession) ListCACerts(string, string, []string, string,
	*util.PaginationInfo) ([]types.CACertInfo, error) {
	panic("not used in this test")
}
func (s *fakeSession) PutCACertData(string, string, *types.CACertInfo, string, string) error {
	panic("not used in this test")
}
func (s *fakeSession) UpdateCACertData(string, string, time.Time, time.Time, time.Time,
	time.Time, string, string) error {
	panic("not used in this test")
}
func (s *fakeSession) GetResource(string, string, bool, string) (string, error) {
	panic("not used in this test")
}
func (s *fakeSession) GetResources(string, string, bool, ...string) ([]string, error) {
	panic("not used in this test")
}
func (s *fakeSession) GetNumberOfCerts(string, bool, time.Time) (uint, error) {
	panic("not used in this test")
}
func (s *fakeSession) DeleteCertAllCA(string) error { panic("not used in this test") }
func (s *fakeSession) ListExpired(time.Time, uint) ([]types.CertificateRenewInfo, error) {
	panic("not used in this test")
}
func (s *fakeSession) ListToRenew(time.Time, uint) ([]types.CertificateRenewInfo, error) {
	panic("not used in this test")
}
func (s *fakeSession) GetDomains(string, string) ([]string, error) {
	panic("not used in this test")
}
func (s *fakeSession) UserHasCerts(*authtypes.UserInfo, string) (bool, error) {
	panic("not used in this test")
}
func (s *fakeSession) GetLastRenewSummary() (*renew.ServerInfoRenewal, error) {
	panic("not used in this test")
}
func (s *fakeSession) PutLastRenewSummary(*renew.ServerInfoRenewal) error {
	panic("not used in this test")
}

// TestDeleteCertificatesAllCASucceeds is a regression test for issue #97:
// a successful deletion must return a nil error. Previously the loop fell into
// the failure branch on a nil error and returned fmt.Errorf(..., nil), i.e. a
// non-nil error wrapping nil, so the DELETE endpoint reported failure on success.
func TestDeleteCertificatesAllCASucceeds(t *testing.T) {
	cfg := &Config{
		Providers: map[string]*ProviderInfo{
			"test-ca": {Type: "fake", Prov: &fakeCAProvider{}},
		},
	}
	h := &CAFunctionHandler{
		Config: cfg,
		State:  &fakeStateManager{},
	}

	err := h.DeleteCertificatesAllCA("test-key")
	if err != nil {
		t.Fatalf("expected nil error on successful deletion, got: %v", err)
	}
}
