package test

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/dns3l/dns3l-core/ca"
	"github.com/dns3l/dns3l-core/ca/acme"
	castate "github.com/dns3l/dns3l-core/ca/state"
	"github.com/dns3l/dns3l-core/ca/types"
	dns "github.com/dns3l/dns3l-core/dns"
	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	dnstypes "github.com/dns3l/dns3l-core/dns/types"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/state"
	"github.com/dns3l/dns3l-core/util"
)

type RootConfig struct {
	DNS     *dns.Config `yaml:"dns"`
	DNSTest struct {
		TestableZones map[string]struct {
			Zones        []string `yaml:"zones"`
			Checkservers []string `yaml:"checkservers"`
		} `yaml:"testablezones"`
	} `yaml:"dns-test"`
}

type ProvConfigurationContextImpl struct {
	caID    string
	dnsprov dnstypes.DNSProvider
	state   types.CAStateManager
}

func (ctx *ProvConfigurationContextImpl) GetCAID() string {
	return ctx.caID
}

func (ctx *ProvConfigurationContextImpl) GetStateMgr() types.CAStateManager {
	return ctx.state
}

func (ctx *ProvConfigurationContextImpl) GetDNSProviderForDomain(domain string, challenge bool) (dnstypes.DNSProvider, error) {
	return ctx.dnsprov, nil
}

func TestWithLEStaging() {

	c := &RootConfig{}

	err := util.ConfigFromFileEnv(c)
	if err != nil {
		panic(err)
	}

	dbstr := os.Getenv("DNS3L_MYSQL_ADDR")
	if dbstr == "" {
		panic("no MySQL address set")
	}

	var dbprov state.SQLDBProvider = &state.SQLDBProviderDefault{
		Type:     "mysql",
		URL:      dbstr,
		DBPrefix: "test",
	}

	var casm types.CAStateManager = &castate.CAStateManagerSQL{
		Prov: dbprov,
	}

	caID := "foo"

	e := acme.Engine{
		CAID: caID,
		Conf: &acme.Config{
			Name:                       "Test LE Staging",
			CAType:                     "public",
			API:                        "https://acme-staging-v02.api.letsencrypt.org/directory",
			Roots:                      "",
			RelativeLifetimeUntilRenew: 0.7, //this is to test immediale renewal
		},
		State: &acme.ACMEStateManagerSQL{
			CAID: caID,
			Prov: dbprov,
		},
		Context: &ProvConfigurationContextImpl{
			caID:    caID,
			dnsprov: c.DNS.Providers["otc"].Prov,
			state:   casm,
		},
	}

	h := ca.CAFunctionHandler{
		State: casm,
	}

	err = h.Init()
	if err != nil {
		panic(err)
	}

	err = state.CreateSQLTables(dbprov, true)
	if err != nil {
		panic(err)
	}

	dnsProvider := "otc"
	issuedBy := &authtypes.UserInfo{Name: "testuser1", Email: ""}
	acmeuser := "testacmeuser1"

	domainName1, _, err := dnscommon.MakeNewDomainName4Test(c.DNSTest.TestableZones[dnsProvider].Zones)
	if err != nil {
		panic(err)
	}
	domainName2, _, err := dnscommon.MakeNewDomainName4Test(c.DNSTest.TestableZones[dnsProvider].Zones)
	if err != nil {
		panic(err)
	}

	err = e.TriggerUpdate(acmeuser, domainName1, []string{domainName1, domainName2},
		issuedBy, time.Duration(720)*time.Hour, false)
	if err != nil {
		var norenew *acme.NoRenewalDueError
		if errors.As(err, &norenew) {
			log.Infof("No renewal due yet, continuing. %s",
				norenew.RenewalDate.Format(time.RFC3339))
		} else {
			panic(err)
		}
	}

	//this should trigger updating the existing key while getting details from database
	err = e.TriggerUpdate("", domainName1, nil, nil, time.Duration(720)*time.Hour, false)
	if err != nil {
		var norenew *acme.NoRenewalDueError
		if errors.As(err, &norenew) {
			log.Infof("No renewal due yet, continuing. %s",
				norenew.RenewalDate.Format(time.RFC3339))
		} else {
			panic(err)
		}
	}

	key, err := h.GetCertificateResource(domainName1, caID, "key")
	if err != nil {
		panic(err)
	}

	tmpDir, err := os.MkdirTemp("", "dns3l-test")
	if err != nil {
		panic(err)
	}
	err = writeToFile(tmpDir, "key.pem", key.ContentType, key.PEMData)
	if err != nil {
		panic(err)
	}

	crt, err := h.GetCertificateResource(domainName1, caID, "crt")
	if err != nil {
		panic(err)
	}
	err = writeToFile(tmpDir, "crt.pem", crt.ContentType, crt.PEMData)
	if err != nil {
		panic(err)
	}
	fullchain, err := h.GetCertificateResource(domainName1, caID, "fullchain")
	if err != nil {
		panic(err)
	}
	err = writeToFile(tmpDir, "fullchain.pem", fullchain.ContentType, fullchain.PEMData)
	if err != nil {
		panic(err)
	}

}

func writeToFile(tmpdir, fname, contenttype, content string) error {
	fullname := filepath.Join(tmpdir, fname)
	log.Infof("Writing to file %s, type %s", fullname, contenttype)
	return os.WriteFile(fullname, []byte(content), 0644)
}
