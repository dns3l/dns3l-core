package acme

import (
	sqlraw "database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	dns "github.com/dta4/dns3l-go/dns"
	dnscommon "github.com/dta4/dns3l-go/dns/common"
	"github.com/dta4/dns3l-go/sql"
	"github.com/dta4/dns3l-go/util"
	_ "github.com/mattn/go-sqlite3"
)

type RootConfig struct {
	DNS     *dns.Config `yaml:"dns"`
	DNSTest struct {
		TestableZones map[string][]string
	} `yaml:"dns-test"`
}

func TestWithLEStaging() {

	c := &RootConfig{}

	err := util.ConfigFromFileEnv(c)
	if err != nil {
		panic(err)
	}

	var dbprov sql.SQLDBProvider = &sql.SQLDBProviderDefault{
		Type:     "sqlite3",
		DBPrefix: "dns3l.test",
		PreExecFunc: func(db *sqlraw.DB) error {
			_, err := db.Exec(`ATTACH DATABASE './test-sqlite.db' AS dns3l;`)
			return err
		},
	}

	e := Engine{
		Conf: &Config{
			ID:                    "test-lestaging",
			Name:                  "Test LE Staging",
			CAType:                "public",
			URL:                   "https://acme-staging-v02.api.letsencrypt.org/directory",
			Roots:                 "",
			DaysRenewBeforeExpiry: 16,
		},
		DNSConf: c.DNS,
		State: &ACMEStateManagerSQL{
			Prov: dbprov,
		},
	}

	err = sql.InitDB(dbprov)
	if err != nil {
		panic(err)
	}

	dnsProvider := "dns3l"
	email := "leo@nobach.net"
	userid := "testuser1"
	keyid := "testkey1"

	domainName1, err := dnscommon.MakeNewDomainName4Test(c.DNSTest.TestableZones[dnsProvider])
	if err != nil {
		panic(err)
	}
	domainName2, err := dnscommon.MakeNewDomainName4Test(c.DNSTest.TestableZones[dnsProvider])
	if err != nil {
		panic(err)
	}

	err = e.TriggerUpdate(userid, keyid, []string{domainName1, domainName2}, dnsProvider, email)
	if err != nil {
		var norenew *NoRenewalDueError
		if errors.As(err, &norenew) {
			log.Infof("No renewal due yet, continuing. %s", norenew.RenewalDate.Format(time.RFC3339))
		} else {
			panic(err)
		}
	}

	key, ctype, err := e.GetResource(keyid, userid, "key")
	if err != nil {
		panic(err)
	}

	tmpDir, err := os.MkdirTemp("", "dns3l-test")
	if err != nil {
		panic(err)
	}
	err = writeToFile(tmpDir, "key.pem", ctype, key)
	if err != nil {
		panic(err)
	}

	crt, ctype, err := e.GetResource(keyid, userid, "crt")
	if err != nil {
		panic(err)
	}
	err = writeToFile(tmpDir, "crt.pem", ctype, crt)
	if err != nil {
		panic(err)
	}
	fullchain, ctype, err := e.GetResource(keyid, userid, "crt")
	if err != nil {
		panic(err)
	}
	err = writeToFile(tmpDir, "fullchain.pem", ctype, fullchain)
	if err != nil {
		panic(err)
	}

}

func writeToFile(tmpdir, fname, contenttype, content string) error {
	fullname := filepath.Join(tmpdir, fname)
	log.Infof("Writing to file %s, type %s", fullname, contenttype)
	return os.WriteFile(fullname, []byte(content), 0644)
}
