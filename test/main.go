package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	acmetest "github.com/dns3l/dns3l-core/ca/acme/test"
	"github.com/dns3l/dns3l-core/dns"
	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/test/comp"
	"github.com/dns3l/dns3l-core/test/runs"
	"github.com/dns3l/dns3l-core/util"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("module", "test")

var testruns = map[string]func(){

	"acme": func() {

		acmetest.TestWithLEStaging()

	}, "dns": func() {

		dns.TestAllProvidersFromConfig()

	}, "tryout": func() {

		comptest := comp.ComponentTest{
			TestConfig: filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml"),
		}

		err := comptest.Exec(func(srv *service.Service) error {
			time.Sleep(500 * time.Millisecond)
			waitUntilSigInt()
			return nil
		})
		if err != nil {
			panic(err)
		}

	}, "dbfull": func() {

		r := runs.TestRunner{
			TestConfig:    filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml"),
			CAID:          "bogus",
			Domain:        "test.example.com.",
			Truncate:      true,
			ReplicaOffset: 0,
			NumReplicas:   20,
			Dump:          false,
			WithACME:      false,
		}

		r.RunDBFull()

	}, "acmestep": func() {

		// Tests currently do not run stable because DNS cache
		// propagation artifacts may occur on a local instance

		r := runs.TestRunner{
			TestConfig:    filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml"),
			CAID:          "step-comptest",
			Domain:        "test.example.com.",
			Truncate:      true,
			ReplicaOffset: 0,
			NumReplicas:   10,
			Dump:          false,
			WithACME:      true,
		}

		r.RunSingleEntry()

	}, "acmestep-external": func() {

		rootdomain := os.Getenv("DNS3L_TEST_ROOTDOMAIN")
		if rootdomain == "" {
			panic(errors.New("DNS3L_TEST_ROOTDOMAIN not set"))
		}

		testconf := os.Getenv("DNS3L_TESTCONFIG")
		if testconf == "" {
			panic(errors.New("DNS3L_TESTCONFIG not set"))
		}

		r := runs.TestRunner{
			TestConfig:    testconf,
			CAID:          "step-comptest",
			Domain:        rootdomain,
			Truncate:      false,
			ReplicaOffset: 0,
			NumReplicas:   1,
			Dump:          false,
			WithACME:      true,
		}

		r.RunACMEUsers()

	}, "bogus": func() {

		r := runs.TestRunner{
			TestConfig:        filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml"),
			CAID:              "bogus",
			Domain:            "test.example.com.",
			Truncate:          true,
			ReplicaOffset:     0,
			NumReplicas:       1,
			Dump:              false,
			WithACME:          false,
			CheckIntermediate: true,
		}

		r.RunSingleEntry()

	}, "le-staging": func() {

		rootdomain := os.Getenv("DNS3L_TEST_ROOTDOMAIN")
		if rootdomain == "" {
			panic(errors.New("DNS3L_TEST_ROOTDOMAIN not set"))
		}

		testconf := os.Getenv("DNS3L_TESTCONFIG")
		if testconf == "" {
			panic(errors.New("DNS3L_TESTCONFIG not set"))
		}

		r := runs.TestRunner{
			TestConfig:    testconf,
			CAID:          "le-staging",
			Domain:        rootdomain,
			Truncate:      false,
			ReplicaOffset: 0,
			NumReplicas:   1,
			Dump:          false,
			WithACME:      false,
		}

		r.RunSingleEntry()

	}, "renewexisting": func() {

		comptest := comp.ComponentTest{
			TestConfig: filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml"),
		}

		err := comptest.Exec(func(srv *service.Service) error {
			time.Sleep(500 * time.Millisecond)

			certs, err := srv.Config.CA.Functions.ListCertsToRenew(10000)
			if err != nil {
				panic(err)
			}

			if len(certs) <= 0 {
				log.Warn("No certificates to renew.")
			}

			for i := range certs {
				err := srv.Config.CA.Functions.RenewCertificate(&certs[i])
				if err != nil {
					panic(err)
				}
			}

			return nil
		})
		if err != nil {
			panic(err)
		}

	},
}

// Component test with external systems which cannot be unit tests
// are triggered from here
func main() {

	logrus.SetLevel(logrus.DebugLevel)
	//
	//acmetest.TestWithLEStaging()

	if len(os.Args) <= 1 {
		panic("no command given")
	}

	key := os.Args[1]

	if runfunc, ok := testruns[key]; ok {
		runfunc()
		return
	}

	panic(fmt.Sprintf("command %s not found", key))

}

func waitUntilSigInt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
