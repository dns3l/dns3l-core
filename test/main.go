package main

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/test/comp"
	"github.com/dns3l/dns3l-core/test/runs"
	"github.com/dns3l/dns3l-core/util"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("module", "test")

// Component test with external systems which cannot be unit tests
// are triggered from here
func main() {

	logrus.SetLevel(logrus.DebugLevel)
	//dns.TestAllProvidersFromConfig()
	//acmetest.TestWithLEStaging()

	if os.Args[1] == "tryout" {

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

	} else if os.Args[1] == "dbfull" {

		testconf := filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml")

		runs.RunDBFull(testconf, "bogus", "test.example.com.", true, 20, false)

	} else if os.Args[1] == "le-staging" {

		rootdomain := os.Getenv("DNS3L_TEST_ROOTDOMAIN")
		if rootdomain == "" {
			panic(errors.New("DNS3L_TEST_ROOTDOMAIN not set"))
		}

		testconf := os.Getenv("DNS3L_TESTCONFIG")
		if rootdomain == "" {
			panic(errors.New("DNS3L_TESTCONFIG not set"))
		}

		runs.RunDBFull(testconf, "le-staging", rootdomain, false, 1, false)

	} else if os.Args[1] == "renewexisting" {

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

	}

}

func waitUntilSigInt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
