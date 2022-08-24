package main

import (
	acmetest "github.com/dns3l/dns3l-core/ca/acme/test"
	"github.com/dns3l/dns3l-core/dns"
	log "github.com/sirupsen/logrus"
)

//Component test with external systems which cannot be unit tests
//are triggered from here
func main() {

	log.SetLevel(log.DebugLevel)
	dns.TestAllProvidersFromConfig()
	acmetest.TestWithLEStaging()

}
