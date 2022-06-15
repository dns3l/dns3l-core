package main

import (
	acmetest "github.com/dta4/dns3l-go/ca/acme/test"
	log "github.com/sirupsen/logrus"
)

//Component test with external systems which cannot be unit tests
//are triggered from here
func main() {

	log.SetLevel(log.DebugLevel)
	acmetest.TestWithLEStaging()

}
