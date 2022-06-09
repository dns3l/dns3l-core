package main

import "github.com/dta4/dns3l-go/ca/acme"

//Component test with external systems which cannot be unit tests
//are triggered from here
func main() {

	acme.TestWithLEStaging()

}
