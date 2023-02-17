package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/test/apiv1"
	testauth "github.com/dns3l/dns3l-core/test/auth"
	"github.com/dns3l/dns3l-core/test/comp"
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

		comptest := comp.ComponentTest{}

		err := comptest.Exec(func(srv *service.Service) error {
			time.Sleep(500 * time.Millisecond)
			waitUntilSigInt()
			return nil
		})
		if err != nil {
			panic(err)
		}

	} else if os.Args[1] == "simplest" {

		comptest := comp.ComponentTest{
			StubUsers: map[string]testauth.AuthStubUser{
				"alice": {
					Name:  "Alice Doe",
					Email: "alice@example.com",
					DomainsAllowed: []string{
						"sub1.test.example.com.",
						"sub2.test.example.com.",
					},
					WriteAllowed: true,
					ReadAllowed:  true,
				},
				"bob": {
					Name:  "Alice Doe",
					Email: "alice@example.com",
					DomainsAllowed: []string{
						"sub1.test.example.com.",
						"bar.sub2.test.example.com.",
					},
					WriteAllowed: true,
					ReadAllowed:  true,
				},
				"kilgore": {
					Name:  "Kilgore Trout",
					Email: "ktrout@example.com",
					DomainsAllowed: []string{
						"sub1.test.example.com.",
						"sub2.test.example.com.",
					},
					WriteAllowed: false,
					ReadAllowed:  true,
				},
			},
		}

		err := comptest.Exec(func(srv *service.Service) error {

			// apiv1.CreateKey("1st key", srv, "alice", "foo.bar.sub1.test.example.com", []string{
			// 	"alt.foo.bar.sub1.test.example.com",
			// 	"alt2.foo.bar.sub2.test.example.com",
			// })

			// apiv1.CreateKey("2nd key", srv, "alice", "foo.bar.sub2.test.example.com", []string{
			// 	"alt.foo.bar.sub2.test.example.com",
			// 	"alt2.foo.bar.sub1.test.example.com",
			// })

			// apiv1.CreateKey("3rd key", srv, "bob", "test1.1337.sub1.test.example.com", []string{
			// 	"alt.test1.1337.sub1.test.example.com",
			// 	"alt2.test1.1337.sub1.test.example.com",
			// })

			// log.Infof("Create key 1")
			// apiv1.CreateKey(srv, "alice", "test2.1337.sub2.test.example.com", []string{
			// 	"alt.foo.bar.sub2.test.example.com",
			// 	"alt2.foo.bar.sub1.test.example.com",
			// })

			log.Infof("List keys")
			fmt.Println(apiv1.ListKeys(srv, "kilgore"))

			log.Infof("Get Key by ID")
			fmt.Println(apiv1.GetKeyById(srv, "bob", "foo.bar.sub2.test.example.com"))

			waitUntilSigInt()

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
