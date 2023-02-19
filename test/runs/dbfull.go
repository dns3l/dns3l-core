package runs

import (
	"fmt"

	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/state"
	"github.com/dns3l/dns3l-core/test/apiv1"
	testauth "github.com/dns3l/dns3l-core/test/auth"
	"github.com/dns3l/dns3l-core/test/comp"
	testhttp "github.com/dns3l/dns3l-core/test/http"
)

func RunDBFull(testconfig, caid string, domain string, truncate bool) {

	comptest := comp.ComponentTest{
		TestConfig: testconfig,
		StubUsers: map[string]testauth.AuthStubUser{
			"alice": {
				Name:  "Alice Doe",
				Email: "alice@example.com",
				DomainsAllowed: []string{
					"sub1." + domain,
					"sub2." + domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"bob": {
				Name:  "Bob Doe",
				Email: "bob@example.com",
				DomainsAllowed: []string{
					"sub1." + domain,
					"bar.sub2." + domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"clara": {
				Name:  "Clara Doe",
				Email: "clara@example.com",
				DomainsAllowed: []string{
					"bar.sub1." + domain,
					"sub2." + domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"kilgore": {
				Name:  "Kilgore Trout",
				Email: "ktrout@example.com",
				DomainsAllowed: []string{
					"sub1." + domain,
					"sub2." + domain,
				},
				WriteAllowed: false,
				ReadAllowed:  true,
			},
		},
	}

	err := comptest.Exec(func(srv *service.Service) error {

		if truncate {
			err := state.Truncate(srv.Config.DB)
			if err != nil {
				return err
			}
		}
		testhttp.AssertSuccess("Create key 1", apiv1.CreateKey(srv, caid, "alice",
			"foo.bar.sub1."+domain, []string{
				"alt.foo.bar.sub1." + domain,
				"alt2.foo.bar.sub2." + domain,
			}))

		testhttp.AssertSuccess("Create key 2", apiv1.CreateKey(srv, caid, "alice",
			"foo.bar.sub2."+domain, []string{
				"alt.foo.bar.sub2." + domain,
				"alt2.foo.bar.sub1." + domain,
			}))

		testhttp.AssertSuccess("Create key 3", apiv1.CreateKey(srv, caid, "bob",
			"test1.bar.sub1."+domain, []string{
				"alt.test1.1337.sub1." + domain,
				"alt2.test1.1337.sub1." + domain,
			}))

		testhttp.AssertSuccess("Create key 3 bogus2", apiv1.CreateKey(srv, "bogus2", "bob",
			"test1.bar.sub1."+domain, []string{
				"alt.test1.1337.sub1." + domain,
				"alt2.test1.1337.sub1." + domain,
			}))

		testhttp.AssertSuccess("Create key 4", apiv1.CreateKey(srv, caid, "bob",
			"test1.1337.sub1."+domain, []string{
				"alt.test1.1337.sub1." + domain,
				"alt2.test1.bar.sub2." + domain,
			}))

		testhttp.AssertSuccess("Create key 5", apiv1.CreateKey(srv, caid, "alice",
			"test2.bar.sub2."+domain, []string{
				"alt.foo.1337.sub2." + domain,
				"alt2.foo.bar.sub1." + domain,
			}))

		// testhttp.AssertStatusCode("Create key 6", 500,
		// 	apiv1.CreateKey(srv, caid, "bob",
		// 		"test2.bar.sub2."+domain, []string{
		// 			"alt.foo.bar.sub2." + domain,
		// 			"alt2.foo.bar.sub1." + domain,
		// 		}))

		testhttp.AssertStatusCode("Create key 6", 403,
			apiv1.CreateKey(srv, caid, "bob",
				"test3.bar.sub2."+domain, []string{
					"alt.foo.1337.sub2." + domain,
					"alt2.foo.bar.sub1." + domain,
				}))

		fmt.Println(testhttp.AssertSuccess("List keys",
			apiv1.ListKeys(srv, caid, "kilgore")))

		fmt.Println(testhttp.AssertSuccess("List keys restricted",
			apiv1.ListKeys(srv, caid, "clara"))) //key 4 should not be seen

		fmt.Println(testhttp.AssertSuccess("List all keys",
			apiv1.ListAllKeys(srv, "kilgore")))

		fmt.Println(testhttp.AssertSuccess("List key all CA",
			apiv1.ListKeyAllCA(srv, "kilgore", "test1.bar.sub1."+domain)))

		// These are the accesses that require checking all SANs for security
		fmt.Println(testhttp.AssertSuccess("Get key 3 by alice",
			apiv1.GetCertResources(srv, caid, "alice", "test1.bar.sub1."+domain)))
		fmt.Println(testhttp.AssertSuccess("Get key 3 PEM key by alice",
			apiv1.GetCertResource(srv, caid, "alice", "test1.bar.sub1."+domain, "key")))
		testhttp.AssertStatusCode("Get key 3 by clara", 403,
			apiv1.GetCertResources(srv, caid, "clara", "test1.bar.sub1."+domain))
		testhttp.AssertStatusCode("Get key 3 PEM cert by clara", 403,
			apiv1.GetCertResource(srv, caid, "clara", "test1.bar.sub1."+domain, "crt"))
		testhttp.AssertStatusCode("Get key 5 by bob", 403,
			apiv1.GetCertResources(srv, caid, "bob", "test2.bar.sub2."+domain))
		testhttp.AssertStatusCode("Get key 5 PEM key by bob", 403,
			apiv1.GetCertResource(srv, caid, "bob", "test2.bar.sub2."+domain, "key"))

		// Key deletion only requires check for first domain name
		testhttp.AssertSuccess("Delete key 2",
			apiv1.DeleteKeyById(srv, caid, "bob", "foo.bar.sub2."+domain))
		testhttp.AssertStatusCode("Get key by ID 2", 404,
			apiv1.GetKeyById(srv, caid, "kilgore", "foo.bar.sub2."+domain))
		testhttp.AssertStatusCode("Delete key 3 by kilgore", 403,
			apiv1.DeleteKeyById(srv, caid, "kilgore", "test1.bar.sub1."+domain))
		testhttp.AssertStatusCode("Delete key 5 by bob", 403,
			apiv1.DeleteKeyById(srv, caid, "bob", "test1.1337.sub2."+domain))

		log.Info("All tests succeeded.")

		return nil
	})
	if err != nil {
		panic(err)
	}

}
