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

func RunDBFull(testconfig, caid, domain string, truncate bool, replicaOffset, numReplicas uint, dump bool) {

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
			"fquux": {
				Name:  "Frank Quux",
				Email: "fquux@example.com",
				DomainsAllowed: []string{
					"sub5." + domain,
				},
				WriteAllowed:         false,
				ReadAllowed:          true,
				ReadAnyPublicAllowed: true,
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

		for i := replicaOffset; i < numReplicas; i++ {

			prefix := fmt.Sprintf("node%d", i)

			testhttp.AssertSuccess("Create key 1", apiv1.CreateKey(srv, caid, "alice",
				prefix+".foo.bar.sub1."+domain, []string{
					prefix + ".alt.foo.bar.sub1." + domain,
					prefix + ".alt2.foo.bar.sub2." + domain,
				}))

			testhttp.AssertSuccess("Create key 2", apiv1.CreateKey(srv, caid, "alice",
				prefix+".foo.bar.sub2."+domain, []string{
					prefix + ".alt.foo.bar.sub2." + domain,
					prefix + ".alt2.foo.bar.sub1." + domain,
				}))

			testhttp.AssertSuccess("Create key 3", apiv1.CreateKey(srv, caid, "bob",
				prefix+".test1.bar.sub1."+domain, []string{
					prefix + ".alt.test1.1337.sub1." + domain,
					prefix + ".alt2.test1.1337.sub1." + domain,
				}))

			testhttp.AssertSuccess("Create key 3 bogus2", apiv1.CreateKey(srv, "bogus2", "bob",
				prefix+".test1.bar.sub1."+domain, []string{
					prefix + ".alt.test1.1337.sub1." + domain,
					prefix + ".alt2.test1.1337.sub1." + domain,
				}))

			testhttp.AssertSuccess("Create key 4", apiv1.CreateKey(srv, caid, "bob",
				prefix+".test1.1337.sub1."+domain, []string{
					prefix + ".alt.test1.1337.sub1." + domain,
					prefix + ".alt2.test1.bar.sub2." + domain,
				}))

			testhttp.AssertSuccess("Create key 5", apiv1.CreateKey(srv, caid, "alice",
				prefix+".test2.bar.sub2."+domain, []string{
					prefix + ".alt.foo.1337.sub2." + domain,
					prefix + ".alt2.foo.bar.sub1." + domain,
				}))

			// testhttp.AssertStatusCode("Create key 6", 500,
			// 	apiv1.CreateKey(srv, caid, "bob",
			// 		"test2.bar.sub2."+domain, []string{
			// 			"alt.foo.bar.sub2." + domain,
			// 			"alt2.foo.bar.sub1." + domain,
			// 		}))

			testhttp.AssertStatusCode("Create key 6", 403,
				apiv1.CreateKey(srv, caid, "bob",
					prefix+".test3.bar.sub2."+domain, []string{
						prefix + ".alt.foo.1337.sub2." + domain,
						prefix + ".alt2.foo.bar.sub1." + domain,
					}))

			out := testhttp.AssertSuccess("List keys",
				apiv1.ListKeys(srv, caid, "kilgore"))

			if dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys: %d keys returned.", apiv1.CountJSONArray(out))

			out = testhttp.AssertSuccess("List keys restricted",
				apiv1.ListKeys(srv, caid, "clara")) //key 4 should not be seen

			if dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys restricted: %d keys returned.", apiv1.CountJSONArray(out))

			out = testhttp.AssertSuccess("List keys publicly readable",
				apiv1.ListKeys(srv, caid, "fquux"))

			if dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys publicly readable: %d keys returned.", apiv1.CountJSONArray(out))

			out = testhttp.AssertSuccess("List all keys",
				apiv1.ListAllKeys(srv, "kilgore"))

			if dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("List key all CA",
				apiv1.ListKeyAllCA(srv, "kilgore", prefix+".test1.bar.sub1."+domain))

			if dump {
				fmt.Println(out)
			}

			// These are the accesses that require checking all SANs for security
			out = testhttp.AssertSuccess("Get key 3 by alice",
				apiv1.GetCertResources(srv, caid, "alice", prefix+".test1.bar.sub1."+domain))
			if dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("Get key 3 PEM key by alice",
				apiv1.GetCertResource(srv, caid, "alice", prefix+".test1.bar.sub1."+domain, "key"))
			out2 := testhttp.AssertSuccess("Get key 3 PEM fullchain by alice",
				apiv1.GetCertResource(srv, caid, "alice", prefix+".test1.bar.sub1."+domain, "fullchain"))
			out3 := testhttp.AssertSuccess("Get key 3 PEM root by alice",
				apiv1.GetCertResource(srv, caid, "alice", prefix+".test1.bar.sub1."+domain, "root"))
			if dump {
				fmt.Println("key", out)
			}
			fmt.Println("fullchain", out2)
			fmt.Println("root", out3)

			testhttp.AssertStatusCode("Get key 3 by clara", 403,
				apiv1.GetCertResources(srv, caid, "clara", prefix+".test1.bar.sub1."+domain))
			testhttp.AssertStatusCode("Get key 3 PEM cert by clara", 403,
				apiv1.GetCertResource(srv, caid, "clara", prefix+".test1.bar.sub1."+domain, "crt"))
			testhttp.AssertStatusCode("Get key 5 by bob", 403,
				apiv1.GetCertResources(srv, caid, "bob", prefix+".test2.bar.sub2."+domain))
			testhttp.AssertStatusCode("Get key 5 PEM key by bob", 403,
				apiv1.GetCertResource(srv, caid, "bob", prefix+".test2.bar.sub2."+domain, "key"))

			// Accessing publicly available things
			testhttp.AssertSuccess("Get key 3 PEM root by fquux",
				apiv1.GetCertResource(srv, caid, "fquux", prefix+".test1.bar.sub1."+domain, "root"))
			testhttp.AssertStatusCode("Get key 3 PEM key by fquux", 403,
				apiv1.GetCertResource(srv, caid, "fquux", prefix+".test1.bar.sub1."+domain, "key"))
			testhttp.AssertStatusCode("Get key 3 PEM all by fquux", 403,
				apiv1.GetCertResources(srv, caid, "fquux", prefix+".test1.bar.sub1."+domain))

			// Key deletion only requires check for first domain name
			testhttp.AssertSuccess("Delete key 2",
				apiv1.DeleteKeyById(srv, caid, "bob", prefix+".foo.bar.sub2."+domain))
			testhttp.AssertStatusCode("Get key by ID 2", 404,
				apiv1.GetKeyById(srv, caid, "kilgore", prefix+".foo.bar.sub2."+domain))
			testhttp.AssertStatusCode("Delete key 3 by kilgore", 403,
				apiv1.DeleteKeyById(srv, caid, "kilgore", prefix+".test1.bar.sub1."+domain))
			testhttp.AssertStatusCode("Delete key 5 by bob", 403,
				apiv1.DeleteKeyById(srv, caid, "bob", prefix+".test1.1337.sub2."+domain))

		}

		testStateClean(srv.Config.DB)

		log.Info("All tests succeeded.")

		return nil
	})
	if err != nil {
		panic(err)
	}

}

func testStateClean(dbProvider *state.SQLDBProviderDefault) {

	dbtype := dbProvider.GetType()

	if dbProvider.GetType() == "mysql" {

		stats, err := dbProvider.GetStats()
		if err != nil {
			panic(err)
		}

		log.Infof("DB stats after execution: InUse=%d, Idle=%d, OpenConnections=%d",
			stats.InUse,
			stats.Idle,
			stats.OpenConnections)

	} else {
		log.Warnf("Clean state test executed for an unknown SQL provider, no checks "+
			"implemented for '%s'", dbtype)
	}

}
