package runs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dns3l/dns3l-core/renew"
	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/state"
	"github.com/dns3l/dns3l-core/test/apiv1"
	testauth "github.com/dns3l/dns3l-core/test/auth"
	"github.com/dns3l/dns3l-core/test/comp"
	testhttp "github.com/dns3l/dns3l-core/test/http"
)

func (t *TestRunner) RunDBFull() {

	comptest := comp.ComponentTest{
		TestConfig: t.TestConfig,
		StubUsers: map[string]testauth.AuthStubUser{
			"alice": {
				Name:  "Alice Doe",
				Email: "alice@example.com",
				DomainsAllowed: []string{
					"sub1." + t.Domain,
					"sub2." + t.Domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"bob": {
				Name:  "Bob Doe",
				Email: "bob@example.com",
				DomainsAllowed: []string{
					"sub1." + t.Domain,
					"bar.sub2." + t.Domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"clara": {
				Name:  "Clara Doe",
				Email: "clara@example.com",
				DomainsAllowed: []string{
					"bar.sub1." + t.Domain,
					"sub2." + t.Domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"kilgore": {
				Name:  "Kilgore Trout",
				Email: "ktrout@example.com",
				DomainsAllowed: []string{
					"sub1." + t.Domain,
					"sub2." + t.Domain,
				},
				WriteAllowed: false,
				ReadAllowed:  true,
			},
			"fquux": {
				Name:  "Frank Quux",
				Email: "fquux@example.com",
				DomainsAllowed: []string{
					"sub5." + t.Domain,
				},
				WriteAllowed:         false,
				ReadAllowed:          true,
				ReadAnyPublicAllowed: true,
			},
		},
	}

	err := comptest.Exec(func(srv *service.Service) error {

		if t.Truncate {
			err := state.Truncate(srv.Config.DB)
			if err != nil {
				return err
			}
		}

		for i := t.ReplicaOffset; i < t.NumReplicas; i++ {

			prefix := fmt.Sprintf("node%d", i)

			testhttp.AssertSuccess("Create key 1", apiv1.CreateKey(srv, t.CAID, "alice",
				prefix+".foo.bar.sub1."+t.Domain, []string{
					prefix + ".alt.foo.bar.sub1." + t.Domain,
					prefix + ".alt2.foo.bar.sub2." + t.Domain,
				}))

			testhttp.AssertSuccess("Create key 2", apiv1.CreateKey(srv, t.CAID, "alice",
				prefix+".foo.bar.sub2."+t.Domain, []string{
					prefix + ".alt.foo.bar.sub2." + t.Domain,
					prefix + ".alt2.foo.bar.sub1." + t.Domain,
				}))

			testhttp.AssertSuccess("Create key 3", apiv1.CreateKey(srv, t.CAID, "bob",
				prefix+".test1.bar.sub1."+t.Domain, []string{
					prefix + ".alt.test1.1337.sub1." + t.Domain,
					prefix + ".alt2.test1.1337.sub1." + t.Domain,
				}))

			testhttp.AssertSuccess("Create key 3 bogus2", apiv1.CreateKey(srv, "bogus2", "bob",
				prefix+".test1.bar.sub1."+t.Domain, []string{
					prefix + ".alt.test1.1337.sub1." + t.Domain,
					prefix + ".alt2.test1.1337.sub1." + t.Domain,
				}))

			testhttp.AssertSuccess("Create key 4", apiv1.CreateKey(srv, t.CAID, "bob",
				prefix+".test1.1337.sub1."+t.Domain, []string{
					prefix + ".alt.test1.1337.sub1." + t.Domain,
					prefix + ".alt2.test1.bar.sub2." + t.Domain,
				}))

			testhttp.AssertSuccess("Create key 5", apiv1.CreateKey(srv, t.CAID, "alice",
				prefix+".test2.bar.sub2."+t.Domain, []string{
					prefix + ".alt.foo.1337.sub2." + t.Domain,
					prefix + ".alt2.foo.bar.sub1." + t.Domain,
				}))

			testhttp.AssertSuccess("Create key 6 with custom TTL",
				apiv1.CreateKeyExtended(srv, t.CAID, "alice",
					prefix+".test3.bar.sub2."+t.Domain, []string{
						prefix + ".alt.foo.1337.sub2." + t.Domain,
						prefix + ".alt2.foo.bar.sub1." + t.Domain,
					}, 82))

			testhttp.AssertStatusCode("Create key 6 with too long TTL", 400,
				apiv1.CreateKeyExtended(srv, t.CAID, "alice",
					prefix+".test4.bar.sub2."+t.Domain, []string{
						prefix + ".alt.foo.1337.sub2." + t.Domain,
						prefix + ".alt2.foo.bar.sub1." + t.Domain,
					}, 100))

			testhttp.AssertStatusCode("Create key 6 with too short TTL", 400,
				apiv1.CreateKeyExtended(srv, t.CAID, "alice",
					prefix+".test4.bar.sub2."+t.Domain, []string{
						prefix + ".alt.foo.1337.sub2." + t.Domain,
						prefix + ".alt2.foo.bar.sub1." + t.Domain,
					}, 3))

			// testhttp.AssertStatusCode("Create key 6", 500,
			// 	apiv1.CreateKey(srv, t.CAID, "bob",
			// 		"test2.bar.sub2."+t.Domain, []string{
			// 			"alt.foo.bar.sub2." + t.Domain,
			// 			"alt2.foo.bar.sub1." + t.Domain,
			// 		}))

			testhttp.AssertStatusCode("Create key 6", 403,
				apiv1.CreateKey(srv, t.CAID, "bob",
					prefix+".test3.bar.sub2."+t.Domain, []string{
						prefix + ".alt.foo.1337.sub2." + t.Domain,
						prefix + ".alt2.foo.bar.sub1." + t.Domain,
					}))

			out := testhttp.AssertSuccess("List keys",
				apiv1.ListKeys(srv, t.CAID, "kilgore"))

			if t.Dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys: %d keys returned.\n", apiv1.CountJSONArray(out))

			out = testhttp.AssertSuccess("List keys restricted",
				apiv1.ListKeys(srv, t.CAID, "clara")) //key 4 should not be seen

			if t.Dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys restricted: %d keys returned.\n", apiv1.CountJSONArray(out))

			out = testhttp.AssertSuccess("List keys publicly readable",
				apiv1.ListKeys(srv, t.CAID, "fquux"))

			if t.Dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys publicly readable: %d keys returned.\n", apiv1.CountJSONArray(out))

			out = testhttp.AssertSuccess("List all keys",
				apiv1.ListAllKeys(srv, "kilgore"))

			if t.Dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("List key all CA",
				apiv1.ListKeyAllCA(srv, "kilgore", prefix+".test1.bar.sub1."+t.Domain))

			if t.Dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("Get key 3 info by alice",
				apiv1.GetKeyById(srv, t.CAID, "alice", prefix+".test1.bar.sub1."+t.Domain))
			if t.Dump {
				fmt.Println(out)
			}

			// These are the accesses that require checking all SANs for security
			out = testhttp.AssertSuccess("Get key 3 by alice",
				apiv1.GetCertResources(srv, t.CAID, "alice", prefix+".test1.bar.sub1."+t.Domain))
			if t.Dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("Get key 3 PEM key by alice",
				apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".test1.bar.sub1."+t.Domain, "key"))
			out2 := testhttp.AssertSuccess("Get key 3 PEM fullchain by alice",
				apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".test1.bar.sub1."+t.Domain, "fullchain"))
			out3 := testhttp.AssertSuccess("Get key 3 PEM root by alice",
				apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".test1.bar.sub1."+t.Domain, "root"))
			if t.Dump {
				fmt.Println("key", out)
				fmt.Println("fullchain", out2)
				fmt.Println("root", out3)
			}

			testhttp.AssertStatusCode("Get key 3 by clara", 403,
				apiv1.GetCertResources(srv, t.CAID, "clara", prefix+".test1.bar.sub1."+t.Domain))
			testhttp.AssertStatusCode("Get key 3 PEM cert by clara", 403,
				apiv1.GetCertResource(srv, t.CAID, "clara", prefix+".test1.bar.sub1."+t.Domain, "crt"))
			testhttp.AssertStatusCode("Get key 5 by bob", 403,
				apiv1.GetCertResources(srv, t.CAID, "bob", prefix+".test2.bar.sub2."+t.Domain))
			testhttp.AssertStatusCode("Get key 5 PEM key by bob", 403,
				apiv1.GetCertResource(srv, t.CAID, "bob", prefix+".test2.bar.sub2."+t.Domain, "key"))

			// Accessing publicly available things
			testhttp.AssertSuccess("Get key 4 info by fquux",
				apiv1.GetKeyById(srv, t.CAID, "fquux", prefix+".test1.bar.sub1."+t.Domain))
			testhttp.AssertSuccess("Get key 3 PEM root by fquux",
				apiv1.GetCertResource(srv, t.CAID, "fquux", prefix+".test1.bar.sub1."+t.Domain, "root"))
			testhttp.AssertStatusCode("Get key 3 PEM key by fquux", 403,
				apiv1.GetCertResource(srv, t.CAID, "fquux", prefix+".test1.bar.sub1."+t.Domain, "key"))
			testhttp.AssertStatusCode("Get key 3 PEM all by fquux", 403,
				apiv1.GetCertResources(srv, t.CAID, "fquux", prefix+".test1.bar.sub1."+t.Domain))

			// Key deletion only requires check for first t.Domain name
			testhttp.AssertSuccess("Delete key 2",
				apiv1.DeleteKeyById(srv, t.CAID, "bob", prefix+".foo.bar.sub2."+t.Domain))
			testhttp.AssertStatusCode("Get key by ID 2", 404,
				apiv1.GetKeyById(srv, t.CAID, "kilgore", prefix+".foo.bar.sub2."+t.Domain))
			testhttp.AssertStatusCode("Delete key 3 by kilgore", 403,
				apiv1.DeleteKeyById(srv, t.CAID, "kilgore", prefix+".test1.bar.sub1."+t.Domain))
			testhttp.AssertStatusCode("Delete key 5 by bob", 403,
				apiv1.DeleteKeyById(srv, t.CAID, "bob", prefix+".test1.1337.sub2."+t.Domain))

		}

		// Testing domain name equals permissions filter

		testhttp.AssertSuccess("Create key 0", apiv1.CreateKey(srv, t.CAID, "bob",
			"bar.sub2."+t.Domain, []string{}))

		testhttp.AssertSuccess("Create key 0.1", apiv1.CreateKey(srv, t.CAID, "bob",
			"footest.bar.sub2."+t.Domain, []string{}))

		out := testhttp.AssertSuccess("List all keys visible for Bob",
			apiv1.ListAllKeys(srv, "alice"))
		assertContainsKey(out, "bar.sub2."+t.Domain)
		assertContainsKey(out, "footest.bar.sub2."+t.Domain)

		testhttp.AssertSuccess("Delete key 0",
			apiv1.DeleteKeyById(srv, t.CAID, "bob", "bar.sub2."+t.Domain))

		testhttp.AssertSuccess("Delete key 0.1",
			apiv1.DeleteKeyById(srv, t.CAID, "bob", "footest.bar.sub2."+t.Domain))

		testStateClean(srv.Config.DB)

		now := time.Now()
		err := srv.Config.CA.Functions.PutLastRenewSummary(
			&renew.ServerInfoRenewal{LastRun: &now, Successful: 3, Failed: 4})
		if err != nil {
			panic(err)
		}

		renewalsum, err := srv.Config.CA.Functions.GetLastRenewSummary()
		if err != nil {
			panic(err)
		}
		fmt.Println(renewalsum)

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

func assertContainsKey(output, keyname string) {
	var data []map[string]interface{}
	err := json.Unmarshal([]byte(output), &data)
	if err != nil {
		panic(err)
	}

	for _, elem := range data {

		name, exists := elem["name"]
		if !exists {
			continue
		}
		if name != keyname {
			continue
		}

		return

	}

	panic(fmt.Sprintf("could not find %s key in output", keyname))
}
