package runs

import (
	"encoding/json"
	"fmt"

	"github.com/dns3l/dns3l-core/service"
	srvapiv1 "github.com/dns3l/dns3l-core/service/apiv1"
	"github.com/dns3l/dns3l-core/state"
	"github.com/dns3l/dns3l-core/test/apiv1"
	testauth "github.com/dns3l/dns3l-core/test/auth"
	"github.com/dns3l/dns3l-core/test/comp"
	testhttp "github.com/dns3l/dns3l-core/test/http"
)

func RunSingleEntry(testconfig, caid, domain string, truncate bool, replicaOffset, numReplicas uint, dump bool) {

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
					"bar.sub2." + domain,
				},
				WriteAllowed: true,
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

		for i := replicaOffset; i < numReplicas; i++ {

			prefix := fmt.Sprintf("node%d", i)

			testhttp.AssertSuccess("Create key 1", apiv1.CreateKey(srv, caid, "alice",
				prefix+".foo.bar.sub1."+domain, []string{
					prefix + ".alt.foo.bar.sub1." + domain,
					prefix + ".alt2.foo.bar.sub2." + domain,
				}))

			out := testhttp.AssertSuccess("List keys",
				apiv1.ListKeys(srv, caid, "alice"))

			if dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("List all keys",
				apiv1.ListAllKeys(srv, "alice"))

			if dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("List key all CA",
				apiv1.ListKeyAllCA(srv, "alice", prefix+".foo.bar.sub1."+domain))

			if dump {
				fmt.Println(out)
			}

			{
				// These are the accesses that require checking all SANs for security
				resstr := testhttp.AssertSuccess("Get key 1 by alice",
					apiv1.GetCertResources(srv, caid, "alice", prefix+".foo.bar.sub1."+domain))
				if dump {
					fmt.Println(out)
				}
				res := srvapiv1.CertResources{}
				fromJson(&res, resstr)

				key := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, caid, "alice", prefix+".foo.bar.sub1."+domain, "key"))
				crt := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, caid, "alice", prefix+".foo.bar.sub1."+domain, "crt"))
				fullchain := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, caid, "alice", prefix+".foo.bar.sub1."+domain, "fullchain"))
				root := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, caid, "alice", prefix+".foo.bar.sub1."+domain, "root"))
				rootchain := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, caid, "alice", prefix+".foo.bar.sub1."+domain, "rootchain"))
				chain := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, caid, "alice", prefix+".foo.bar.sub1."+domain, "chain"))
				if dump {
					fmt.Println("key", key)
					fmt.Println("crt", crt)
					fmt.Println("fullchain", fullchain)
					fmt.Println("root", root)
					fmt.Println("rootchain", rootchain)
					fmt.Println("chain", chain)
				}

				assertEqual(res.Key, key)
				assertEqual(res.Certificate, crt)
				assertEqual(res.FullChain, fullchain)
				if res.Root == "" {
					panic("root cert is empty string")
				}
				assertEqual(res.Root, root)
				assertEqual(res.RootChain, rootchain)
				if res.Chain == "" {
					panic("chain is empty string")
				}
				assertEqual(res.Chain, chain)

			}

			testhttp.AssertStatusCode("Get key 1 by bob", 403,
				apiv1.GetCertResources(srv, caid, "bob", prefix+".foo.bar.sub1."+domain))
			testhttp.AssertStatusCode("Get key 1 PEM cert by bob", 403,
				apiv1.GetCertResource(srv, caid, "bob", prefix+".foo.bar.sub1."+domain, "crt"))
			testhttp.AssertStatusCode("Get key 1 key by bob", 403,
				apiv1.GetCertResource(srv, caid, "bob", prefix+".foo.bar.sub1."+domain, "key"))

			// Key deletion only requires check for first domain name

			testhttp.AssertStatusCode("Delete key 1 by bob", 403,
				apiv1.DeleteKeyById(srv, caid, "bob", prefix+".foo.bar.sub1."+domain))
			testhttp.AssertSuccess("Delete key 1 by bob",
				apiv1.DeleteKeyById(srv, caid, "alice", prefix+".foo.bar.sub1."+domain))
			testhttp.AssertStatusCode("Get key 1 by alice", 404,
				apiv1.GetKeyById(srv, caid, "alice", prefix+".foo.bar.sub1."+domain))

		}

		testStateClean(srv.Config.DB)

		log.Info("All tests succeeded.")

		return nil
	})
	if err != nil {
		panic(err)
	}

}

func assertEqual(expected, actual string) {

	if expected != actual {
		panic(fmt.Errorf("Expected '%s', but got '%s'", expected, actual))
	}

}

func fromJson(strct interface{}, input string) {

	err := json.Unmarshal([]byte(input), strct)
	if err != nil {
		panic(err)
	}

}
