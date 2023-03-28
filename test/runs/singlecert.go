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

func (t *TestRunner) RunSingleEntry() {

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
					"bar.sub2." + t.Domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
		},
		WithACME: t.WithACME,
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

			out := testhttp.AssertSuccess("List keys",
				apiv1.ListKeys(srv, t.CAID, "alice"))

			if t.Dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("List all keys",
				apiv1.ListAllKeys(srv, "alice"))

			if t.Dump {
				fmt.Println(out)
			}

			out = testhttp.AssertSuccess("List key all CA",
				apiv1.ListKeyAllCA(srv, "alice", prefix+".foo.bar.sub1."+t.Domain))

			if t.Dump {
				fmt.Println(out)
			}

			{
				// These are the accesses that require checking all SANs for security
				resstr := testhttp.AssertSuccess("Get key 1 by alice",
					apiv1.GetCertResources(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain))
				if t.Dump {
					fmt.Println(out)
				}
				res := srvapiv1.CertResources{}
				fromJson(&res, resstr)

				key := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain, "key"))
				crt := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain, "crt"))
				fullchain := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain, "fullchain"))
				root := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain, "root"))
				rootchain := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain, "rootchain"))
				chain := testhttp.AssertSuccess("Get key 1 PEM key by alice",
					apiv1.GetCertResource(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain, "chain"))
				if t.Dump {
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
				if t.CheckIntermediate && res.Chain == "" {
					panic("chain is empty string")
				}
				assertEqual(res.Chain, chain)

			}

			testhttp.AssertStatusCode("Get key 1 by bob", 403,
				apiv1.GetCertResources(srv, t.CAID, "bob", prefix+".foo.bar.sub1."+t.Domain))
			testhttp.AssertStatusCode("Get key 1 PEM cert by bob", 403,
				apiv1.GetCertResource(srv, t.CAID, "bob", prefix+".foo.bar.sub1."+t.Domain, "crt"))
			testhttp.AssertStatusCode("Get key 1 key by bob", 403,
				apiv1.GetCertResource(srv, t.CAID, "bob", prefix+".foo.bar.sub1."+t.Domain, "key"))

			// Key deletion only requires check for first  t.Domain name

			testhttp.AssertStatusCode("Delete key 1 by bob", 403,
				apiv1.DeleteKeyById(srv, t.CAID, "bob", prefix+".foo.bar.sub1."+t.Domain))
			testhttp.AssertSuccess("Delete key 1 by bob",
				apiv1.DeleteKeyById(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain))
			testhttp.AssertStatusCode("Get key 1 by alice", 404,
				apiv1.GetKeyById(srv, t.CAID, "alice", prefix+".foo.bar.sub1."+t.Domain))

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
