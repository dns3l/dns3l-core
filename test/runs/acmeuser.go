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

func (t *TestRunner) RunACMEUsers() {

	comptest := comp.ComponentTest{
		TestConfig: t.TestConfig,
		StubUsers: map[string]testauth.AuthStubUser{
			"alice": {
				Name:  "Alice Doe",
				Email: "alice@example.com",
				DomainsAllowed: []string{
					t.Domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"bob": {
				Name:  "Bob Doe",
				Email: "bob@example.com",
				DomainsAllowed: []string{
					t.Domain,
				},
				WriteAllowed: true,
				ReadAllowed:  true,
			},
			"clara": {
				Name:  "Clara Doe",
				Email: "clara@example.com",
				DomainsAllowed: []string{
					t.Domain,
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

			prefix := "host"
			suffix := "sub1." + t.Domain

			testhttp.AssertSuccess("Create key 1", apiv1.CreateKey(srv, t.CAID, "alice",
				prefix+".foo1."+suffix, []string{}))

			testhttp.AssertSuccess("Create key 2", apiv1.CreateKey(srv, t.CAID, "bob",
				prefix+".bar1."+suffix, []string{}))

			testhttp.AssertSuccess("Create key 3", apiv1.CreateKey(srv, t.CAID, "clara",
				prefix+".baz1."+suffix, []string{}))

			testhttp.AssertSuccess("Create key 10", apiv1.CreateKey(srv, t.CAID, "alice",
				prefix+".foo2."+suffix, []string{}))

			testhttp.AssertSuccess("Create key 11", apiv1.CreateKey(srv, t.CAID, "bob",
				prefix+".bar2."+suffix, []string{}))

			testhttp.AssertSuccess("Create key 12", apiv1.CreateKey(srv, t.CAID, "clara",
				prefix+".baz2."+suffix, []string{}))

			testhttp.AssertSuccess("Create key 20", apiv1.CreateKey(srv, t.CAID, "alice",
				prefix+".foo3."+suffix, []string{}))

			out := testhttp.AssertSuccess("List keys",
				apiv1.ListKeys(srv, t.CAID, "clara"))

			if t.Dump {
				fmt.Println(out)
			}
			fmt.Printf("List keys: %d keys returned.\n", apiv1.CountJSONArray(out))

			testhttp.AssertSuccess("Delete key 1",
				apiv1.DeleteKeyById(srv, t.CAID, "alice", prefix+".foo1."+suffix))
			testhttp.AssertSuccess("Delete key 2",
				apiv1.DeleteKeyById(srv, t.CAID, "alice", prefix+".bar1."+suffix))
			testhttp.AssertSuccess("Delete key 3",
				apiv1.DeleteKeyById(srv, t.CAID, "alice", prefix+".baz1."+suffix))

			testhttp.AssertSuccess("Delete key 10",
				apiv1.DeleteKeyById(srv, t.CAID, "bob", prefix+".foo2."+suffix))
			testhttp.AssertSuccess("Delete key 11",
				apiv1.DeleteKeyById(srv, t.CAID, "bob", prefix+".bar2."+suffix))
			testhttp.AssertSuccess("Delete key 12",
				apiv1.DeleteKeyById(srv, t.CAID, "bob", prefix+".baz2."+suffix))

			testhttp.AssertSuccess("Delete key 20",
				apiv1.DeleteKeyById(srv, t.CAID, "clara", prefix+".foo3."+suffix))

		}

		log.Info("All tests succeeded.")

		return nil
	})
	if err != nil {
		panic(err)
	}

}
