package comp

import (
	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/state"
	testauth "github.com/dns3l/dns3l-core/test/auth"
	"github.com/dns3l/dns3l-core/test/mariadb"
	"github.com/dns3l/dns3l-core/test/step"
	"github.com/dns3l/dns3l-core/util"
)

const MariaDB_Port = 15234
const StepCA_Port = 8081

// Generic component test mini-framework
type ComponentTest struct {
	TestConfig string
	StubUsers  map[string]testauth.AuthStubUser
	WithACME   bool
}

func (c *ComponentTest) Exec(testfn func(*service.Service) error) error {
	mdb := mariadb.MariaDBController{
		Port: MariaDB_Port,
	}
	err := mdb.Start()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, mdb.Stop)

	conf, err := c.prepareTestConfig(&mdb)
	if err != nil {
		return err
	}

	err = conf.DB.Init()
	if err != nil {
		return err
	}

	err = state.CreateSQLTables(conf.DB, true)
	if err != nil {
		return err
	}

	if c.WithACME {
		acme := step.StepCAController{
			Port: StepCA_Port,
		}
		err = acme.Start()
		if err != nil {
			return err
		}
		defer util.LogDefer(log, acme.Stop)
	}

	srv := service.Service{
		Config:  conf,
		Socket:  ":8080",
		NoRenew: true,
	}

	err = srv.RunAsync()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, srv.Stop)

	return testfn(&srv)

}

func (c *ComponentTest) prepareTestConfig(mdb *mariadb.MariaDBController) (*service.Config, error) {

	confTemplate := c.TestConfig

	conf := &service.Config{}
	err := conf.FromFile(confTemplate)
	if err != nil {
		return nil, err
	}

	//Patch config to insert our AuthStub
	conf.Auth.Provider = &testauth.AuthStub{
		TestUsers: c.StubUsers,
	}

	//Patch database URL to the one of the MariaDB stub
	conf.DB.URL, err = mdb.GetUnixSockURL("")
	if err != nil {
		return nil, err
	}

	log.Debugf("DB URL set to '%s'", conf.DB.URL)

	err = conf.Initialize()
	if err != nil {
		return nil, err
	}

	return conf, nil

}
