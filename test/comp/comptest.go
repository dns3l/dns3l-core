package comp

import (
	"path/filepath"

	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/state"
	testauth "github.com/dns3l/dns3l-core/test/auth"
	"github.com/dns3l/dns3l-core/test/mariadb"
	"github.com/dns3l/dns3l-core/util"
)

const MariaDB_Port = 15234

type ComponentTest struct {
	StubUsers map[string]testauth.AuthStubUser
}

func (c *ComponentTest) Exec(testfn func(*service.Service) error) error {
	mdb := mariadb.MariaDBController{
		Port: MariaDB_Port,
	}
	err := mdb.Start()
	if err != nil {
		return err
	}
	defer func() {
		util.LogDefer(log, mdb.Stop())
	}()

	conf, err := c.prepareTestConfig()
	if err != nil {
		return err
	}

	err = state.CreateSQLTables(conf.DB, true)
	if err != nil {
		return err
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
	defer func() {
		util.LogDefer(log, srv.Stop())
	}()

	return testfn(&srv)

}

func (c *ComponentTest) prepareTestConfig() (*service.Config, error) {

	confTemplate := filepath.Join(util.GetExecDir(), "test", "config-comptest.yaml")

	conf := &service.Config{}
	err := conf.FromFile(confTemplate)
	if err != nil {
		return nil, err
	}

	//Patch config to insert our AuthStub
	conf.Auth.Provider = &testauth.AuthStub{
		TestUsers: c.StubUsers,
	}

	err = conf.Initialize()
	if err != nil {
		return nil, err
	}

	return conf, nil

}
