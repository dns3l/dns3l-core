package dns

import (
	"math/rand"
	"net"
	"testing"

	"github.com/dta4/dns3l-go/dns/common"
	"github.com/dta4/dns3l-go/util"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("module", "dns-test")

type RootConfig struct {
	DNS     *Config `yaml:"dns"`
	DNSTest struct {
		TestableZones map[string][]string
	} `yaml:"dns-test"`
}

func TestAllProvidersFromConfig(t *testing.T) {

	c := &RootConfig{}

	err := util.ConfigFromFileEnv(c)
	if err != nil {
		panic(err)
	}

	rt := common.ResolveTester{}
	rt.ConfigureFromEnv()

	for id, p := range c.DNS.Providers {

		testableZones := c.DNSTest.TestableZones[id]

		log.WithField("provider", id).Info("Testing A record behavior")

		domainName, err := common.MakeNewDomainName4Test(testableZones)
		if err != nil {
			panic(err)
		}
		ipAddr, err := makeNewIPAddr4Test()
		if err != nil {
			panic(err)
		}

		err = p.Prov.SetRecordA(domainName, 300, ipAddr)
		if err != nil {
			panic(err)
		}

		err = rt.WaitForAActive(domainName, ipAddr)
		if err != nil {
			panic(err)
		}

		err = p.Prov.DeleteRecordA(domainName)
		if err != nil {
			panic(err)
		}

		log.WithField("provider", id).Info("Testing acme-challenge TXT record behavior")

		domainName, err = common.MakeNewDomainName4Test(testableZones)
		if err != nil {
			panic(err)
		}
		acmeChallenge := common.GenerateAcmeChallenge()

		err = p.Prov.SetRecordAcmeChallenge(domainName, acmeChallenge)
		if err != nil {
			panic(err)
		}

		err = rt.WaitForChallengeActive(domainName, acmeChallenge)
		if err != nil {
			panic(err)
		}

		err = p.Prov.DeleteRecordAcmeChallenge(domainName)
		if err != nil {
			panic(err)
		}
	}

}

func makeNewIPAddr4Test() (net.IP, error) {
	twobytes := make([]byte, 2)
	rand.Read(twobytes)
	return net.IPv4(10, 0, twobytes[0], twobytes[1]), nil
}
