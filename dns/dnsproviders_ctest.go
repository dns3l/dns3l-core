package dns

import (
	"math/rand"
	"net"

	"github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/util"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("module", "dns-test")

type RootConfig struct {
	DNS     *Config `yaml:"dns"`
	DNSTest struct {
		TestableZones map[string]struct {
			Zones        []string `yaml:"zones"`
			Checkservers []string `yaml:"checkservers"`
		} `yaml:"testablezones"`
	} `yaml:"dns-test"`
}

func TestAllProvidersFromConfig() {

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

		domainName, _, err := common.MakeNewDomainName4Test(testableZones.Zones)
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

		log.WithField("provider", id).Info("Trying to resolve A record now...")

		rt.DNSCheckServers = testableZones.Checkservers
		if len(rt.DNSCheckServers) > 0 {
			err := rt.WaitForAActive(domainName, ipAddr)
			if err != nil {
				panic(err)
			}
		} else {
			log.WithField("provider", id).Info("DNS check skipped, no servers.")
		}

		log.WithField("provider", id).Info("Success with resolving, deleting A record now...")

		err = p.Prov.DeleteRecordA(domainName)
		if err != nil {
			panic(err)
		}

		log.WithField("provider", id).Info("Testing acme-challenge TXT record behavior")

		domainName, _, err = common.MakeNewDomainName4Test(testableZones.Zones)
		if err != nil {
			panic(err)
		}
		acmeChallenge := common.GenerateAcmeChallenge()

		err = p.Prov.SetRecordAcmeChallenge(domainName, acmeChallenge)
		if err != nil {
			panic(err)
		}

		log.WithField("provider", id).Info("Trying to resolve TXT record now...")

		rt.DNSCheckServers = testableZones.Checkservers
		if len(rt.DNSCheckServers) > 0 {
			err = rt.WaitForChallengeActive(domainName, acmeChallenge)
			if err != nil {
				panic(err)
			}
		} else {
			log.WithField("provider", id).Info("DNS check skipped, no servers.")
		}

		log.WithField("provider", id).Info("Success with resolving, deleting TXT record now...")

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
