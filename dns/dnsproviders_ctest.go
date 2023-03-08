package dns

import (
	"crypto/rand"
	"net"

	"github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/util"

	"github.com/sirupsen/logrus"
)

// For this test to work you need to extend your dns3ld config with metadata:
// dns-test:
//   testablezones:
//     <dnsplugin>:
//       zones:
//       - test.example.com.
//       - playground.example.com.
//       checkservers:
//       - 1.2.3.4:53
//       - 4.5.6.7:53

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
	err = rt.ConfigureFromEnv()
	if err != nil {
		panic(err)
	}

	for id, p := range c.DNS.Providers {

		log.WithField("provider", id).Info("Running tests for provider")

		testableZones, zonesFound := c.DNSTest.TestableZones[id]
		if !zonesFound {
			panic("No testable zones found. Did you extend the config with DNS test metadata?")
		}

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
	_, err := rand.Read(twobytes)
	if err != nil {
		return net.IP{}, err
	}
	return net.IPv4(10, 0, twobytes[0], twobytes[1]), nil
}
