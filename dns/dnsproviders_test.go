package dns

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/dta4/dns3l-go/dns/common"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var log = logrus.WithField("module", "dns-test")

type RootConfig struct {
	DNS     *Config `yaml:"dns"`
	DNSTest struct {
		TestableZones map[string][]string
	} `yaml:"dns-test"`
}

func TestAllProvidersFromConfig(t *testing.T) {

	c, err := ConfigFromFileEnv()
	if err != nil {
		panic(err)
	}

	rt := common.ResolveTester{}
	rt.ConfigureFromEnv()

	for id, p := range c.DNS.Providers {

		testableZones := c.DNSTest.TestableZones[id]

		log.WithField("provider", id).Info("Testing A record behavior")

		domainName, err := makeNewDomainName4Test(testableZones)
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

		domainName, err = makeNewDomainName4Test(testableZones)
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

func makeNewDomainName4Test(testableZones []string) (string, error) {
	zone := strings.TrimLeft(testableZones[rand.Int()%len(testableZones)], ".")
	name := fmt.Sprintf("test%d.%s", rand.Intn(100000), zone)
	return name, nil
}

func makeNewIPAddr4Test() (net.IP, error) {
	twobytes := make([]byte, 2)
	rand.Read(twobytes)
	return net.IPv4(10, 0, twobytes[0], twobytes[1]), nil
}

func ConfigFromFileEnv() (*RootConfig, error) {
	filename := os.Getenv("DNS3L_TEST_CONFIG")
	if filename == "" {
		return nil, errors.New("no DNS3L_TEST_CONFIG env variable given")
	}
	return ConfigFromFile(filename)
}

func ConfigFromFile(filename string) (*RootConfig, error) {
	filebytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ConfigFromYamlBytes(filebytes)
}

func ConfigFromYamlBytes(bytes []byte) (*RootConfig, error) {
	c := &RootConfig{}
	err := yaml.Unmarshal(bytes, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}
