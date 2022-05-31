package dns

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"gopkg.in/yaml.v2"
)

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

	for id, p := range c.DNS.Providers {

		testableZones := c.DNSTest.TestableZones[id]

		domainName, err := makeNewDomainName4Test(testableZones)
		if err != nil {
			panic(err)
		}
		ipAddr, err := makeNewIPAddr4Test()
		if err != nil {
			panic(err)
		}
		err = p.Prov.SetRecordA(domainName, ipAddr)
		if err != nil {
			panic(err)
		}
		err = p.Prov.DeleteRecordA(domainName)
		if err != nil {
			panic(err)
		}

		domainName, err = makeNewDomainName4Test(testableZones)
		if err != nil {
			panic(err)
		}
		acmeChallenge, err := makeNewAcmeChallenge4Test()
		if err != nil {
			panic(err)
		}

		err = p.Prov.SetRecordAcmeChallenge(domainName, acmeChallenge)
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
	return "", errors.New("stubbed, not yet implemented")
}

func makeNewIPAddr4Test() (string, error) {
	return "", errors.New("stubbed, not yet implemented")
}

func makeNewAcmeChallenge4Test() (string, error) {
	return "", errors.New("stubbed, not yet implemented")
}

func ConfigFromFileEnv() (*RootConfig, error) {
	filename := os.Getenv("DNS3L_TEST_CONFIG")
	if filename == "" {
		return nil, errors.New("No DNS3L_TEST_CONFIG env variable given.")
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
