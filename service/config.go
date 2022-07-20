package service

import (
	"fmt"
	"io/ioutil"

	"github.com/creasty/defaults"
	"github.com/dta4/dns3l-go/ca"
	"github.com/dta4/dns3l-go/dns"
	"github.com/dta4/dns3l-go/service/auth"
	"github.com/dta4/dns3l-go/state"
	myvalidation "github.com/dta4/dns3l-go/util/validation"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v2"
)

type Config struct {
	DNS       *dns.Config                 `yaml:"dns" validate:"required"`
	CA        *ca.Config                  `yaml:"ca" validate:"required"`
	RootZones dns.RootZones               `yaml:"rtzn" validate:"required,dive"`
	DB        *state.SQLDBProviderDefault `yaml:"db" validate:"required"`   //SQL hard-coded (only here)
	Auth      *auth.OIDCHandler           `yaml:"auth" validate:"required"` //OIDC hard-coded (only here)

	//RootZoneAllowedCA map[string] //maybe we need this later...
	//CAAllowedRootZones map[string][]dns.RootZone
}

func (c *Config) FromFile(file string) error {
	filebytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	return c.FromYamlBytes(filebytes)
}

func (c *Config) FromYamlBytes(bytes []byte) error {
	return yaml.Unmarshal(bytes, c)
}

//Must be executed after config struct initialization
func (c *Config) Initialize() error {

	err := defaults.Set(c)
	if err != nil {
		return err
	}

	log.Debug("Validating config...")
	validate := validator.New()
	myvalidation.RegisterDNS3LValidations(validate)

	err = validate.StructFiltered(c, func(ns []byte) bool {
		//fmt.Printf("VALIDATION: %s\n", ns)
		return false
	})
	if err != nil {
		return err
	}
	log.Info("Successfully validated config.")

	for _, rtzn := range c.RootZones {
		if foo := rtzn.CAs[0]; foo == "*" {
			//all CAs can handle this root zone
			for _, ca := range c.CA.Providers {
				ca.AddAllowedRootZone(rtzn)
			}
			continue
		}
		for _, caID := range rtzn.CAs {
			ca, exists := c.CA.Providers[caID]
			if !exists {
				return fmt.Errorf("CA '%s' has not been configured", caID)
			}
			ca.AddAllowedRootZone(rtzn)
		}
	}

	err = c.CA.Init(&CAConfigurationContextImpl{
		StateProvider: c.DB,
		DNSConfig:     c.DNS,
	})
	if err != nil {
		return err
	}

	return nil

}
