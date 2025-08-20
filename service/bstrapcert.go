package service

import (
	"errors"
	"fmt"

	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/sirupsen/logrus"
)

type BStrapConfig struct {
	certs []BStrapCertInfo `yaml:"certs"`
}

type BStrapCertInfo struct {
	CA           string   `yaml:"ca"`
	Name         string   `yaml:"name"`
	OtherDomains []string `yaml:"otherdomains"`
	Force        bool     `yaml:"force"`
}

func DoSafeBootstrapCerts(s *Service) error {

	c := s.Config.Bootstrap
	if c == nil || len(c.certs) == 0 {
		log.Debug("no bootstrap certs configured, continuing...")
		return nil
	}

	for _, cert := range c.certs {
		domains := append([]string{cert.Name}, cert.OtherDomains...)

		cinfo, err := s.Config.CA.Functions.GetCertificateInfo(cert.CA, cert.Name)

		nferr := &common.NotFoundError{}
		if err == nil {
			log.WithFields(logrus.Fields{"certName": cert.Name, "claimTime": cinfo.ClaimTime}).Debug(
				"Bootstrap cert already present, skipping...")
			continue
		} else if !errors.As(err, &nferr) {
			if cert.Force {
				return fmt.Errorf("could not check if bootstrap cert is already present (cert %s): %w", cert.Name, err)
			} else {
				log.WithField("certName", cert.Name).WithError(err).Errorf("Could not check if bootstrap cert is already present.")
				continue
			}
		}

		log.WithField("certName", cert.Name).Info("Claiming bootstrap certificate.")

		namerz, err := s.Config.RootZones.GetLowestRZForDomain(cert.Name)
		if err != nil {
			if cert.Force {
				return fmt.Errorf("could not get root zone for domain (cert %s): %w", cert.Name, err)
			} else {
				log.WithField("certName", cert.Name).WithError(err).Errorf("Could not get root zone for domain.")
				continue
			}
		}

		claim, err := s.Config.CA.Functions.PrepareClaimCertificate(cert.CA, &types.CertificateClaimInfo{
			Name:    cert.Name,
			NameRZ:  namerz.Root,
			Domains: domains,
			IssuedBy: &authtypes.UserInfo{
				Name:  "DNS3L Bootstrap",
				Email: "",
			},
			TTLSelected: 0,
		})
		if err != nil {
			if cert.Force {
				return fmt.Errorf("could not prepare claiming certificate (cert %s): %w", cert.Name, err)
			} else {
				log.WithField("certName", cert.Name).WithError(err).Errorf("Could not prepare claiming certificate.")
				continue
			}
		}

		err = claim()
		if err != nil {
			if cert.Force {
				return fmt.Errorf("could not claim certificate (cert %s): %w", cert.Name, err)
			} else {
				log.WithField("certName", cert.Name).WithError(err).Errorf("Could not claim certificate.")
			}
		}
	}

	return nil
}
