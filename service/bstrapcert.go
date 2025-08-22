package service

import (
	"errors"
	"fmt"

	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/util"
	"github.com/sirupsen/logrus"
)

type BStrapConfig struct {
	Certs []BStrapCertInfo `yaml:"certs"`
}

type BStrapCertInfo struct {
	CA           string   `yaml:"ca"`
	Name         string   `yaml:"name"`
	OtherDomains []string `yaml:"otherdomains"`
	Force        bool     `yaml:"force"`
}

func DoSafeBootstrapCerts(s *Service) error {

	c := s.Config.Bootstrap
	if c == nil || len(c.Certs) == 0 {
		log.Debug("no bootstrap certs configured, continuing...")
		return nil
	}

	for _, cert := range c.Certs {

		name := util.GetDomainFQDNDot(cert.Name)
		altnames := make([]string, len(cert.OtherDomains))
		for i := range cert.OtherDomains {
			altnames[i] = util.GetDomainFQDNDot(cert.OtherDomains[i])
		}

		domains := append([]string{name}, cert.OtherDomains...)

		cinfo, err := s.Config.CA.Functions.GetCertificateInfo(cert.CA, name)

		nferr := &common.NotFoundError{}
		if err == nil && cinfo != nil {
			log.WithFields(logrus.Fields{"certName": name, "claimTime": cinfo.ClaimTime}).Debug(
				"Bootstrap cert already present, skipping...")
			continue
		} else if err != nil && !errors.As(err, &nferr) {
			if cert.Force {
				return fmt.Errorf("could not check if bootstrap cert is already present (cert %s): %w", name, err)
			} else {
				log.WithField("certName", name).WithError(err).Errorf("Could not check if bootstrap cert is already present.")
				continue
			}
		}

		log.WithField("certName", name).Info("Claiming bootstrap certificate.")

		namerz, err := s.Config.RootZones.GetLowestRZForDomain(name)
		if err != nil {
			if cert.Force {
				return fmt.Errorf("could not get root zone for domain (cert %s): %w", name, err)
			} else {
				log.WithField("certName", name).WithError(err).Errorf("Could not get root zone for domain.")
				continue
			}
		}

		claim, err := s.Config.CA.Functions.PrepareClaimCertificate(cert.CA, &types.CertificateClaimInfo{
			Name:    name,
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
				return fmt.Errorf("could not prepare claiming certificate (cert %s): %w", name, err)
			} else {
				log.WithField("certName", name).WithError(err).Errorf("Could not prepare claiming certificate.")
				continue
			}
		}

		err = claim()
		if err != nil {
			if cert.Force {
				return fmt.Errorf("could not claim certificate (cert %s): %w", name, err)
			} else {
				log.WithField("certName", name).WithError(err).Errorf("Could not claim certificate.")
			}
		}
	}

	return nil
}
