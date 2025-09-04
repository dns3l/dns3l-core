package service

import (
	"time"

	catypes "github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/renew"
)

type RenewConfig struct {
	JobStartTime         string        `yaml:"jobStartTime" validate:"required"`
	MaxDuration          time.Duration `yaml:"maxDuration"`
	LimitPerDay          uint          `yaml:"limitPerDay"`
	DaysWarnBeforeExpiry uint          `yaml:"daysWarnBeforeExpiry"`
}

type Renewer struct {
	Service *Service
	Config  *RenewConfig
	sched   *renew.Scheduler[catypes.CertificateRenewInfo, *catypes.CertificateRenewInfo]
}

func (r *Renewer) WarnForExpiringCerts() {
	warnAt := time.Now().Add(
		time.Duration(r.Config.DaysWarnBeforeExpiry*24) * time.Hour)

	warnCerts, err := r.Service.Config.CA.Functions.ListExpiring(warnAt, r.Config.LimitPerDay)
	if err != nil {
		log.WithError(err).Error("Could not collect expiring certs to warn about expiry.")
		return
	}
	for _, cert := range warnCerts {
		log.WithField("cert", cert).Warn("Certificate is about to expire soon")
	}
	if len(warnCerts) <= 0 {
		return
	}
	if len(warnCerts) >= int(r.Config.LimitPerDay) {
		log.Warnf("Expiring certificate warn limit reached (%d),"+
			"maybe more certificates are about to expire soon, see previous log messages, "+
			"check renewal process for misconfigurations", r.Config.LimitPerDay)
	}

	log.WithField("numExpiring", len(warnCerts)).Warn("Certificates are about to expire soon, " +
		"see previous log messages, check renewal process for misconfigurations")
}

func (r *Renewer) Init() error {

	r.sched = &renew.Scheduler[catypes.CertificateRenewInfo, *catypes.CertificateRenewInfo]{
		JobStartTime: r.Config.JobStartTime,
		MaxDuration:  r.Config.MaxDuration,
		GetJobsFunc: func() ([]catypes.CertificateRenewInfo, error) {

			r.WarnForExpiringCerts()

			return r.Service.Config.CA.Functions.ListCertsToRenew(r.Config.LimitPerDay)
		},
		JobExecFunc: func(job *catypes.CertificateRenewInfo) error {

			return r.Service.Config.CA.Functions.RenewCertificate(job)

		},
		ReportFunc: func(_, end time.Time, success, fail uint) {
			err := r.Service.Config.CA.Functions.PutLastRenewSummary(
				&renew.ServerInfoRenewal{
					LastRun:    end,
					Successful: success,
					Failed:     fail,
				})
			if err != nil {
				log.WithError(err).Error("Error occurred putting last renew summary to store.")
			}
		},
	}

	return nil
}

func (r *Renewer) StartAsync() error {
	return r.sched.StartAsync()
}
