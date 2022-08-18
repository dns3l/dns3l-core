package renew

import (
	"time"

	"github.com/go-co-op/gocron"
)

type Scheduler[T any, PT interface {
	String() string
	*T
}] struct {
	sched        *gocron.Scheduler
	JobStartTime string
	MaxDuration  time.Duration
	GetJobsFunc  func() ([]T, error)
	JobExecFunc  func(job PT) error
}

func (s *Scheduler[T, PT]) StartAsync() error {

	s.sched = gocron.NewScheduler(time.UTC)

	_, err := s.sched.Every(1).Day().At(s.JobStartTime).Do(s.scheduleRenewJobs)
	if err != nil {
		return err
	}

	s.sched.StartAsync()

	return nil

}

func (s *Scheduler[T, PT]) scheduleRenewJobs() {

	jobs, err := s.GetJobsFunc()
	if err != nil {
		log.WithError(err).Error("error when obtaining jobs to schedule, will omit job scheduling today")
		//TODO maybe retry?
		return
	}

	if len(jobs) <= 0 {
		log.WithField("jobcount", 0).Info("No renewal jobs to trigger.")
		return
	}

	log.WithField("jobcount", len(jobs)).Info("Triggering renewal jobs...")

	interval := time.Duration(s.MaxDuration.Nanoseconds() / int64(len(jobs)))
	for i := range jobs {
		job := &jobs[i]
		go s.execRenewJob(job)
		time.Sleep(interval)
	}

	log.WithField("jobcount", len(jobs)).Info("Triggering renewal jobs completed")

}

func (s *Scheduler[T, PT]) execRenewJob(job PT) {
	log.WithField("job", job.String()).Info("Job execution started")
	err := s.JobExecFunc(job)
	if err != nil {
		log.WithError(err).WithField("job", job.String()).Error("Job execution failed")
		return
	}
	log.WithField("job", job.String()).Info("Job execution successfully finished")
}
