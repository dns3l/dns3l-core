package renew

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"
)

type Scheduler[T any, PT interface {
	String() string
	*T
}] struct {
	sched        gocron.Scheduler
	JobStartTime string
	MaxDuration  time.Duration
	GetJobsFunc  func() ([]T, error)
	JobExecFunc  func(job PT) error
}

func (s *Scheduler[T, PT]) StartAsync() error {

	var err error
	hours, minutes, err := ParseTimeAtDay(s.JobStartTime)
	if err != nil {
		return fmt.Errorf("error parsing time at day: %w", err)
	}

	s.sched, err = gocron.NewScheduler(gocron.WithLocation(time.UTC))
	if err != nil {
		return fmt.Errorf("error creating new scheduler: %w", err)
	}

	_, err = s.sched.NewJob(
		gocron.DailyJob(1,
			gocron.NewAtTimes(gocron.NewAtTime(hours, minutes, 0)),
		),
		gocron.NewTask(s.scheduleRenewJobs),
	)
	if err != nil {
		return err
	}

	s.sched.Start()

	return nil

}

func ParseTimeAtDay(timeStr string) (uint, uint, error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid time format, expected hh:mm")
	}

	hours, err := strconv.Atoi(parts[0])
	if err != nil || hours < 0 || hours > 23 {
		return 0, 0, errors.New("invalid hour value")
	}

	minutes, err := strconv.Atoi(parts[1])
	if err != nil || minutes < 0 || minutes > 59 {
		return 0, 0, errors.New("invalid minute value")
	}

	return uint(hours), uint(minutes), nil
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
