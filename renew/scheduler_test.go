package renew

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

type SchedulerJob struct {
	Name string
}

func (s SchedulerJob) String() string {
	return s.Name
}

func TestSchedulers(T *testing.T) {

	rand.Seed(time.Now().Unix())

	s := &Scheduler[SchedulerJob, *SchedulerJob]{
		JobStartTime: "17:20",
		MaxDuration:  time.Minute,
		GetJobsFunc: func() ([]SchedulerJob, error) {
			num := rand.Intn(123)
			jobs := make([]SchedulerJob, num)
			for i := 0; i < num; i++ {
				jobs[i] = SchedulerJob{
					Name: fmt.Sprintf("Job %d", i),
				}
			}
			return jobs, nil
		},
		JobExecFunc: func(job *SchedulerJob) error {

			duration := time.Millisecond * time.Duration(rand.Intn(3000))

			fmt.Println("Starting job " + job.Name)
			time.Sleep(duration)
			fmt.Println("Stopping job " + job.Name)
			return nil
		},
	}

	s.scheduleRenewJobs()

}
