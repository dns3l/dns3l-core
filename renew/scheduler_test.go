package renew

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

type SchedulerJob struct {
	Name string
}

func (s SchedulerJob) String() string {
	return s.Name
}

func TestSchedulers(T *testing.T) {

	rand.Seed(time.Now().Unix())

	num := rand.Intn(123)
	jobsExecuted := 0

	s := &Scheduler[SchedulerJob, *SchedulerJob]{
		JobStartTime: "17:20", //doesn't matter in the tests
		MaxDuration:  time.Minute,
		GetJobsFunc: func() ([]SchedulerJob, error) {
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
			jobsExecuted++
			return nil
		},
	}

	s.scheduleRenewJobs()

	time.Sleep(61 * time.Second)

	assert.Equal(T, num, jobsExecuted)

}
