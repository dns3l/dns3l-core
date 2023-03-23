package runs

import "github.com/sirupsen/logrus"

var log = logrus.WithField("module", "test-runs")

type TestRunner struct {
	TestConfig        string
	CAID              string
	Domain            string
	Truncate          bool
	ReplicaOffset     uint
	NumReplicas       uint
	Dump              bool
	WithACME          bool
	CheckIntermediate bool
}
