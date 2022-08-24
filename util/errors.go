package util

import "github.com/sirupsen/logrus"

func LogDefer(l *logrus.Entry, e error) {
	if e != nil {
		l.WithError(e).Errorf("Error occurred during deferred action")
	}
}
