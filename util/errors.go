package util

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
)

func LogDefer(l *logrus.Entry, f func() error) {
	err := f()
	if err != nil {
		l.WithError(err).Errorf("Error occurred during deferred action")
	}
}

func LogIfError(l *logrus.Entry, err error) {
	if err != nil {
		l.WithError(err).Errorf("Error occurred")
	}
}

func CatchPanic(fu func() error) (err error) {
	defer func() {
		if panic := recover(); panic != nil {
			if suberr, isError := panic.(error); isError {
				err = fmt.Errorf("caught panic: %w", suberr)
			} else {
				err = fmt.Errorf("caught panic: %v", panic)
			}

		}
	}()
	err = fu()
	return
}

// this would be nice in the errors lib...
func UnwrapMultiErr(err error) []error {
	u, ok := err.(interface {
		Unwrap() []error
	})
	if !ok {
		suberr := errors.Unwrap(err)
		if suberr == nil {
			return nil
		}
		return []error{suberr}
	}
	return u.Unwrap()
}
