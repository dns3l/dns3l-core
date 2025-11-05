package state

import (
	"time"
)

// Dereferences a time, if it is nil, provide
// zero time
func NilToZeroTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
